#include <linux/tx_list2.h>

#ifdef CONFIG_TX_KSTM
#ifndef CONFIG_DISABLE_LIST2

struct kmem_cache *tx_list2_cachep;

int commit_tx_list2(struct txobj_thread_list_node * xnode){

	struct tx_list2_head *head = (struct tx_list2_head *) xnode->orig_obj;
	struct tx_list2_entry *cursor, *n;

	/* A transactional del/add combo can hose up the list
	 * traversal such that n isn't valid and we have to just try
	 * again.  We don't lose any ground, as we are deleting as we go. */
restart:
	list_for_each_entry_safe(cursor, n, &head->spec_list, spec){
		if(cursor->transaction == current->transaction){
			if(cursor->transactional_state == TRANSACTIONAL_ADD){
				struct tx_list2_entry *entry = &cursor->cursor->entry;
				int need_restart = 0;
				KSTM_BUG_ON(!entry->embedded);
				KSTM_BUG_ON(cursor->embedded);

				/* We may have to commit a speculative
				 * delete for another list */
				if(!list_empty(&entry->list)){
					BUG_ON(entry->transactional_state != TRANSACTIONAL_DEL);
					/* Move the stable entry to our spot*/
					list_move(&entry->list, &cursor->list);
					list_del_init(&entry->spec);
					need_restart = 1;
				} else
					list_add(&entry->list, &cursor->list);

				/* Take the speculative entry out */
				list_del_init(&cursor->list);
				entry->transactional_state = NON_TX;
				entry->parent = cursor->parent;
				entry->transaction = NULL;
				KSTM_BUG_ON(cursor->cursor->tx != current->transaction
					    &&cursor->cursor->tx != NULL);
				cursor->cursor->tx = NULL;
				KSTM_BUG_ON(cursor->cursor->sentry != cursor);
				cursor->cursor->sentry = NULL;
				list_del(&cursor->spec);
				free_tx_list2_entry(cursor);
				if(need_restart)
					goto restart;
			} else if(cursor->transactional_state == TRANSACTIONAL_DEL){
				list_del_init(&cursor->list);
				KSTM_BUG_ON(cursor->cursor->tx != current->transaction
					    &&cursor->cursor->tx != NULL);
				cursor->cursor->tx = NULL;
				cursor->transactional_state = NON_TX;
				cursor->transaction = NULL;
				cursor->parent = NULL;
				KSTM_BUG_ON(cursor->cursor->sentry == cursor);
				list_del_init(&cursor->spec);
				if(!cursor->embedded)
					free_tx_list2_entry(cursor);
			} else {
				printk(KERN_ERR "Odd transactional state %d, %p\n", 
				       cursor->transactional_state, &cursor->transactional_state);
				BUG();
			}
		}
	}

	if(xnode->rw == ACCESS_RW)
		head->mode = NO_TX;
	else if(xnode->rw == ACCESS_R
		&& list_empty(&xnode->tx_obj->readers))
		head->mode = NO_TX;

	return 0;
}

int abort_tx_list2(struct txobj_thread_list_node * xnode){

	struct tx_list2_head *head = (struct tx_list2_head *) xnode->orig_obj;
	struct tx_list2_entry *cursor, *n;

	list_for_each_entry_safe(cursor, n, &head->spec_list, spec){
		if(cursor->transaction == current->transaction){
			if(cursor->transactional_state == TRANSACTIONAL_DEL){
				cursor->transactional_state = NON_TX;
				if(cursor->cursor->tx == cursor->transaction){
					cursor->cursor->tx = NULL;
				}
				cursor->transaction = NULL;

				list_del_init(&cursor->spec);
			} else if(cursor->transactional_state == TRANSACTIONAL_ADD){
				list_del(&cursor->list);
				if(cursor->cursor->tx == cursor->transaction){
					cursor->cursor->sentry = NULL;
					cursor->cursor->tx = NULL;
				}
				list_del(&cursor->spec);
				BUG_ON(cursor->embedded);
				free_tx_list2_entry(cursor);
			} else 
				BUG();
		}
	}

	if(xnode->rw == ACCESS_RW)
		head->mode = NO_TX;
	else if(xnode->rw == ACCESS_R
		&& list_empty(&xnode->tx_obj->readers))
		head->mode = NO_TX;

	return 0;
}

#ifdef CONFIG_TX_KSTM_ASSERTIONS
int validate_tx_list2(struct txobj_thread_list_node * xnode){
	struct tx_list2_head *head = (struct tx_list2_head *) xnode->orig_obj;
	//struct tx_list2_entry *cursor, *n;

	if(head->mode == NO_TX)
		printk(KERN_ERR "Notx at %p\n", &head->mode);

	BUG_ON(head->mode == NO_TX);

	/* DEP 3/5/09 - This is too slow for the crash boxes, and not that useful

	for(cursor = head->head.next, n = cursor->next; cursor != &head->head; cursor = n, n = cursor->next){

		BUG_ON(cursor->next->prev != cursor);
		BUG_ON(cursor->prev->next != cursor);
		BUG_ON(cursor->parent != head);
		
		//XXX: Probably need more here
	}
	*/

	return 0;
}
#endif

int lock_list(struct txobj_thread_list_node * xnode, int blocking){

	struct tx_list2_head * orig = (struct tx_list2_head *)xnode->orig_obj;
	if(!blocking)
		spin_lock(&orig->lock);
	return 0;
}

int unlock_list(struct txobj_thread_list_node * xnode, int blocking){

	struct tx_list2_head * orig = (struct tx_list2_head *)xnode->orig_obj;
	if(!blocking)
		spin_unlock(&orig->lock);
	return 0;
}

void acquire_list(struct tx_list2_head *head, enum access_mode mode){
	
	/*
	 * Lists have special semantics - readers or writers can exist
	 * concurrently, so long as writers don't write the same node.
	 * If a transaction reads and writes, it goes into exclusive
	 * state.
	 *
	 * We map read and write onto ACCESS_R at the transaction
	 * level, and exclusive onto ACCESS_RW at the transaction
	 * level.
	 */
	enum access_mode tx_mode = ACCESS_R;
	txobj_thread_list_node_t *list_node;
	int should_sleep = 0;
	struct transaction *winner;

#ifdef CONFIG_TX_KSTM_PROF
	unsigned long long cycles, a;
	rdtscll(cycles);
#endif
	if(mode == ACCESS_R){
		mode = TX_R;
		switch(head->mode){
		case NO_TX:
			goto acquire;
		case TX_R:
			break;
		case TX_W:
			tx_mode = ACCESS_RW;
			mode = TX_EXCL;
			break;
		case TX_EXCL:
			tx_mode = ACCESS_RW;
			break;
		default:
			printk(KERN_ERR "Bad mode %d\n", head->mode);
			BUG();
		}
	} else if(mode == ACCESS_RW){
		mode = TX_W;
		switch(head->mode){
		case NO_TX:
			tx_mode = ACCESS_R;
			goto acquire;
		case TX_R:
			tx_mode = ACCESS_RW;
			mode = TX_EXCL;
			break;
		case TX_W:
			break;
		case TX_EXCL:
			tx_mode = ACCESS_RW;
			break;
		default:
			printk(KERN_ERR "Bad mode %d\n", head->mode);
			BUG();
		}
	} else {
		printk(KERN_ERR "Bad mode %d\n", mode);
		BUG();
	}

	LOCK_XOBJ(&head->xobj);
	if((list_node = workset_has_object_locked(&head->xobj))){
		if(list_node->rw < tx_mode){
			/* Upgrade the mode */

			winner = 
				upgrade_xobj_mode(list_node->tx_obj, tx_mode, &should_sleep);
			if(winner){
				if(!should_sleep)
					winner = NULL;
					
				UNLOCK_XOBJ(&head->xobj);
				abort_self(winner, 0);
			} 
			list_node->rw = tx_mode;
		}
		UNLOCK_XOBJ(&head->xobj);

		head->mode = mode;
#ifdef CONFIG_TX_KSTM_PROF
		rdtscll(a);
		shadowCopyCycles += (a - cycles);
#endif	
		return;
	} else
		goto noacquire;

	
acquire:
	LOCK_XOBJ(&head->xobj);
noacquire:
	list_node = tx_check_add_obj(&head->xobj, TYPE_LIST2_HEAD, tx_mode,
				     &should_sleep, &winner);

	if(unlikely(!list_node)){
		if(!should_sleep)
			winner = NULL;
		UNLOCK_XOBJ(&head->xobj);
		abort_self(winner, 0);
	}
	UNLOCK_XOBJ(&head->xobj);

	head->mode = mode;

	list_node->type = TYPE_LIST2_HEAD;
	list_node->shadow_obj = head;
	list_node->orig_obj = head;
	list_node->rw = tx_mode;
	list_node->lock = lock_list;
	list_node->unlock = unlock_list;
	list_node->commit = commit_tx_list2;
	list_node->abort  = abort_tx_list2;
	list_node->release = NULL;
	list_node->tx_obj = &head->xobj;

#ifdef CONFIG_TX_KSTM_ASSERTIONS
	list_node->checkpoint_obj = NULL;
	list_node->validate = validate_tx_list2;
#endif
	workset_add(list_node,
		    &(current->transaction->list_list));
#ifdef CONFIG_TX_KSTM_PROF
	rdtscll(a);
	shadowCopyCycles += (a - cycles);
#endif	
}

EXPORT_SYMBOL(tx_list2_cachep);
EXPORT_SYMBOL(acquire_list);

#endif // !CONFIG_DISABLE_LIST2
#endif //CONFIG_TX_KSTM
