#include <linux/tx_list.h>

#ifdef CONFIG_TX_KSTM

# define alloc_tx_list() kmem_cache_alloc(cachep_tx_list, GFP_KERNEL)
# define free_tx_list(tx) kmem_cache_free(cachep_tx_list, tx)

# define alloc_tx_hlist() kmem_cache_alloc(cachep_tx_hlist, GFP_KERNEL)
# define free_tx_hlist(tx) kmem_cache_free(cachep_tx_hlist, tx)

/* Do the cleanup/freeing work */
int release_list(struct txobj_thread_list_node * xnode, int early){
				
	struct tx_list_head * shadow = (struct tx_list_head *)xnode->shadow_obj;
#ifdef CONFIG_TX_KSTM_ASSERTIONS
	struct tx_list_head * checkpoint = (struct tx_list_head *)xnode->checkpoint_obj;

	free_tx_list(checkpoint);
#endif
	free_tx_list(shadow);

	return 0;
}

int release_hlist(struct txobj_thread_list_node * xnode, int early){
				
	struct tx_hlist_head * shadow = (struct tx_hlist_head *)xnode->shadow_obj;
#ifdef CONFIG_TX_KSTM_ASSERTIONS
	struct tx_hlist_head * checkpoint = (struct tx_hlist_head *)xnode->checkpoint_obj;

	free_tx_hlist(checkpoint);
#endif
	free_tx_hlist(shadow);

	return 0;
}


void *lookup_placeholder(void *in, enum access_mode mode){
	void *rv;
	KSTM_BUG_ON(in == NULL);
	
	/* Some initial checks for non-active tx status */
	if((rv = tx_status_check(in, mode, 0)) != NULL)
		return rv;

	/* We should not be transactional if we get here */
	BUG();
}

void list_commit_tx(struct tx_list_head *head, int new){
	if(new == 1){
		// Cope with the fact that we are replacing object pointers, rather than copying values.
		if(head->next != LIST_POISON1
		   && head->next == head->self->next)
			head->next->prev = head;
		if(head->prev != LIST_POISON2
		   && head->prev == head->self->prev)
			head->prev->next = head;

		head->shadow = 0;
		head->rw = ACCESS_R;
		head->self = head;
	} else if(new == 2){
		// Special case for d_alias, which is in both worlds

		// Make sure that our stable copy points to our speculative neighbors
		// and that they point to our stable version.  How ugly.
		if(head->next == LIST_POISON1)
			head->self->next = LIST_POISON1;
		else {
			head->self->next = head->next;
			if(head->self->next->prev == head)
				head->self->next->prev = head->self;
		}

		if(head->prev == LIST_POISON2)
			head->self->prev = LIST_POISON2;
		else {
			head->self->prev = head->prev;
			if(head->self->prev->next == head)
				head->self->prev->next = head->self;
		}
		
	} else {
		if(head->next == LIST_POISON1)
			head->self->next = LIST_POISON1;
		else
			head->self->next = head->next->self;
		if(head->prev == LIST_POISON2)
			head->self->prev = LIST_POISON2;
		else
			head->self->prev = head->prev->self;
	}
		
	atomic_dec(&head->self->tx_count);
}

int commit_list_head(struct txobj_thread_list_node * xnode){

	struct tx_list_head * shadow = (struct tx_list_head *)xnode->shadow_obj;
	if(xnode->rw == ACCESS_RW)
		list_commit_tx(shadow, 0);
	else 
		atomic_dec(&shadow->self->tx_count);
	return 0;
}

int abort_list_head(struct txobj_thread_list_node * xnode){

	struct tx_list_head * orig = (struct tx_list_head *)xnode->orig_obj;
	atomic_dec(&orig->tx_count);
	return 0;
}


#ifdef CONFIG_TX_KSTM_ASSERTIONS
int validate_list_head(struct txobj_thread_list_node * xnode){
	struct tx_list_head * orig = (struct tx_list_head *)xnode->orig_obj;
	struct tx_list_head * checkpoint = (struct tx_list_head *)xnode->checkpoint_obj;
	list_validate_tx(orig, checkpoint);
	return 0;
}
#endif

static struct tx_list_head *__tx_cache_get_tx_list_head(struct tx_list_head * head, enum access_mode mode){
	struct tx_list_head * shadow;
	txobj_thread_list_node_t * list_node = NULL;
	struct tx_list_head *tmp;
	int should_sleep = 0;
	struct transaction *winner;

#ifdef CONFIG_TX_KSTM_PROF
	unsigned long long cycles, a;
#endif
#ifdef CONFIG_TX_KSTM_ASSERTIONS
 	struct tx_list_head * checkpoint;

	BUG_ON(head == NULL);
#endif

	/* If this is already a shadow copy, return it */
	if(head->shadow){
		if(head->rw >= mode){
			return head;
		} else
			head = head->self;
	}

	/* Some initial checks for non-active tx status */
	if((tmp = tx_status_check(head, mode, 0)) != NULL){
		return tmp;
	}

#ifdef CONFIG_TX_KSTM_PROF
	rdtscll(cycles);
#endif	

	/* Next, make sure we don't already have the object */
	list_node = workset_has_object(head->xobj);
	if(list_node) {
		shadow = list_node->shadow_obj;
		if(mode == ACCESS_RW && list_node->rw == ACCESS_R){
			/* Upgrade the mode */
			LOCK_XOBJ(head->xobj);
			winner = 
				upgrade_xobj_mode(list_node->tx_obj, mode, &should_sleep);
			if(winner){
				if(!should_sleep)
					winner = NULL;
					
				UNLOCK_XOBJ(head->xobj);
				abort_self(winner, 0);
			} 
			list_node->rw = mode;
			UNLOCK_XOBJ(head->xobj);
			shadow->rw = mode;
		}
#ifdef CONFIG_TX_KSTM_PROF
		rdtscll(a);
		shadowCopyCycles += (a - cycles);
#endif	
		return shadow;
	}

	/* At this point, we definitely don't have the object.  Add
	 * it!
	 */
	LOCK_XOBJ(head->xobj);
	list_node = tx_check_add_obj(head->xobj, TYPE_LIST_HEAD, mode, &should_sleep, &winner);

	if(unlikely(!list_node)){
#ifdef CONFIG_TX_KSTM_PROF
		rdtscll(a);
		shadowCopyCycles += (a - cycles);
#endif	
		if(!should_sleep)
			winner = NULL;

		UNLOCK_XOBJ(head->xobj);
		abort_self(winner, 0);
	}
	UNLOCK_XOBJ(head->xobj);
	
	// Allocate the shadow copy and update the local workset
	
	//alloc a shadow object: TODO cache allocate these
	shadow = alloc_tx_list();
	if(!shadow)
		goto fail1;

	/* Assume no locking requred - dcache_lock should already be
	 * held
	 */

	memcpy(shadow, head, sizeof(struct tx_list_head));

	// Unlock would go here

	/* XXX: We are not going to overwrite the parent in the shadow
	 * copy so that we can just memcpy the whole thing when we are
	 * done.  Be aware.
	 */

	shadow->shadow = 1;

#ifdef CONFIG_TX_KSTM_ASSERTIONS

	checkpoint = alloc_tx_list();
	if(!checkpoint)
		goto fail2;
	memcpy(checkpoint, shadow, sizeof(struct tx_list_head));
	list_init_tx(shadow, mode);
#endif

	list_node->type = TYPE_LIST_HEAD;
	list_node->shadow_obj = shadow;
	list_node->orig_obj = head;
	list_node->rw = mode;
	/* Need to hold the dcache lock and there is only one of them */
	list_node->lock = NULL;
	list_node->unlock = NULL;
	list_node->commit = commit_list_head;
	list_node->abort  = abort_list_head;
	list_node->release = release_list;
	list_node->tx_obj = head->xobj;

#ifdef CONFIG_TX_KSTM_ASSERTIONS
	list_node->checkpoint_obj = checkpoint;
	list_node->validate = validate_list_head;
#endif
	workset_add(list_node,
		    &(current->transaction->object_list));
#ifdef CONFIG_TX_KSTM_PROF
	rdtscll(a);
	shadowCopyCycles += (a - cycles);
#endif	
	return shadow;

#ifdef CONFIG_TX_KSTM_ASSERTIONS
fail2:
	free_tx_list(checkpoint);
#endif
fail1:
	free_tx_list(shadow);
	BUG();
#ifdef CONFIG_TX_KSTM_PROF
	rdtscll(a);
	shadowCopyCycles += (a - cycles);
#endif	
	return ERR_PTR(-ETXABORT);
}

struct tx_list_head *tx_cache_get_tx_list_head(struct tx_list_head * head){
	return (void*) __tx_cache_get_tx_list_head(head, ACCESS_RW);
}

struct tx_list_head *tx_cache_get_tx_list_head_ro(struct tx_list_head * head){
	return (void*) __tx_cache_get_tx_list_head(head, ACCESS_R);
}

void *tx_cache_get_tx_list_head_void(void* in, enum access_mode mode){
	return (void*) __tx_cache_get_tx_list_head((struct tx_list_head *) in, mode);
}

int lock_hlist(struct txobj_thread_list_node * xnode, int blocking){

	struct tx_hlist_head * orig = (struct tx_hlist_head *)xnode->orig_obj;
	if(!blocking)
		write_lock(&orig->lock);
	return 0;
}

int unlock_hlist(struct txobj_thread_list_node * xnode, int blocking){

	struct tx_hlist_head * orig = (struct tx_hlist_head *)xnode->orig_obj;
	if(!blocking)
		write_unlock(&orig->lock);
	return 0;
}


void hlist_commit_tx(struct tx_hlist_node *head, int new){

	if(new){
		// Cope with the fact that we are replacing object pointers, rather than copying values.
		if(head->next != LIST_POISON1
		   && head->next != NULL
		   && head->next == head->self->next)
			head->next->prev = head;
		if(head->prev != LIST_POISON2
		   && head->prev != NULL
		   && head->prev == head->self->prev)
			head->prev->next = head;
		head->self = head;
	} else {
		if(head->next == NULL || head->next == LIST_POISON1)
			head->self->next = head->next;
		else
			head->self->next = head->next->self;
		
		if(head->prev == NULL || head->prev == LIST_POISON2)
			head->self->prev = head->prev;
		else 
			head->self->prev = head->prev->self;
	}
		
	atomic_dec(&head->self->tx_count);
}


int commit_hlist_head(struct txobj_thread_list_node * xnode){

	struct tx_hlist_head * shadow = (struct tx_hlist_head *)xnode->shadow_obj;
	if(xnode->rw == ACCESS_RW)
		hlist_commit_tx(shadow, 0);
	else
		atomic_dec(&shadow->self->tx_count);
	return 0;
}

int abort_hlist_head(struct txobj_thread_list_node * xnode){

	struct tx_hlist_head * orig = (struct tx_hlist_head *)xnode->orig_obj;
	atomic_dec(&orig->tx_count);
	return 0;
}


#ifdef CONFIG_TX_KSTM_ASSERTIONS
int validate_hlist_head(struct txobj_thread_list_node * xnode){
	struct tx_hlist_head * orig = (struct tx_hlist_head *)xnode->orig_obj;
	struct tx_hlist_head * checkpoint = 
		(struct tx_hlist_head *)xnode->checkpoint_obj;
	struct tx_hlist_head * shadow = (struct tx_hlist_head *)xnode->shadow_obj;
	hlist_validate_tx(orig, checkpoint);
	if(xnode->rw == ACCESS_R)
		hlist_validate_tx_ro(orig, shadow);
	return 0;
}
#endif

static inline struct tx_hlist_head *__tx_cache_get_tx_hlist_head(struct tx_hlist_head * head, enum access_mode mode){
	struct tx_hlist_head * shadow;
	txobj_thread_list_node_t * list_node = NULL;
	struct tx_hlist_head *tmp;
	int should_sleep = 0;
	struct transaction *winner;

#ifdef CONFIG_TX_KSTM_PROF
	unsigned long long cycles, a;
#endif
#ifdef CONFIG_TX_KSTM_ASSERTIONS
 	struct tx_hlist_head * checkpoint;

	BUG_ON(head == NULL);
#endif

	/* If this is already a shadow copy, return it */
	if(head->shadow){
		if(head->rw >= mode){
			return head;
		} else
			head = head->self;
	}

	/* Some initial checks for non-active tx status */
	if((tmp = tx_status_check(head, mode, 0)) != NULL){
		return tmp;
	}

#ifdef CONFIG_TX_KSTM_PROF
	rdtscll(cycles);
#endif	

	/* Next, make sure we don't already have the object */
	list_node = workset_has_object(head->xobj);
	if(list_node) {
		shadow = list_node->shadow_obj;
		if(mode == ACCESS_RW && list_node->rw == ACCESS_R){
			/* Upgrade the mode */
			LOCK_XOBJ(head->xobj);
			winner = 
				upgrade_xobj_mode(list_node->tx_obj, mode, &should_sleep);
			if(winner){
				if(!should_sleep)
					winner = NULL;
					
				UNLOCK_XOBJ(head->xobj);
				abort_self(winner, 0);
			} 
			list_node->rw = mode;
			UNLOCK_XOBJ(head->xobj);
			shadow->rw = mode;
		}
#ifdef CONFIG_TX_KSTM_PROF
		rdtscll(a);
		shadowCopyCycles += (a - cycles);
#endif	
		return shadow;
	}

	/* At this point, we definitely don't have the object.  Add
	 * it!
	 */
	LOCK_XOBJ(head->xobj);
	list_node = tx_check_add_obj(head->xobj, TYPE_HLIST_HEAD, mode, 
				     &should_sleep, &winner);
	
	if(unlikely(!list_node)){
#ifdef CONFIG_TX_KSTM_PROF
		rdtscll(a);
		shadowCopyCycles += (a - cycles);
#endif	
		if(!should_sleep)
			winner = 0;
		UNLOCK_XOBJ(head->xobj);
		abort_self(winner, 0);
	}
	UNLOCK_XOBJ(head->xobj);

	// Allocate the shadow copy and update the local workset
	
	//alloc a shadow object: TODO cache allocate these
	shadow = alloc_tx_hlist();
	if(!shadow)
		goto fail1;

	/* Lock 'em up */
	rlock_tx_hlist(head);

	memcpy(shadow, head, sizeof(struct tx_hlist_head));

	hlist_init_tx(shadow, mode);

	/* unLock 'em up */
	runlock_tx_hlist(head);

	/* XXX: We are not going to overwrite the parent in the shadow
	 * copy so that we can just memcpy the whole thing when we are
	 * done.  Be aware.
	 */

	shadow->shadow = 1;
	shadow->rw = mode;

#ifdef CONFIG_TX_KSTM_ASSERTIONS

	checkpoint = alloc_tx_hlist();
	if(!checkpoint)
		goto fail2;
	memcpy(checkpoint, shadow, sizeof(struct tx_hlist_head));
#endif

	list_node->type = TYPE_HLIST_HEAD;
	list_node->shadow_obj = shadow;
	list_node->orig_obj = head;
	list_node->rw = mode;
	/* Need to hold the dcache lock and there is only one of them */
	list_node->lock = lock_hlist;
	list_node->unlock = unlock_hlist;
	list_node->commit = commit_hlist_head;
	list_node->abort  = abort_hlist_head;
	list_node->release = release_hlist;
	list_node->tx_obj = head->xobj;

#ifdef CONFIG_TX_KSTM_ASSERTIONS
	list_node->checkpoint_obj = checkpoint;
	list_node->validate = validate_hlist_head;
#endif
	workset_add(list_node,
		    &(current->transaction->object_list));

#ifdef CONFIG_TX_KSTM_PROF
	rdtscll(a);
	shadowCopyCycles += (a - cycles);
#endif	
	return shadow;

#ifdef CONFIG_TX_KSTM_ASSERTIONS
fail2:
	free_tx_hlist(checkpoint);
#endif
fail1:
	free_tx_hlist(shadow);
	BUG();
#ifdef CONFIG_TX_KSTM_PROF
	rdtscll(a);
	shadowCopyCycles += (a - cycles);
#endif	
	return ERR_PTR(-ETXABORT);
}

void *tx_cache_get_tx_hlist_head_void(void* in, enum access_mode mode){
	return (void*) __tx_cache_get_tx_hlist_head((struct tx_hlist_head *) in, mode);
}

struct tx_hlist_head *tx_cache_get_tx_hlist_head(struct tx_hlist_head *head){
	return __tx_cache_get_tx_hlist_head(head, ACCESS_RW);
}

struct tx_hlist_head *tx_cache_get_tx_hlist_head_ro(struct tx_hlist_head *head){
	return __tx_cache_get_tx_hlist_head(head, ACCESS_R);
}

#else 

struct tx_list_head *tx_cache_get_tx_list_head(struct tx_list_head * head){
	return head;
}

struct tx_list_head *tx_cache_get_tx_list_head_ro(struct tx_list_head * head){
	return head;
}


struct tx_hlist_head *tx_cache_get_tx_hlist_head(struct tx_hlist_head * head){
	return head;
}

struct tx_hlist_head *tx_cache_get_tx_hlist_head_ro(struct tx_hlist_head * head){
	return head;
}

void *tx_cache_get_tx_list_head_void(void* in, enum access_mode mode){
	return (void*) in;
}


#endif //CONFIG_TX_KSTM

EXPORT_SYMBOL(tx_cache_get_tx_list_head_void);

