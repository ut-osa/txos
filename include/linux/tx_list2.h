#ifndef _LINUX_TX_LIST2_H
#define _LINUX_TX_LIST2_H

#ifdef __KERNEL__

#include <linux/module.h>
#include <linux/stddef.h>
#include <linux/poison.h>
#include <linux/prefetch.h>
#include <asm/system.h>
#include <linux/transaction.h>
#include <linux/list.h>
#include <linux/tx_list.h>

#ifndef CONFIG_DISABLE_LIST2

/* New Tx List strategy:
 *  List has:
 *   Old and new list pointers (primary and shadow) in same struct
 *   xobj
 *   Lives in stable object, not swappable portion
 *   Lock neighbors for insert/delete
 *   Use xobj to check consistency
 *   
 */

#define NON_TX              0x0
#define TRANSACTIONAL_ADD   0x1
#define TRANSACTIONAL_DEL   0x2

struct tx_list2_entry {
	struct list_head list;
	int transactional_state;
	struct transaction *transaction;
	struct tx_list2_entry_ref *cursor;  /* Lives in a stable object, has shadow version */
	struct tx_list2_head *parent;
	struct list_head spec; /* To put on the speculative list */
	int embedded; /* Is this embedded in another object? */
};

#define NO_TX    0
#define TX_R     1
#define TX_W     2
#define TX_EXCL  3

struct tx_list2_head {
	struct list_head head;
	spinlock_t lock;
	int mode;

	struct list_head spec_list; /* speculative entries do we have */
	struct transactional_object xobj; /* Embedded xobj for heads - could probably be minimized */
};

struct tx_list2_entry_ref {
	struct tx_list2_entry entry;
	struct tx_list2_entry *sentry;
	struct transaction *tx;
};

#define LOCK_LIST(head) do{ spin_lock(&(head)->lock); record_tx_lock(&(head)->lock, SPIN_LOCK); } while(0)
#define UNLOCK_LIST(head) do{ spin_unlock(&(head)->lock); record_tx_unlock(&(head)->lock, SPIN_LOCK); } while(0)

static inline void INIT_TX_LIST2_HEAD(struct tx_list2_head *head)
{
	INIT_LIST_HEAD(&head->head);
	spin_lock_init(&head->lock);
	head->mode = NO_TX;
	INIT_LIST_HEAD(&head->spec_list);
	init_tx_object(&head->xobj, TYPE_LIST2_HEAD);	
}

static inline void INIT_TX_LIST2_ENTRY(struct tx_list2_entry *entry, 
				       struct tx_list2_entry_ref *cursor)
{
	INIT_LIST_HEAD(&entry->list);
	entry->transactional_state = NON_TX;
	entry->transaction = NULL;
	entry->cursor = cursor;
	INIT_LIST_HEAD(&entry->spec);
	entry->parent = NULL;
	entry->embedded = 0;
}

static inline void INIT_TX_LIST2_REF(struct tx_list2_entry_ref *ref)
{
	INIT_TX_LIST2_ENTRY(&ref->entry, ref);
	ref->sentry = NULL;
	ref->tx = NULL;
	ref->entry.embedded = 1;
}


void acquire_list(struct tx_list2_head *head, enum access_mode mode);

static inline void acquire_list_entry_ref(struct tx_list2_head *head,
					  struct tx_list2_entry_ref *ref){
	acquire_list(head, ACCESS_RW);

	if(ref->tx != NULL && ref->tx != current->transaction){
		// We need to contend for this entry
		if(!contentionManager(current->transaction, ref->tx, NULL)){
			UNLOCK_LIST(head);
			// XXX: Could potentially sleep here without aborting
			abort_self(ref->tx, 0);
		} else {
			/* Give the other joker the boot */
			ref->tx = current->transaction;
			ref->sentry = NULL;
			ref->entry.transactional_state = NON_TX;
			ref->entry.transaction = NULL;
		}
	}
}

/* Ref may be null */
static void check_list2_asymmetric_conflict(struct tx_list2_head *head, 
						   struct tx_list2_entry_ref *ref,
						   enum access_mode mode){
	struct transaction *winner;
	if(active_transaction())
		return;
	if(mode == ACCESS_R){
		while((head->mode != NO_TX && head->mode != TX_R)
		      && (winner =					
			  check_asymmetric_conflict(&head->xobj, mode, 
						    tx_preemptible(1), 0)
			      )){
			
			/* Sleep until the winner commits */
			UNLOCK_LIST(head);
			wait_on_tx(winner);
			LOCK_LIST(head);
		}
		
		if(head->mode != TX_R)
			head->mode = NO_TX;

		/* Kick out the tx-deleter/adder.  The asymmetric conflict
		 * check should have aborted him.
		 */
		if(ref && ref->tx){
			ref->tx = NULL;
			ref->sentry = NULL;
		}

	} else {
	retry:
		while((head->mode != NO_TX && head->mode != TX_W)
		      && (winner =					
			  check_asymmetric_conflict(&head->xobj, mode, 
						    tx_preemptible(1), 0)
			      )){
			
			/* Sleep until the winner commits */
			UNLOCK_LIST(head);
			wait_on_tx(winner);
			LOCK_LIST(head);
		}
		if(head->mode != TX_W)
			head->mode = NO_TX;

		/* Kick out the tx-deleter/adder.  The asymmetric conflict
		 * check may not have aborted him
		 */
		if(ref && ref->tx){
			if(tx_preemptible(1)
			   && contentionManager(ref->tx, current->transaction, NULL)){
				
				/* Sleep until the winner commits */
				UNLOCK_LIST(head);
				wait_on_tx(ref->tx);
				LOCK_LIST(head);
				goto retry;
			} else {
				abortTransaction(ref->tx);
				ref->tx = NULL;
				ref->sentry = NULL;
			}
		}
	}
}

extern struct kmem_cache *tx_list2_cachep;
#define alloc_tx_list2_entry() kmem_cache_alloc(tx_list2_cachep, GFP_ATOMIC)
#define free_tx_list2_entry(entry) kmem_cache_free(tx_list2_cachep, entry)

static inline void tx_list2_add_locked(struct tx_list2_entry_ref *cursor,
				       struct tx_list2_head *head)
{
	
	struct tx_list2_entry *entry;
	struct transaction *tx = NULL;
	
	if(live_transaction()){
		acquire_list_entry_ref(head, cursor);
		tx = current->transaction;
		entry = alloc_tx_list2_entry();
		INIT_TX_LIST2_ENTRY(entry, cursor);
		entry->transaction = tx;
	} else {
		check_list2_asymmetric_conflict(head, cursor, ACCESS_RW);
		entry = &cursor->entry;
	}
	
	/* At this point, we can safely work on the list*/
	list_add(&entry->list, &head->head);
	entry->parent = head;

	if(tx){
		entry->transactional_state = TRANSACTIONAL_ADD;
		cursor->sentry = entry;
		cursor->tx = current->transaction;
		list_add(&entry->spec, &head->spec_list);
	} else {
		entry->transactional_state =  NON_TX;
	}
}

static inline void tx_list2_add(struct tx_list2_entry_ref *cursor, 
				struct tx_list2_head *head)
{
	LOCK_LIST(head);
	tx_list2_add_locked(cursor, head);
	UNLOCK_LIST(head);
}

static inline void tx_list2_add_tail(struct tx_list2_entry_ref *cursor, struct tx_list2_head *head){
	
	struct tx_list2_entry *entry;
	struct transaction *tx = NULL;
	
	LOCK_LIST(head);

	if(live_transaction()){
		acquire_list_entry_ref(head, cursor);
		tx = current->transaction;
		entry = alloc_tx_list2_entry();
		INIT_TX_LIST2_ENTRY(entry, cursor);
		entry->transaction = tx;
	} else {
		check_list2_asymmetric_conflict(head, cursor, ACCESS_RW);
		entry = &cursor->entry;
	}
	
	/* At this point, we can safely work on the list*/
	list_add_tail(&entry->list, &head->head);
	entry->parent = head;

	if(tx){
		entry->transactional_state = TRANSACTIONAL_ADD;
		cursor->sentry = entry;
		cursor->tx = current->transaction;
		list_add(&entry->spec, &head->spec_list);
	} else {
		entry->transactional_state =  NON_TX;
	}

	
	UNLOCK_LIST(head);
}

static inline void tx_list2_add_at_locked(struct tx_list2_entry_ref *cursor, 
					  struct tx_list2_entry *at)
{
	
	struct tx_list2_entry *entry;
	struct transaction *tx = NULL;
	
	if(live_transaction()){
		acquire_list_entry_ref(at->parent, cursor);
		tx = current->transaction;
		entry = alloc_tx_list2_entry();
		INIT_TX_LIST2_ENTRY(entry, cursor);
		entry->transaction = tx;
	} else {
		check_list2_asymmetric_conflict(at->parent, cursor, ACCESS_RW);
		entry = &cursor->entry;
	}
	
	/* At this point, we can safely work on the list*/
	list_add(&entry->list, &at->list);
	entry->parent = at->parent;

	if(tx){
		entry->transactional_state = TRANSACTIONAL_ADD;
		cursor->sentry = entry;
		cursor->tx = current->transaction;
		list_add(&entry->spec, &entry->parent->spec_list);
	} else {
		entry->transactional_state =  NON_TX;
	}

}

static inline void tx_list2_add_at(struct tx_list2_entry_ref *cursor, struct tx_list2_entry *at){
	
	LOCK_LIST(at->parent);
	tx_list2_add_at_locked(cursor, at);
	UNLOCK_LIST(at->parent);
}



static void tx_list2_del(struct tx_list2_entry_ref *cursor){

	struct tx_list2_head *head;
	struct tx_list2_entry *entry;

	if(live_transaction()){
		
		entry = cursor->tx == current->transaction ? 
			(cursor->sentry ? cursor->sentry : &cursor->entry)
			: &cursor->entry;
		
		/* DEP 2/5/09: I still contend we shouldn't get here */
		KSTM_BUG_ON(entry == NULL);
		
		head = entry->parent;
		/* We can re-delete a list */
		if(head == NULL)
			return;
		LOCK_LIST(head);
		acquire_list_entry_ref(head, cursor);
		KSTM_BUG_ON(entry->transactional_state != NON_TX && entry->transaction == NULL);
		if(cursor->sentry)
			BUG_ON(entry != cursor->sentry);
		cursor->sentry = NULL;
		cursor->tx = current->transaction;
		if(entry->transactional_state == TRANSACTIONAL_ADD){
			BUG_ON(entry->embedded);
			list_del_init(&entry->spec);
			goto delete_for_realzies;
		}
		entry->transactional_state |= TRANSACTIONAL_DEL;
		entry->transaction = current->transaction;
		list_add(&entry->spec, &head->spec_list);
	} else {
		entry = &cursor->entry;
		/* DEP 2/10/09: I think this is ok, as the same list
		 * entry can be removed more than once. (See
		 * d_child) 
		 */
		if(entry == NULL)
			return;
		head = entry->parent;
		if(head == NULL)
			return;
		LOCK_LIST(head);
		check_list2_asymmetric_conflict(head, cursor, ACCESS_RW);
	delete_for_realzies:
		list_del_init(&entry->list);
		if(entry->embedded){
			/* Reinit */
			entry->transactional_state = NON_TX;
			entry->transaction = NULL;
			INIT_LIST_HEAD(&entry->spec);
			entry->parent = NULL;
		} else
			free_tx_list2_entry(entry);
	}
	
	UNLOCK_LIST(head);
}

#define tx_list2_del_init(cursor) tx_list2_del(cursor)

static inline void tx_list2_del_locked(struct tx_list2_entry_ref *cursor){

	struct tx_list2_head *head;
	struct tx_list2_entry *entry;

	if(live_transaction()){

		entry = cursor->tx == current->transaction ? 
			(cursor->sentry ? cursor->sentry : &cursor->entry)
			: &cursor->entry;

		head = entry->parent;
		if(head == NULL)
			return;

		acquire_list_entry_ref(head, cursor);
		KSTM_BUG_ON(entry->transactional_state != NON_TX && entry->transaction == NULL);
		cursor->sentry = NULL;
		cursor->tx = current->transaction;
		if(entry->transactional_state == TRANSACTIONAL_ADD){
			BUG_ON(entry->embedded);
			list_del_init(&entry->spec);
			goto delete_for_realzies;
		}
		entry->transactional_state |= TRANSACTIONAL_DEL;
		entry->transaction = current->transaction;
		list_add(&entry->spec, &head->spec_list);
	} else {
		entry = &cursor->entry;
		/* DEP 2/10/09: I think this is ok, as the same list
		 * entry can be removed more than once. (See
		 * d_child) 
		 */
		if(entry == NULL)
			return;

		head = entry->parent;
		if(head == NULL)
			return;

		check_list2_asymmetric_conflict(head, cursor, ACCESS_RW);
	delete_for_realzies:
		list_del_init(&entry->list);
		if(entry->embedded){
			/* Reinit */
			entry->transactional_state = NON_TX;
			entry->transaction = NULL;
			INIT_LIST_HEAD(&entry->spec);
			entry->parent = NULL;
		} else
			free_tx_list2_entry(entry);
	}
	
}


#define tx_list2_move(cursor, head) do{				\
		tx_list2_del(cursor);				\
		tx_list2_add(cursor, head);			\
	} while(0)

#define tx_list2_move_locked(cursor, head) do{				\
		tx_list2_del_locked(cursor);				\
		tx_list2_add_locked(cursor, head);			\
	} while(0)


#define tx_list2_move_tail(cursor, head) do{			\
		tx_list2_del(cursor);				\
		tx_list2_add_tail(cursor, head);		\
	} while(0)

/* See if we can punt on this one 

static inline void __tx_list_splice (struct tx_list_head *list, struct tx_list_head *head)
{
	
	struct tx_list_head *first;
	struct tx_list_head *last;
	struct tx_list_head *at;

	if(!live_transaction()){					
		check_list_asymmetric_conflict(list);		
		if(list->next != list){
			check_list_asymmetric_conflict(list->next);		
			check_list_asymmetric_conflict(list->prev);		
		}
		check_list_asymmetric_conflict(head);		
		check_list_asymmetric_conflict(head->next);		
	} 

	check_tx_list_next(list, ACCESS_RW);
	check_tx_list_prev(list, ACCESS_RW);
	check_tx_list_next(head, ACCESS_RW);

	first = list->next;
	last = list->prev;
	at = head->next;

	first->prev = head;
	head->next = first;

	last->next = at;
	at->prev = last;
}

static inline void tx_list_splice (struct tx_list_head *list, struct tx_list_head *head)
{
	if(!tx_list_empty(list))
		__tx_list_splice(list, head);
}



static inline void tx_list_splice_init (struct tx_list_head *list, struct tx_list_head *head)
{
	if(!tx_list_empty(list)) {
		__tx_list_splice(list, head);
		__INIT_TX_LIST(list);
	}
}

*/

/* Replace for_each with an iterator */
// for each - get the head in R mode
// iterate as usual, filtering speculative nodes
struct tx_list2_iterator {
	struct list_head *cur;
	struct list_head *next;
	struct tx_list2_head *head;
};

static inline void tx_list2_get_iterator(struct tx_list2_iterator *iter, struct tx_list2_head *head){
	LOCK_LIST(head);

	if(live_transaction()){
		acquire_list(head, ACCESS_R);
	} else {
		check_list2_asymmetric_conflict(head, NULL, ACCESS_R);
	}
	
	iter->cur = &head->head;
	iter->next = iter->cur->next;
	iter->head = head;
}

static inline int tx_list2_get_iterator_pos(struct tx_list2_iterator *iter, struct tx_list2_entry_ref *cursor){

	struct tx_list2_entry *entry = cursor->tx == current->transaction ? cursor->sentry : &cursor->entry;
	struct tx_list2_head *head;

	if(unlikely(entry == NULL))
		return 1;

	head = entry->parent;
	
	LOCK_LIST(head);
	if(live_transaction()){
		acquire_list(head, ACCESS_R);
	} else {
		check_list2_asymmetric_conflict(head, NULL, ACCESS_R);
	}

	iter->cur = &entry->list;
	iter->next = iter->cur->next;
	iter->head = head;

	return 0;
}


static inline void tx_list2_put_iterator(struct tx_list2_iterator *iter){
	UNLOCK_LIST(iter->head);
}

static inline int tx_list2_iter_next(struct tx_list2_iterator *iter){					
	int rv = 0;
	while(rv == 0 && iter->next != &iter->head->head){
		struct tx_list2_entry *entry;
		iter->cur = iter->next;						
		iter->next = iter->cur->next;			
		entry = container_of(iter->cur, struct tx_list2_entry, list);
		if(entry->transactional_state == NON_TX
		   || (entry->transactional_state == TRANSACTIONAL_ADD 
		       && entry->transaction == current->transaction)
		   || (entry->transactional_state == TRANSACTIONAL_DEL
		       && entry->transaction != current->transaction))
			rv = 1;
	} 
	return rv;
}

#define tx_list2_iter_entry(iter, type, member)			\
	list_entry(list_entry((iter)->cur, struct tx_list2_entry, list)->cursor, \
		   type, member)

#define tx_list2_first_entry(hd, type, member)				\
	list_entry(list_entry((hd)->head.next, struct tx_list2_entry, list)->cursor, \
		   type, member)

#define tx_list2_move_iter(cursor, iter) do{			\
		tx_list2_del(cursor);				\
		tx_list2_add_at(cursor, list_entry((iter)->cur, struct tx_list2_entry, list)); \
} while(0)

#define tx_list2_move_iter_locked(cursor, iter) do{			\
		tx_list2_del_locked(cursor);				\
		tx_list2_add_at_locked(cursor,	list_entry((iter)->cur, struct tx_list2_entry, list)); \
	} while(0)


/*
#define tx_list_for_each(pos, head, mode)			\
	for (check_tx_list_next_inline((head), mode),		\
		     pos = (head)->next;			\
	     pos != (head);					\
	     check_tx_list_next_inline(pos, mode),		\
		     pos = pos->next)


#define tx_list_for_each_safe(pos, n, head, mode)			\
	for (check_tx_list_next_inline((head), mode),			\
		     pos = (head)->next,                                \
                     check_tx_list_next_inline((pos), mode),		\
                     n = pos->next;              			\
	     pos != (head);						\
	     pos = n, check_tx_list_next_inline(n, mode), n = pos->next)


#define tx_list_for_each_entry(pos, head, type, member, mode)		\
	for(								\
		check_tx_list_next_inline(head, mode),			\
			pos = tx_list_entry((head)->next, type, member); \
		&pos->member != (head);					\
		check_tx_list_next_inline(&(pos->member), mode),	\
			pos = tx_list_entry(pos->member.next, type, member))

#define tx_list_for_each_entry_safe(pos, n, head, type, member, mode)	\
	for(								\
		check_tx_list_next_inline(head, mode), 			\
			pos = tx_list_entry((head)->next, type, member), \
                        check_tx_list_next_inline(&((pos)->member), mode), \
			n = tx_list_entry(pos->member.next, type, member); \
		&pos->member != (head);					\
	        pos = n,                                                \
			check_tx_list_next_inline(&((pos)->member), mode), \
			n = tx_list_entry(pos->member.next, type, member))
*/

static inline int tx_list2_empty_locked(struct tx_list2_head *head){
	struct transaction *tx = NULL;
	struct tx_list2_entry *iter;
	int rv = 1;

	if(live_transaction()){
		acquire_list(head, ACCESS_R);
		tx = current->transaction;
	} else {
		check_list2_asymmetric_conflict(head, NULL, ACCESS_R);
	}

	/* Ignore transactionally accessed entries */
	list_for_each_entry(iter, &head->head, list){
		if(iter->transactional_state == NON_TX
		   || (iter->transactional_state == TRANSACTIONAL_ADD && iter->transaction == tx)
		   || (iter->transactional_state == TRANSACTIONAL_DEL && iter->transaction != tx))
		   rv = 0;
	}
	return rv;
}

static inline int tx_list2_empty(struct tx_list2_head *head){
	int rv = 1;

	LOCK_LIST(head);
	
	rv = tx_list2_empty_locked(head);
	
	UNLOCK_LIST(head);
	return rv;
}


#define tx_list2_unreferenced(ref) (list_empty(&(ref)->entry.list)) && ((ref)->sentry == NULL)

#else // CONFIG_DISABLE_LIST2 set

#define tx_list2_head list_head
#define tx_list2_entry_ref list_head

struct tx_list2_iterator{
	struct list_head *head;
	struct list_head *cur;
};

#define tx_list2_del(head) list_del(head)
#define tx_list2_del_init(head) list_del_init(head)
#define tx_list2_add(a, b) list_add(a, b)
#define tx_list2_add_tail(a, b) list_add_tail(a, b)
#define tx_list2_move(a, b) list_move(a, b)
#define tx_list2_move_iter_locked(a, b) list_move(a, (b)->cur)

#define INIT_TX_LIST2_HEAD(head) INIT_LIST_HEAD(head)
#define INIT_TX_LIST2_REF(head) INIT_LIST_HEAD(head)
#define tx_list2_empty(list) list_empty(list)
#define tx_list2_empty_locked(list) list_empty(list)

#define tx_list2_get_iterator(iter, list) do{	\
		(iter)->head = list;		\
		(iter)->cur = list;		\
	} while(0)

#define tx_list2_get_iterator_pos(iter, list) 0

static inline int tx_list2_iter_next(struct tx_list2_iterator *iter){
	iter->cur = iter->cur->next;
	return iter->cur != iter->head;
}

#define tx_list2_iter_entry(iter, type, member)			\
	list_entry((iter)->cur,					\
		   type, member)

#define tx_list2_put_iterator(iter)
#define LOCK_LIST(list)
#define UNLOCK_LIST(list)

#define tx_list2_first_entry(hd, type, member)				\
	list_entry((hd)->next, type, member)


#define tx_list2_unreferenced(lst) list_empty(lst)

#define check_list2_asymmetric_conflict(head, a, b)

#endif

/* Do we add other fns to interface? */
#else
#warning "don't include kernel headers in userspace"
#endif /* __KERNEL__ */
#endif
