#ifndef _LINUX_TX_LIST_H
#define _LINUX_TX_LIST_H

#ifdef __KERNEL__

#include <linux/module.h>
#include <linux/stddef.h>
#include <linux/poison.h>
#include <linux/prefetch.h>
#include <asm/system.h>
#include <linux/transaction.h>
#include <linux/list.h>

/* Tx List strategy:
 *  List has:
 *   Old and new list pointers (primary and shadow)
 *   If equal, no change
 *   If a shadow next or prev point to primary, list_del
 *   If a shadow next points to something different, need to do a list_add
 *   
 */

#define tx_list_entry(ptr, type, member) list_entry(ptr, type, member)
#define tx_hlist_entry(ptr, type, member) list_entry(ptr, type, member)

#ifdef CONFIG_TX_KSTM

extern void *lookup_placeholder(void *in, enum access_mode);

static inline long compute_offset(void *parent, void *list)
{
	return (long) ((char*) parent - ((char *) list));
}

struct tx_list_head {
	struct tx_list_head *next, *prev;
	struct tx_list_head* self;  /* Pointer from shadow to stable copy */
	int shadow; /* Is this a shadow entry? */
	enum access_mode rw;
	void *(*lookup)(void *, enum access_mode); /* The function to fetch the shadow copy */
	long offset; /* The offset into the struct, for pointer acrobatics */
	atomic_t tx_count;

	struct transactional_object* xobj; /* Reference to xobj - only _xobj in heads */
	struct transactional_object _xobj; /* Embedded xobj for heads - could probably be minimized */
};

#define TX_LIST_INIT(name) { &(name), &(name), &(name), 0, 0, tx_cache_get_tx_list_head_void, 0, {0, 0},\
			&(name)._xobj, {TYPE_LIST_HEAD, NULL, {&(name)._xobj.readers, &(name)._xobj.readers} }  }

#define TX_LIST(name)					\
	struct tx_list_head name = TX_LIST_INIT(name)

static inline void __INIT_TX_LIST(struct tx_list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void INIT_TX_LIST(struct tx_list_head *list, void *(*fn)(void *, enum access_mode), void *parent, 
				struct transactional_object *xobj)
{
	__INIT_TX_LIST(list);
	list->self = list;
	list->shadow = 0;
	KSTM_BUG_ON(fn == NULL);
	list->lookup = fn;
	list->offset = compute_offset(parent, list);
	atomic_set(&list->tx_count, 0);
	list->xobj = xobj ? xobj : &list->_xobj;
	init_tx_object(&list->_xobj, TYPE_LIST_HEAD);
}

static inline void list_init_tx(struct tx_list_head *lst, enum access_mode mode){
	lst->shadow = 1;
	if(lst->prev == lst->self)
		lst->prev = lst;

	if(lst->next == lst->self)
		lst->next = lst;

	lst->rw = mode;

	atomic_inc(&lst->self->tx_count);
}

static inline void list_validate_tx(struct tx_list_head *orig, struct tx_list_head *checkpoint){
	if(orig->next != checkpoint->next){
		printk(KERN_ERR "Inconsistent next value for %p, %p - %p, %p\n", orig->next, checkpoint->next, &orig->next, &checkpoint->next);
	}

	if(orig->prev != checkpoint->prev){
		printk(KERN_ERR "Inconsistent prev value for %p: %p, %p - %p, %p\n", orig->self, orig->prev, checkpoint->prev, &orig->prev, &checkpoint->prev);
	}

	if(orig->self != checkpoint->self){
		printk(KERN_ERR "Inconsistent self value for %p, %p - %p, %p\n", orig->self, checkpoint->self, &orig->self, &checkpoint->self);
	}

	TX_VALIDATE(orig, checkpoint, next);
	TX_VALIDATE(orig, checkpoint, prev);
	TX_VALIDATE(orig, checkpoint, self);
	KSTM_BUG_ON(checkpoint->self != orig);
	if(orig->next != LIST_POISON1 && orig != orig->next->prev){
		printk(KERN_ERR "Inconsistent value at %p, %p\n", &orig->next, &orig->next->prev);
		BUG();
	}
	if(orig->prev != LIST_POISON2 && orig != orig->prev->next){
		printk(KERN_ERR "Inconsistent value at %p, %p\n", &orig->prev, &orig->prev->next);
		BUG();
	}
}

static inline void list_validate_tx_ro(struct tx_list_head *orig, struct tx_list_head *shadow){

	if(orig->next == orig){
		if(shadow->next != shadow)
			printk(KERN_ERR "Shadow = %p (%p) but shadow next = %p (%p). orig = %p\n", shadow, &shadow, shadow->next, &shadow->next, orig);

		KSTM_BUG_ON(shadow->next != shadow);
		KSTM_BUG_ON(shadow->prev != shadow);
	} else {
		KSTM_BUG_ON(orig->next != shadow->next->self);
		KSTM_BUG_ON(orig->prev != shadow->prev->self);
	}
	TX_VALIDATE(orig, shadow, self);
	KSTM_BUG_ON(shadow->self != orig);
}


static inline void __check_list_asymmetric_conflict(struct tx_list_head *head) 
{
	struct transaction *winner;
	while((atomic_read(&(head)->tx_count) != 0)			
	      && inactive_transaction()
	      && (winner =					
		  check_asymmetric_conflict(head->xobj, ACCESS_RW, 
					    tx_preemptible(0), 0)
		      )){
			
		/* Sleep until the winner commits */
		wait_on_tx(winner);
	}
}

#define check_list_asymmetric_conflict(head) __check_list_asymmetric_conflict((struct tx_list_head *) head)

extern void list_commit_tx(struct tx_list_head *head, int new);

/* DEP: ugly and inlined function to avoid tmp declaration in macro.
 * Eesh
 */

static inline struct tx_list_head * check_tx_list_entry(struct tx_list_head *head, enum access_mode mode){
	if(!live_transaction()){
		check_list_asymmetric_conflict(head);
	} else if((!head->shadow) || head->rw < mode ){
		void *tmp = ((char *)head) + head->offset;
		struct tx_list_head * t;
		KSTM_BUG_ON(head->lookup == NULL);
		tmp = head->lookup(tmp, mode);
		t = (struct tx_list_head *) (((char *)tmp) - head->offset);
		return t;
	} 

	return head;
}

#define check_tx_list_next_inline(head, mode) (head)->next = check_tx_list_entry(((head)->next), mode), \
		(head)->next->prev = head

#define check_tx_list_prev_inline(head, mode) (head)->prev = check_tx_list_entry(((head)->prev), mode), \
		(head)->prev->next = head

#define check_tx_list_next(head, mode) if((head)->shadow) check_tx_list_next_inline(head, mode)
#define check_tx_list_prev(head, mode) if((head)->shadow) check_tx_list_prev_inline(head, mode)

#define get_tx_list_next(head, mode) (head)->shadow ? check_tx_list_entry((head)->next, mode) : (head)->next
#define get_tx_list_prev(head, mode) (head)->shadow ? check_tx_list_entry((head)->prev, mode) : (head)->prev


/* DEP: Need to ensure that all affected list entries are in our
 * workset.  Assume that new and head are.
 */
#define tx_list_add(new, head) do{					\
  		KSTM_BUG_ON(live_transaction() && (new)->rw != ACCESS_RW);\
		KSTM_BUG_ON((new)->shadow && !(head)->shadow);		\
		KSTM_BUG_ON(!(new)->shadow && (head)->shadow);		\
		if(!live_transaction()){				\
			check_list_asymmetric_conflict(new);		\
			check_list_asymmetric_conflict(head);		\
			if((head)->next != head)			\
				check_list_asymmetric_conflict((head)->next); \
		} else if((new)->shadow)				\
			check_tx_list_next(head, ACCESS_RW);		\
  		KSTM_BUG_ON(live_transaction() && (new)->rw != ACCESS_RW);\
		list_add((struct list_head *) (new), (struct list_head *) (head)); \
	} while(0)

#define tx_list_add_tail(new, head) do{					\
		KSTM_BUG_ON((new)->shadow && !(head)->shadow);		\
		KSTM_BUG_ON(!(new)->shadow && (head)->shadow);		\
		if(!live_transaction()){				\
			check_list_asymmetric_conflict(new);		\
			check_list_asymmetric_conflict(head);		\
			if((head)->prev != head)			\
				check_list_asymmetric_conflict((head)->prev); \
		} else if((new)->shadow)				\
			check_tx_list_prev(head, ACCESS_RW);		\
		list_add_tail((struct list_head *) (new), (struct list_head *) (head)); \
	} while(0)

#define __tx_list_del(entry) do{					\
		if(!live_transaction()){				\
			check_list_asymmetric_conflict(entry);		\
			if((entry)->next != entry && (entry)->next != LIST_POISON1){			\
				check_list_asymmetric_conflict((entry)->next); \
				check_list_asymmetric_conflict((entry)->prev); \
			}						\
		} else if((entry)->shadow){					\
			check_tx_list_next(entry, ACCESS_RW);		\
			check_tx_list_prev(entry, ACCESS_RW);		\
		}							\
  		KSTM_BUG_ON(live_transaction() && (entry)->rw != ACCESS_RW);\
		__list_del((struct list_head *) (entry)->prev, (struct list_head *) (entry)->next); \
	} while(0)

#define tx_list_del(entry) do{						\
		if(!live_transaction()){				\
			check_list_asymmetric_conflict(entry);		\
			if((entry)->next != entry && (entry)->next != LIST_POISON1){			\
				check_list_asymmetric_conflict((entry)->next); \
				check_list_asymmetric_conflict((entry)->prev); \
			}						\
		} else if((entry)->shadow){					\
			check_tx_list_next(entry, ACCESS_RW);		\
			check_tx_list_prev(entry, ACCESS_RW);		\
		}							\
  		KSTM_BUG_ON(live_transaction() && (entry)->rw != ACCESS_RW);\
		list_del((struct list_head *) (entry));			\
	} while(0)

#define tx_list_del_init(entry) do{					\
		if(!live_transaction()){				\
			check_list_asymmetric_conflict(entry);		\
			if((entry)->next != entry && (entry)->next != LIST_POISON1){			\
				check_list_asymmetric_conflict((entry)->next); \
				check_list_asymmetric_conflict((entry)->prev); \
			}						\
		} else if((entry)->shadow){					\
			check_tx_list_next(entry, ACCESS_RW);		\
			check_tx_list_prev(entry, ACCESS_RW);		\
		}							\
  		KSTM_BUG_ON(live_transaction() && (entry)->rw != ACCESS_RW);\
		__list_del((struct list_head *) (entry)->prev, (struct list_head *) (entry)->next); \
		__INIT_TX_LIST(entry);					\
	} while(0)


#define tx_list_move(list, head) do{					\
		__tx_list_del(list);					\
		tx_list_add(list, head);				\
	} while(0)

#define tx_list_move_tail(list, head) do{				\
		__tx_list_del(list);					\
		tx_list_add_tail(list, head);				\
	} while(0)


#define tx_list_empty(lst) list_empty((struct list_head *) (lst))

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


/* XXX: This doesn't get the next entry into the workset */
#define tx_list_first_entry(ptr, type, member) tx_list_entry((ptr)->next, type, member)

/* tx hlist 
 *
 * DEP: We are going to make pprev just a prev pointer so that we can
 * look things up.  Consequently, we also make head essentially the
 * same thing as a node.
 */

struct tx_hlist_node {
	struct tx_hlist_node *next, *prev;
	struct tx_hlist_node *self; /* Pointer from shadow to stable copy */
	int shadow; /* Is this a shadow entry? */
	enum access_mode rw;
	void *(*lookup)(void *, enum access_mode); /* The function to fetch the shadow copy */
	long offset; /* The offset into the struct, for pointer acrobatics */
	atomic_t tx_count;

	struct transactional_object* xobj; /* Reference to xobj - only _xobj in heads */
	struct transactional_object _xobj; /* Embedded xobj for heads - could probably be minimized */

	rwlock_t lock; /* RW lock */

};

#define rlock_tx_hlist(h) do{						\
		if((!(h)->shadow) ||					\
		   atomic_read(&current->transaction->task_count) > 1 ){\
			read_lock(&(h)->lock);				\
			record_tx_lock(&(h)->lock, READ_LOCK);		\
		}}while(0)						

#define runlock_tx_hlist(h) do{						\
		if(!(h)->shadow ||					\
		   atomic_read(&current->transaction->task_count) > 1 ){\
			read_unlock(&(h)->lock);			\
			record_tx_unlock(&(h)->lock, READ_LOCK);	\
		}}while(0)						

#define wlock_tx_hlist(h) do{						\
		if(!(h)->shadow ||					\
		   atomic_read(&current->transaction->task_count) > 1 ){\
			write_lock(&(h)->lock);				\
			record_tx_lock(&(h)->lock, WRITE_LOCK);		\
		}}while(0)						


#define wunlock_tx_hlist(h) do{						\
		if(!(h)->shadow ||					\
		   atomic_read(&current->transaction->task_count) > 1 ){\
			write_unlock(&(h)->lock);			\
			record_tx_unlock(&(h)->lock, WRITE_LOCK);	\
		}}while(0)						


#define tx_hlist_head tx_hlist_node

static inline void INIT_TX_HLIST_NODE(struct tx_hlist_node *h, void *(*fn)(void *, enum access_mode), void *parent, 
				      struct transactional_object *xobj)
{
	h->next = NULL;
	h->prev = NULL;
	h->self = h;
	h->shadow = 0;
	KSTM_BUG_ON(fn == NULL);
	h->lookup = fn;
	h->offset = compute_offset(parent, h);
	atomic_set(&h->tx_count, 0);
	rwlock_init(&h->lock);		
	h->xobj = xobj;
}

#define INIT_TX_HLIST_HEAD(h, fn, parent) do{			\
		INIT_TX_HLIST_NODE(h, fn, parent, &(h)->_xobj);	\
		init_tx_object(&(h)->_xobj, TYPE_HLIST_HEAD);	\
	} while(0)

static inline void hlist_init_tx(struct tx_hlist_node *lst, enum access_mode mode){
	lst->shadow = 1;
	lst->rw = mode;
	atomic_inc(&lst->self->tx_count);
}


static inline void hlist_validate_tx(struct tx_hlist_node *orig, struct tx_hlist_node *checkpoint){
	TX_VALIDATE(orig, checkpoint, next);
	TX_VALIDATE(orig, checkpoint, prev);
	TX_VALIDATE(orig, checkpoint, self);
	KSTM_BUG_ON(checkpoint->self != orig);

	KSTM_BUG_ON(orig->next != LIST_POISON1
		    && orig->next != NULL
		    && orig != orig->next->prev);

	KSTM_BUG_ON(orig->prev != LIST_POISON2
		    && orig->prev != NULL
		    && orig != orig->prev->next);

}

static inline void hlist_validate_tx_ro(struct tx_hlist_node *orig, struct tx_hlist_node *shadow){
	if(orig->next == NULL)
		KSTM_BUG_ON(shadow->next != NULL);
	else
		KSTM_BUG_ON(shadow->next->self != orig->next);

	if(orig->prev == NULL)
		KSTM_BUG_ON(shadow->prev != NULL);
	else
		KSTM_BUG_ON(shadow->prev->self != orig->prev);

	TX_VALIDATE(orig, shadow, self);
	KSTM_BUG_ON(shadow->self != orig);
}


extern void hlist_commit_tx(struct tx_hlist_node *head, int new);

static inline struct tx_hlist_node * check_tx_hlist_node(struct tx_hlist_node *head, enum access_mode mode){
	/* Assume strict inclusion of modes for now */
	if(!live_transaction())
		check_list_asymmetric_conflict(head);
	else if((!head->shadow) || (head->rw < mode) ){
		void *tmp = ((char *)head) + head->offset;
		KSTM_BUG_ON(head->lookup == NULL);
		tmp = head->lookup(tmp, mode);
		return (struct tx_hlist_head *) (((char *)tmp) - head->offset);
	} 

	return head;
}

static inline void check_tx_hlist_next(struct tx_hlist_node *h, enum access_mode mode){
	
	if(h && h->shadow && h->next){
		h->next = check_tx_hlist_node(h->next, mode);	
		if(unlikely(IS_ERR(h->next)))
			return;
		h->next->prev = h;
	}
}

static inline void check_tx_hlist_prev(struct tx_hlist_node *h, enum access_mode mode){
	
	if(h && h->shadow && h->next){
		h->prev = check_tx_hlist_node(h->prev, mode);	
		if(unlikely(IS_ERR(h->prev)))
			return;
		h->prev->next = h;
	}
}



#define get_tx_hlist_next(head, mode) (head && (head)->next) ? \
	check_tx_hlist_node((head)->next, mode) : (head)->next 

#define get_tx_hlist_prev(head, mode) (head && (head)->prev) ? \
	check_tx_hlist_node((head)->prev, mode) : (head)->prev 


static inline void __tx_hlist_del(struct tx_hlist_node *n){
	struct tx_hlist_node *next;
	if(!live_transaction()){
		check_list_asymmetric_conflict(n);
		if(n->next != NULL && n->next != LIST_POISON1 && n->next != n)
			check_list_asymmetric_conflict(n->next);
		if(n->prev != NULL && n->prev != LIST_POISON2 && n->prev != n)
			check_list_asymmetric_conflict(n->prev);
	} else if((n)->shadow){					
		check_tx_hlist_next(n, ACCESS_RW);
		check_tx_hlist_prev(n, ACCESS_RW);
	}							
	next = n->next;
	n->prev->next = next;
	if (next)
		next->prev = n->prev;
}

static inline void tx_hlist_del_rcu(struct tx_hlist_node *n)
{
	__tx_hlist_del(n);
	n->prev = LIST_POISON2;
}

static inline int tx_hlist_unhashed(const struct tx_hlist_node *h)
{
	return h->prev == NULL;
}

static inline void tx_hlist_del_init(struct tx_hlist_node *n)
{
	if(!tx_hlist_unhashed(n)){
		__tx_hlist_del(n);
		n->next = NULL;
		n->prev = NULL;
	}
}

static inline struct tx_hlist_node * tx_hlist_head_first(struct tx_hlist_head *h)
{
	return h->next;
}

static inline int tx_hlist_empty(const struct tx_hlist_head *h)
{
	return !h->next;
}


static inline void tx_hlist_add_head(struct tx_hlist_node *n, struct tx_hlist_head *h)
{
	struct tx_hlist_node *first;
	wlock_tx_hlist(h);
	KSTM_BUG_ON(n->shadow != h->shadow);
	if(!live_transaction()){				       
		check_list_asymmetric_conflict(n);		
		check_list_asymmetric_conflict(h);		
		/* Next checked below */
	}								
	check_tx_hlist_next(h, ACCESS_RW);
	first = h->next;
	n->next = first;
	n->prev = h;
	smp_wmb();
	if (first)
		first->prev = n;
	h->next = n;
	wunlock_tx_hlist(h);
}

static inline void tx_hlist_add_head_rcu(struct tx_hlist_node *n, struct tx_hlist_head *h)
{
	struct tx_hlist_node *first;
	wlock_tx_hlist(h);
	KSTM_BUG_ON(n->shadow != h->shadow);
	if(!live_transaction()){				       
		check_list_asymmetric_conflict(n);		
		check_list_asymmetric_conflict(h);		
	}								
	check_tx_hlist_next(h, ACCESS_RW);
	if(unlikely(IS_ERR(h->next)))
		return;
	first = h->next;
	n->next = first;
	if (first)
		first->prev = n;
	h->next = n;
	n->prev = h;
	wunlock_tx_hlist(h);
}

/* DEP XXX: Dropping prefetch for now for simplicity */
#define tx_hlist_for_each(pos, head, mode)				\
	for (check_tx_hlist_next(head ,mode),				\
		     pos = (head)->next; pos;				\
	     check_tx_hlist_next(pos, mode), pos = pos->next)


#define tx_hlist_for_each_entry_rcu(tpos, pos, head, member, mode)	\
	for (pos = get_tx_hlist_next(head, mode);			\
	     rcu_dereference(pos) &&					\
		({ tpos = tx_hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = get_tx_hlist_next(pos, mode))


#else 

#define tx_list_head list_head

/* 
 * Make everything fall back to a regular list if we aren't using KSTM
 */
#define TX_LIST_INIT(name) { &(name), &(name) }

#define TX_LIST(name) \
	struct tx_list_head name = TX_LIST_INIT(name)

#define INIT_TX_LIST(list, fn, parent) INIT_LIST_HEAD(list)

#define tx_list_add(new, head) list_add(new, head)
#define tx_list_add_tail(new, head) list_add_tail(new, head)
#define tx_list_move(list, head) list_move(list, head)
#define tx_list_move_tail(list, head) list_move_tail(list, head)
#define tx_list_del(item) list_del(item)
#define tx_list_del_init(item) list_del_init(item)
#define tx_list_empty(list) list_empty(list)
#define tx_list_splice(list, head) list_splice(list, head)
#define tx_list_splice_init(list, head) list_splice_init(list, head)

#define tx_list_first_entry(ptr, type, member) list_entry((ptr)->next, type, member)

#define tx_list_for_each(pos, head, mode) list_for_each(pos, head)
#define tx_list_for_each_safe(pos, n, head, mode) list_for_each_safe(pos, n, head)
#define tx_list_for_each_entry(pos, head, type, member, mode) list_for_each_entry(pos, head, member)
#define tx_list_for_each_entry_safe(pos, n, head, type, member, mode) list_for_each_entry_safe(pos, n, head, member)

#define check_tx_list_next(head, mode) 
#define check_tx_list_prev(head, mode) 

#define tx_hlist_head hlist_head
#define tx_hlist_node hlist_node


#define INIT_TX_HLIST_NODE(h, fn, parent) INIT_HLIST_NODE(h)
#define INIT_TX_HLIST_HEAD(h, fn, parent) INIT_HLIST_HEAD(h)

#define hlist_init_tx(lst) 
#define check_tx_hlist_next(h, mode) 
#define check_tx_hlist_prev(h, mode) 

#define __tx_hlist_del(n) __hlist_del(n)
#define tx_hlist_del_rcu(n) hlist_del_rcu(n)
#define tx_hlist_del_init(n) hlist_del_init(n)
#define tx_hlist_unhashed(h) hlist_unhashed(h)
#define tx_hlist_head_first(h) (h)->first
#define tx_hlist_empty(h) hlist_empty(h)
#define tx_hlist_add_head(n, h) hlist_add_head(n, h)
#define tx_hlist_add_head_rcu(n, h) hlist_add_head_rcu(n, h)
#define tx_hlist_for_each(pos, head, mode) hlist_for_each(pos, head)
#define tx_hlist_for_each_entry_rcu(tpos, pos, head, member, mode)	\
	hlist_for_each_entry_rcu(tpos, pos, head, member)

#define check_list_asymmetric_conflict(head)

#define rlock_tx_hlist(h) 
#define runlock_tx_hlist(h) 

#endif

extern void *tx_cache_get_tx_list_head_void(void*, enum access_mode);
extern struct tx_list_head *tx_cache_get_tx_list_head(struct tx_list_head *);
extern struct tx_list_head *tx_cache_get_tx_list_head_ro(struct tx_list_head *);

extern void *tx_cache_get_tx_hlist_head_void(void*, enum access_mode);
extern struct tx_hlist_head *tx_cache_get_tx_hlist_head(struct tx_hlist_head *);
extern struct tx_hlist_head *tx_cache_get_tx_hlist_head_ro(struct tx_hlist_head *);

/* Do we add other fns to interface? */
#else
#warning "don't include kernel headers in userspace"
#endif /* __KERNEL__ */
#endif
