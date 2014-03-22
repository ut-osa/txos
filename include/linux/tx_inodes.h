#ifndef _LINUX_TX_INODE_H
#define _LINUX_TX_INODE_H

#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/transaction.h>
#include <linux/hardirq.h>

struct _inode * __tx_cache_get_inode(struct inode * inode, enum access_mode mode, 
				     int noabort);
void * tx_cache_get_inode_void(void * inode, enum access_mode);

void replace_inode_notx(struct transactional_object *xobj);

// If we are in a transaction, assert that the inode is transactional
static inline void assert_tx_inode(struct _inode * inode){
#ifdef CONFIG_TX_KSTM_ASSERTIONS
	BUG_ON(!inode->shadow);
#endif
}

#ifdef CONFIG_TX_KSTM

static inline struct _inode * _tx_cache_get_inode(struct inode *inode, 
						  enum access_mode mode, int noabort){
	void *tmp;						
	struct _inode *rv;
	if((tmp = tx_status_check(inode, mode, noabort)) != NULL){
		if (IS_ERR(tmp)) return tmp;
		rcu_read_lock();
		rv = inode->i_contents;
		rcu_read_unlock();
		return rv;
	}
	return __tx_cache_get_inode(inode, mode, noabort);	
}





/* Pointer acrobatics to get the offset of the inode in the bigger
 * struct
 */
static inline struct _inode * get_inode_from_parent(struct _inode * inode, 
						   void * shadow_parent) {
	struct _inode *shadow_inode =
		(struct _inode *) (shadow_parent - 
				  (inode->i_parent - (void *) inode));
	return shadow_inode;
}

/* Don't mutex_lock our private inodes */
static inline void imutex_lock(struct inode *inode){

	struct transaction *winner = NULL;
	check_int();
	if(live_transaction()){
		if(atomic_read(&current->transaction->task_count) > 1){
			mutex_lock(&inode->i_mutex);
			record_tx_lock(&inode->i_mutex, MUTEX);
		}
		return;
	} else {
		mutex_lock(&inode->i_mutex);

		// Must kick out transactions with the lock held so
		// that we don't have a race.  But do it fairly.
		while((atomic_read(&tx_count) != 0)
		      && inactive_transaction()
		      && (winner = 
			  check_asymmetric_conflict(&inode->xobj, ACCESS_RW, 
						    tx_preemptible(1), 0)
			      )){
			
			/* Drop the lock */
			mutex_unlock(&inode->i_mutex);

			/* Sleep until the winner commits */
			wait_on_tx(winner);

			/* Try again */
			mutex_lock(&inode->i_mutex);
		}
	}
}

static inline int imutex_trylock(struct inode *inode){

	struct transaction *winner = NULL;
	check_int();
	/* Never lock an inode in a transaction, except explicitly in tx code */
	if(live_transaction()){
		if(atomic_read(&current->transaction->task_count) > 1){
			int rv = mutex_trylock(&inode->i_mutex);
			if(rv)
				record_tx_lock(&inode->i_mutex, MUTEX);
			return rv;
		}
		return 1;
	} 

	if(mutex_trylock(&inode->i_mutex)){

		// Must kick out transactions with the lock held so
		// that we don't have a race.  But do it fairly.
		while((atomic_read(&tx_count) != 0)
		      && inactive_transaction()
		      && (winner = 
			  check_asymmetric_conflict(&inode->xobj, ACCESS_RW, 
						    tx_preemptible(1), 0)
			      )){
		
			/* Drop the lock */
			mutex_unlock(&inode->i_mutex);
		
			/* Sleep until the winner commits */
			wait_on_tx(winner);
			
			/* Try again */
			mutex_lock(&inode->i_mutex);
		}
		return 1;
	}
	return 0;
}

static inline void __imutex_lock_nested(struct inode *inode, unsigned int subclass, enum access_mode mode){

	struct transaction *winner;
	check_int();
	if(live_transaction()){
		if(atomic_read(&current->transaction->task_count) > 1){
			mutex_lock_nested(&inode->i_mutex, subclass);
			record_tx_lock(&inode->i_mutex, MUTEX);
		}
		return;
	} else {
		mutex_lock_nested(&inode->i_mutex, subclass);

		// Must kick out transactions with the lock held so
		// that we don't have a race.  But do it fairly.
		while((atomic_read(&tx_count) != 0)
		      && inactive_transaction()
		      && (winner = 
			  check_asymmetric_conflict(&inode->xobj, mode, 
						    tx_preemptible(1), 0)
			      )){
			
			/* Drop the lock */
			mutex_unlock(&inode->i_mutex);

			/* Sleep until the winner commits */
			wait_on_tx(winner);

			/* Try again */
			mutex_lock_nested(&inode->i_mutex, subclass);
		}
	}
}

#define upgrade_imutex_write(inode) check_asymmetric_conflict(&inode->xobj, ACCESS_RW, 0, 0)

static inline void imutex_unlock(struct inode *inode){

	check_int();
	if(live_transaction()){
		if(atomic_read(&current->transaction->task_count) > 1){
			mutex_unlock(&inode->i_mutex);
			record_tx_unlock(&inode->i_mutex, MUTEX);
		}
		return;
	} else {
		mutex_unlock(&inode->i_mutex);
	}
}

static inline void ispin_lock(struct inode *inode){

	struct transaction *winner = NULL;
	check_int();
	if(live_transaction()){
		if(atomic_read(&current->transaction->task_count) > 1){
			spin_lock(&inode->i_lock);
			record_tx_lock(&inode->i_lock, SPIN_LOCK);
		}
		return;
	} else {
		spin_lock(&inode->i_lock);

		// Must kick out transactions with the lock held so
		// that we don't have a race
		while((atomic_read(&tx_count) != 0)
		      && inactive_transaction()
		      && (winner = 
			  check_asymmetric_conflict(&inode->xobj, ACCESS_RW, 
						    tx_preemptible(1), 0)
			      )){
			
			/* Drop the lock */
			spin_unlock(&inode->i_lock);

			/* Sleep until the winner commits */
			wait_on_tx(winner);

			/* Try again */
			spin_lock(&inode->i_lock);
		}
	}
}

static inline void ispin_unlock(struct inode *inode){

	check_int();
	if(live_transaction()){
		if(atomic_read(&current->transaction->task_count) > 1){
			spin_unlock(&inode->i_lock);
			record_tx_unlock(&inode->i_lock, SPIN_LOCK);
		}
		return;
	} else {
		spin_unlock(&inode->i_lock);
	}
}

#define imutex_lock_nested(inode, subclass) __imutex_lock_nested(inode, subclass, ACCESS_RW)
#define imutex_lock_nested_ro(inode, subclass) __imutex_lock_nested(inode, subclass, ACCESS_R)

#else
#define imutex_lock(inode) mutex_lock(&inode->i_mutex)
#define imutex_lock_nested(inode, subclass) mutex_lock_nested(&inode->i_mutex, subclass)
#define imutex_lock_nested_ro(inode, subclass) mutex_lock_nested(&inode->i_mutex, subclass)
#define imutex_unlock(inode) mutex_unlock(&inode->i_mutex)

#define ispin_lock(inode) spin_lock(&inode->i_lock)
#define ispin_unlock(inode) spin_unlock(&inode->i_lock)

#define upgrade_imutex_write(inode) 

#endif


#define tx_cache_get_inode(inode) _tx_cache_get_inode(inode, ACCESS_RW, 0)
#define tx_cache_get_inode_ro(inode) \
	_tx_cache_get_inode(inode, ACCESS_R, 0)
#define tx_cache_get_inode_ro_noabort(inode) \
	_tx_cache_get_inode(inode, ACCESS_R, 1)

#define _imutex_lock(inode) imutex_lock(parent(inode))
#define _imutex_lock_nested(inode, subclass) imutex_lock_nested(parent(inode), subclass)
#define _imutex_lock_nested_ro(inode, subclass) imutex_lock_nested_ro(parent(inode), subclass)
#define _imutex_unlock(inode) imutex_unlock(parent(inode))

#define _ispin_lock(inode) ispin_lock(parent(inode))
#define _ispin_unlock(inode) ispin_unlock(parent(inode))

/* DEP: Functions below hoisted from include/linux/fs.h to get proper
 * tx indirection while staying inlined
 */
static inline struct inode *iget(struct super_block *sb, unsigned long ino)
{
	struct inode *inode = iget_locked(sb, ino);
	
	if (inode && (inode->i_state & I_NEW)) {
		struct _inode *_inode;
		rcu_read_lock();
		_inode = inode->i_contents;
		rcu_read_unlock();
		sb->s_op->read_inode(_inode);
		unlock_new_inode(inode);
	}

	return inode;
}

/* Mark an inode has having transactional read/writes by changing to a
 * different unlock function */
int lock_inode_tty_write(struct txobj_thread_list_node *xnode, int blocking);
int unlock_inode_tty_write(struct txobj_thread_list_node *xnode, int blocking);
int unlock_inode_data_rw(struct txobj_thread_list_node *xnode, int blocking);
int unlock_inode_data_r(struct txobj_thread_list_node *xnode, int blocking);
static inline void mark_inode_data_rw(struct inode *inode) {
	txobj_thread_list_node_t *list_node = workset_has_object(&inode->xobj);
	BUG_ON(!list_node);
#ifdef CONFIG_TX_KSTM_DORDER
	if(list_empty(&list_node->data_writer_list)) {
#endif
		list_node->unlock = unlock_inode_data_rw;
#ifdef CONFIG_TX_KSTM_DORDER
		list_add_tail(&list_node->data_writer_list,
				&current->transaction->data_writer_list);
	}
#endif
}

static inline void mark_inode_data_r(struct inode *inode) {
	txobj_thread_list_node_t *list_node = workset_has_object(&inode->xobj);
	BUG_ON(!list_node);
	if(list_node->unlock != unlock_inode_data_rw)
		list_node->unlock = unlock_inode_data_r;
}

static inline int inode_has_datarw(struct inode *inode) {
	txobj_thread_list_node_t *list_node = workset_has_object(&inode->xobj);
	BUG_ON(!list_node);
	return list_node->unlock == unlock_inode_data_rw ||
		list_node->unlock == unlock_inode_data_r;
}

#endif //_LINUX_TX_INODE_H
