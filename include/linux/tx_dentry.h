#ifndef _LINUX_TX_DENTRY_H
#define _LINUX_TX_DENTRY_H

#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/transaction.h>
#include <linux/hardirq.h>
#include <linux/tx_list.h>
#include <linux/tx_inodes.h>

struct _dentry * __tx_cache_get_dentry(struct dentry *dentry, enum access_mode mode);
void * tx_cache_get_dentry_void(void *, enum access_mode);
void replace_dentry_notx(struct transactional_object *xobj);

#ifdef CONFIG_TX_KSTM

static inline struct _dentry * _tx_cache_get_dentry(struct dentry *dentry, 
						    enum access_mode mode){
	void *tmp;						
	struct _dentry *rv;
	if((tmp = tx_status_check(dentry, mode, 0)) != NULL){
		if (IS_ERR(tmp)) return tmp;
		rcu_read_lock();
		rv = dentry->d_contents;
		rcu_read_unlock();
		return rv;
	}
	return __tx_cache_get_dentry(dentry, mode);	
}

static inline void dspin_lock_nested(struct dentry *dentry, int subclass){

	struct transaction *winner;
	check_int();

	/* Never lock a dentry in a transaction, except explicitly in tx code */
	if(live_transaction()){
		if(atomic_read(&current->transaction->task_count) > 1){
			spin_lock_nested(&dentry->d_lock, subclass);
			record_tx_lock(&dentry->d_lock, SPIN_LOCK);
		}
		return;
	}

	spin_lock_nested(&dentry->d_lock, subclass);


	// Must kick out transactions with the lock held so
	// that we don't have a race
	while((atomic_read(&tx_count) != 0)
	      && inactive_transaction()
	      && (winner = 
		  check_asymmetric_conflict(&dentry->xobj, ACCESS_RW, 
					    tx_preemptible(1), 0)
		      )){
		
		/* Drop the lock */
		spin_unlock(&dentry->d_lock);
		
		/* Sleep until the winner commits */
		wait_on_tx(winner);
		
		/* Try again */
		spin_lock(&dentry->d_lock);
	}
}


static inline int atomic_dec_and_dlock(struct dentry *dentry){

	int rv;
	check_int();

	if(live_transaction() && atomic_read(&current->transaction->task_count) > 1){
		rv = tx_atomic_dec_and_test(&dentry->d_count);
	} else {
		rv = tx_atomic_dec_and_lock(&dentry->d_count, &dentry->d_lock);
		if(rv && inactive_transaction() && atomic_read(&tx_count))
			check_asymmetric_conflict(&dentry->xobj, ACCESS_RW, 0, 0);
		if(rv)
			record_tx_lock(&dentry->d_lock, SPIN_LOCK);
	}
	return rv;
}

#else
#define dspin_lock_nested(dentry, subclass) spin_lock_nested(&dentry->d_lock, subclass)
#define atomic_dec_and_dlock(dentry) atomic_dec_and_lock(&(dentry)->d_count, &(dentry)->d_lock) 
#endif // CONFIG_TX_KSTM

#define tx_cache_get_dentry(dentry) _tx_cache_get_dentry(dentry, ACCESS_RW)
#define tx_cache_get_dentry_ro(dentry) \
	_tx_cache_get_dentry(dentry, ACCESS_R)


static inline struct _inode *_d_get_inode(const struct _dentry* d, enum access_mode mode){
	
	// Only bother with all this for non-null inodes
	if(!d->d_inode)
		return NULL;

	return _tx_cache_get_inode(d->d_inode, mode, 0);
}

#define d_get_inode(d) _d_get_inode(d, ACCESS_RW)
#define d_get_inode_ro(d) _d_get_inode(d, ACCESS_R)

#define dentry_get_inode(d) d_get_inode(tx_cache_get_dentry(d))
#define dentry_get_inode_ro(d) d_get_inode_ro(tx_cache_get_dentry_ro(d))

#define _dspin_lock(_dentry) dspin_lock(parent(_dentry))
#define _dspin_lock_nested(_dentry, subclass) dspin_lock_nested(parent(_dentry), subclass)
#define _dspin_unlock(_dentry) dspin_unlock(parent(_dentry))

/* DEP: Functions below hoisted from include/linux/fs.h to get proper
 * tx indirection while staying inlined
 */
static inline ino_t parent_ino(struct _dentry *dentry)
{
	ino_t res;
	_dspin_lock(dentry);
	res = dentry_get_inode(dentry->d_parent)->i_ino;
	_dspin_unlock(dentry);
	return res;
}

#endif //_LINUX_TX_DENTRY_H
