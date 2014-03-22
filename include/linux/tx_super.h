#ifndef _LINUX_TX_SUPER_H
#define _LINUX_TX_SUPER_H

#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/transaction.h>
#include <linux/hardirq.h>

#include <linux/tx_inodes.h>

struct _super_block * __tx_cache_get_super_block(struct super_block *sb, enum access_mode mode);
void * tx_cache_get_super_block_void(void *, enum access_mode);
void replace_super_notx(struct transactional_object *xobj);

#ifdef CONFIG_TX_KSTM

static inline struct _super_block * _tx_cache_get_super(struct super_block *sb, 
							enum access_mode mode){
	void *tmp;						
	struct _super_block *rv;
	if((tmp = tx_status_check(sb, mode, 0)) != NULL){
		if (IS_ERR(tmp)) return tmp;
		rcu_read_lock();
		rv = sb->s_contents;
		rcu_read_unlock();
		return rv;
	}
	return __tx_cache_get_super_block(sb, mode);	
}

// If we are in a transaction, assert that the super_block is transactional
static inline void assert_tx_super_block(struct _super_block * _super_block){
#ifdef CONFIG_TX_KSTM_ASSERTIONS
	BUG_ON(!_super_block->shadow);
#endif
}

/* Don't mutex_lock our private super_blocks */
static inline void smutex_lock(struct super_block *super_block){

	struct transaction *winner = NULL;
	check_int();
	if(live_transaction()){
		if(atomic_read(&current->transaction->task_count) > 1){
			mutex_lock(&super_block->s_lock);
			record_tx_lock(&super_block->s_lock, MUTEX);
		}
		return;
	}

	mutex_lock(&super_block->s_lock);

	// Must kick out transactions with the lock held so
	// that we don't have a race
	spin_lock(&sb_lock);

	while((atomic_read(&tx_count) != 0)
	      && inactive_transaction()
	      && (winner = 
		  check_asymmetric_conflict(&super_block->xobj, ACCESS_RW, 
					    tx_preemptible(1), 0)
		      )){
			
		/* Drop the lock */
		spin_unlock(&sb_lock);
		mutex_unlock(&super_block->s_lock);
		
		/* Sleep until the winner commits */
		wait_on_tx(winner);
		
		/* Try again */
		mutex_lock(&super_block->s_lock);
		spin_lock(&sb_lock);
	}
	spin_unlock(&sb_lock);
}

static inline void smutex_lock_nested(struct super_block *super_block, unsigned int subclass){

	check_int();
	if(live_transaction()){
		if(atomic_read(&current->transaction->task_count) > 1){
			mutex_lock_nested(&super_block->s_lock, subclass);
			record_tx_lock(&super_block->s_lock, MUTEX);
		}
		return;
	}

	mutex_lock_nested(&super_block->s_lock, subclass);
	// Must kick out transactions with the lock held so
	// that we don't have a race
	if(inactive_transaction() &&atomic_read(&tx_count)){
		spin_lock(&sb_lock);
		check_asymmetric_conflict(&super_block->xobj, ACCESS_RW, 0, 0);
		spin_unlock(&sb_lock);
	}
}

static inline void smutex_unlock(struct super_block *super_block){

	check_int();
	if(live_transaction()){
		if(atomic_read(&current->transaction->task_count) > 1){
			mutex_unlock(&super_block->s_lock);
			record_tx_unlock(&super_block->s_lock, MUTEX);
		}
		return;
	} else {
		mutex_unlock(&super_block->s_lock);
	}
}

static inline void lock_sb(struct super_block *super_block){

	struct transaction *winner = NULL;
	check_int();
	if(live_transaction()){
		if(atomic_read(&current->transaction->task_count) > 1){
			spin_lock(&sb_lock);
			// Need this b/c it is a global lock
			record_tx_lock(&sb_lock, SPIN_LOCK);
		}
		return;
	}

	spin_lock(&sb_lock);
	// Must kick out transactions with the lock held so
	// that we don't have a race
	while((atomic_read(&tx_count) != 0)
	      && inactive_transaction()
	      && (winner = 
		  check_asymmetric_conflict(&super_block->xobj, ACCESS_RW, 
					    tx_preemptible(1), 0)
		      )){
		
		/* Drop the lock */
		spin_unlock(&sb_lock);
		
		/* Sleep until the winner commits */
		wait_on_tx(winner);
		
		/* Try again */
		spin_lock(&sb_lock);
	}
}

static inline void unlock_sb(struct super_block *super_block){

	check_int();
	if(live_transaction()){
		if(atomic_read(&current->transaction->task_count) > 1){
			spin_unlock(&sb_lock);
			// Need this b/c it is a global lock
			record_tx_unlock(&sb_lock, SPIN_LOCK);
		}
		return;
	} else 
		spin_unlock(&sb_lock);
}



#else
#define smutex_lock(super_block) mutex_lock(&super_block->s_lock)
#define smutex_lock_nested(super_block, subclass) mutex_lock_nested(&super_block->s_lock, subclass)
#define smutex_unlock(super_block) mutex_unlock(&super_block->s_lock)

#define lock_sb(sb) spin_lock(&sb_lock)
#define unlock_sb(sb) spin_unlock(&sb_lock)
#endif

#define tx_cache_get_super(super) _tx_cache_get_super(super, ACCESS_RW)
#define tx_cache_get_super_ro(super) _tx_cache_get_super(super, ACCESS_R)

static inline struct _super_block *_i_get_sb(const struct _inode * _inode, enum access_mode mode){
	
	KSTM_BUG_ON(!_inode->i_sb);
	
	return _tx_cache_get_super(_inode->i_sb, mode);
}

#define i_get_sb(inode) _i_get_sb(inode, ACCESS_RW)
#define i_get_sb_ro(inode) _i_get_sb(inode, ACCESS_R)

#define inode_get_sb(inode) i_get_sb(tx_cache_get_inode(inode))
#define inode_get_sb_ro(inode) i_get_sb(tx_cache_get_inode_ro(inode))


/* DEP: Functions below hoisted from include/linux/fs.h to get proper
 * tx indirection while staying inlined
 */
/*
 * Note that nosuid etc flags are inode-specific: setting some file-system
 * flags just means all the inodes inherit those flags by default. It might be
 * possible to override it selectively if you really wanted to with some
 * ioctl() that is not currently implemented.
 *
 * Exception: MS_RDONLY is always applied to the entire file system.
 *
 * Unfortunately, it is possible to change a filesystems flags with it mounted
 * with files in use.  This means that all of the inodes will not have their
 * i_flags updated.  Hence, i_flags no longer inherit the superblock mount
 * flags, so these have to be checked separately. -- rmk@arm.uk.linux.org
 */
#define __IS_FLG(inode,flg) (i_get_sb(inode)->s_flags & (flg))

#define IS_RDONLY(inode) (i_get_sb(inode)->s_flags & MS_RDONLY)
#define IS_SYNC(inode)		(__IS_FLG(inode, MS_SYNCHRONOUS) || \
					((inode)->i_flags & S_SYNC))
#define IS_DIRSYNC(inode)	(__IS_FLG(inode, MS_SYNCHRONOUS|MS_DIRSYNC) || \
					((inode)->i_flags & (S_SYNC|S_DIRSYNC)))
#define IS_MANDLOCK(inode)	__IS_FLG(inode, MS_MANDLOCK)
#define IS_NOATIME(inode)   __IS_FLG(inode, MS_RDONLY|MS_NOATIME)

#define IS_NOQUOTA(inode)	((inode)->i_flags & S_NOQUOTA)
#define IS_APPEND(inode)	((inode)->i_flags & S_APPEND)
#define IS_IMMUTABLE(inode)	((inode)->i_flags & S_IMMUTABLE)
#define IS_POSIXACL(inode)	__IS_FLG(inode, MS_POSIXACL)

#define IS_DEADDIR(inode)	((inode)->i_flags & S_DEAD)
#define IS_NOCMTIME(inode)	((inode)->i_flags & S_NOCMTIME)
#define IS_SWAPFILE(inode)	((inode)->i_flags & S_SWAPFILE)
#define IS_PRIVATE(inode)	((inode)->i_flags & S_PRIVATE)

/*
 * Candidates for mandatory locking have the setgid bit set
 * but no group execute bit -  an otherwise meaningless combination.
 */
#define MANDATORY_LOCK(inode) \
	(IS_MANDLOCK(inode) && ((inode)->i_mode & (S_ISGID | S_IXGRP)) == S_ISGID)

static inline int locks_verify_locked(struct _inode *inode)
{
	if (MANDATORY_LOCK(inode))
		return locks_mandatory_locked(parent(inode));
	return 0;
}

static inline int locks_verify_truncate(struct inode *inode,
				    struct file *filp,
				    loff_t size)
{
	struct _inode * _inode = tx_cache_get_inode(inode);
	if (inode->i_flock && MANDATORY_LOCK(_inode))
		return locks_mandatory_area(
			FLOCK_VERIFY_WRITE, inode, filp,
			size < _inode->i_size ? size : _inode->i_size,
			(size < _inode->i_size ? _inode->i_size - size
			 : size - _inode->i_size)
		);
	return 0;
}

#endif //_LINUX_TX_SUPER_H
