/*
 * fs/dcache.c
 *
 * Complete reimplementation
 * (C) 1997 Thomas Schoebel-Theuer,
 * with heavy changes by Linus Torvalds
 */

/*
 * Notes on the allocation strategy:
 *
 * The dcache is a master of the icache - whenever a dcache entry
 * exists, the inode will always exist. "iput()" is done either when
 * the dcache entry is deleted or garbage collected.
 */

#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/cache.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <asm/uaccess.h>
#include <linux/security.h>
#include <linux/seqlock.h>
#include <linux/swap.h>
#include <linux/bootmem.h>
#include "internal.h"

#include <linux/tx_inodes.h>
#include <linux/tx_dentry.h>
#include <linux/tx_list.h>
#include <linux/tx_super.h>
#include <linux/debugtx.h>

/* DEP: 3/5/09 - double the cache pressure to roughly account for
 * _inode and _dentry objects.  Otherwise the kernel may not be
 * aggressive enough about garbage collecting them, which can get it
 * in a bad spot.  I pulled this number from a combination of
 * intuition and my butt - it may need to be higher.
 */
int sysctl_vfs_cache_pressure __read_mostly = 200;
EXPORT_SYMBOL_GPL(sysctl_vfs_cache_pressure);

 __cacheline_aligned_in_smp DEFINE_SPINLOCK(dcache_lock);
static __cacheline_aligned_in_smp DEFINE_SEQLOCK(rename_lock);

EXPORT_SYMBOL(dcache_lock);

static struct kmem_cache *dentry_cache __read_mostly;
struct kmem_cache *_dentry_cache __read_mostly;

#define DNAME_INLINE_LEN (sizeof(struct _dentry)-offsetof(struct _dentry,d_iname))

/*
 * This is the single most critical data structure when it comes
 * to the dcache: the hashtable for lookups. Somebody should try
 * to make this good - I've just made it work.
 *
 * This hash-function tries to avoid losing too many bits of hash
 * information, yet avoid using a prime hash-size or similar.
 */
#define D_HASHBITS     d_hash_shift
#define D_HASHMASK     d_hash_mask

static unsigned int d_hash_mask __read_mostly;
static unsigned int d_hash_shift __read_mostly;
static struct tx_list2_head *dentry_hashtable __read_mostly;
static LIST_HEAD(dentry_unused);

/* Statistics gathering. */
struct dentry_stat_t dentry_stat = {
	.age_limit = 45,
};

static void __d_free(struct dentry *dentry)
{
	struct _dentry *_dentry = dentry->d_contents;
	if (dname_external(_dentry))
		kfree(_dentry->d_name.name);
	kmem_cache_free(_dentry_cache, _dentry); 
	kmem_cache_free(dentry_cache, dentry); 
}

static void d_callback(struct rcu_head *head)
{
	struct dentry * dentry = container_of(head, struct dentry, d_rcu);
	__d_free(dentry);
}

/*
 * no dcache_lock, please.  The caller must decrement dentry_stat.nr_dentry
 * inside dcache_lock.
 */
static void d_free(struct dentry *dentry)
{
	struct _dentry *_dentry = dentry->d_contents;
	KSTM_BUG_ON(live_transaction());
	if (_dentry->d_op && _dentry->d_op->d_release)
		_dentry->d_op->d_release(dentry);
	/* if dentry was never inserted into hash, immediate free is OK */
	/* This doesn't do what you think it does in tx_list2, and is
	 * unsafe.  To do this right, we'd need to poison the
	 * entries. 
	 */
	/*
	if (tx_list2_unreferenced(&dentry->d_hash) && !live_transaction())
		__d_free(dentry);
	else
	*/
	call_rcu(&dentry->d_rcu, d_callback);
}

/*
 * Release the dentry's inode, using the filesystem
 * d_iput() operation if defined.
 * Called with dcache_lock and per dentry lock held, drops both.
 */
static void dentry_iput(struct _dentry * dentry)
{
	struct inode *inode = dentry->d_inode;
	/* I don't think this should be called in a live tx */
	KSTM_BUG_ON(live_transaction());
	if (inode) {
		dentry->d_inode = NULL;
		tx_list2_del_init(&parent(dentry)->d_alias);
		_dspin_unlock(dentry);
		spin_unlock(&dcache_lock);
		if (!tx_cache_get_inode(inode)->i_nlink)
			fsnotify_inoderemove(inode);
		if (dentry->d_op && dentry->d_op->d_iput)
			dentry->d_op->d_iput(parent(dentry), inode);
		else
			iput(inode);
	} else {
		_dspin_unlock(dentry);
		spin_unlock(&dcache_lock);
	}
}

/**
 * d_kill - kill dentry and return parent
 * @dentry: dentry to kill
 *
 * Called with dcache_lock and d_lock, releases both.  The dentry must
 * already be unhashed and removed from the LRU.
 *
 * If this is the root of the dentry tree, return NULL.
 */
static struct dentry *d_kill(struct _dentry *dentry)
{
	struct dentry *parent, *_parent;

	_parent = parent(dentry);
	tx_list2_del(&_parent->d_child);
	dentry_stat.nr_dentry--;	/* For d_free, below */
	/*drops the locks, at that point nobody can reach this dentry */
	dentry_iput(dentry);
	parent = dentry->d_parent;
	d_free(parent(dentry));
	return _parent == parent ? NULL : parent;
}

/* 
 * This is dput
 *
 * This is complicated by the fact that we do not want to put
 * dentries that are no longer on any hash chain on the unused
 * list: we'd much rather just get rid of them immediately.
 *
 * However, that implies that we have to traverse the dentry
 * tree upwards to the parents which might _also_ now be
 * scheduled for deletion (it may have been only waiting for
 * its last child to go away).
 *
 * This tail recursion is done by hand as we don't want to depend
 * on the compiler to always get this right (gcc generally doesn't).
 * Real recursion would eat up our stack space.
 */

/*
 * dput - release a dentry
 * @dentry: dentry to release 
 *
 * Release a dentry. This will drop the usage count and if appropriate
 * call the dentry unlink method as well as removing it from the queues and
 * releasing its resources. If the parent dentries were scheduled for release
 * they too may now get deleted.
 *
 * no dcache lock, please.
 * DEP: Add has_dcache_lock param if committing deleted dentry
 */

void dput_core(struct dentry *dentry){
	struct _dentry *_dentry;
	if (!dentry)
		return;

	/* We can drop a reference in a tx, but _never_ drop the last one.
	 */
	KSTM_BUG_ON(live_transaction()
		    && tx_atomic_read(&dentry->d_count) == 1 
		    && workset_has_object(&dentry->xobj));

repeat:
	if (atomic_read(&dentry->d_count) == 1)
		might_sleep();

	if (!tx_atomic_dec_and_lock(&dentry->d_count, &dcache_lock))
		return;

	dspin_lock(dentry);
	if (atomic_read(&dentry->d_count)) {
		dspin_unlock(dentry);
		spin_unlock(&dcache_lock);
		return;
	}

	/*
	 * AV: ->d_delete() is _NOT_ allowed to block now.
	 */
	_dentry = tx_cache_get_dentry(dentry);
	if (_dentry->d_op && _dentry->d_op->d_delete) {
		if (_dentry->d_op->d_delete(_dentry))
			goto unhash_it;
	}
	/* Unreachable? Get rid of it */
 	if (d_unhashed(_dentry))
		goto kill_it;
  	if (list_empty(&dentry->d_lru)) {
  		_dentry->d_flags |= DCACHE_REFERENCED;
  		list_add(&dentry->d_lru, &dentry_unused);
  		dentry_stat.nr_unused++;
  	}
 	dspin_unlock(dentry);
	spin_unlock(&dcache_lock);
	return;

unhash_it:
	__d_drop(_dentry);
kill_it:
	/* If dentry was on d_lru list
	 * delete it from there
	 */
	if (!list_empty(&dentry->d_lru)) {
		list_del(&dentry->d_lru);
		dentry_stat.nr_unused--;
	}
	dentry = d_kill(_dentry);
	if (dentry)
		goto repeat;
}

/**
 * d_invalidate - invalidate a dentry
 * @dentry: dentry to invalidate
 *
 * Try to invalidate the dentry if it turns out to be
 * possible. If there are other dentries that can be
 * reached through this one we can't delete it and we
 * return -EBUSY. On success we return 0.
 *
 * no dcache lock.
 */
 
int d_invalidate(struct _dentry * dentry)
{
	/*
	 * If it's already been dropped, return OK.
	 */
	spin_lock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);
	if (d_unhashed(dentry)) {
		spin_unlock(&dcache_lock);
		record_tx_unlock(&dcache_lock, SPIN_LOCK);
		return 0;
	}
	/*
	 * Check whether to do a partial shrink_dcache
	 * to get rid of unused child entries.
	 */
	if (!tx_list2_empty(&parent(dentry)->d_subdirs)) {
		spin_unlock(&dcache_lock);
		record_tx_unlock(&dcache_lock, SPIN_LOCK);
		shrink_dcache_parent(parent(dentry));
		spin_lock(&dcache_lock);
		record_tx_lock(&dcache_lock, SPIN_LOCK);
	}

	/*
	 * Somebody else still using it?
	 *
	 * If it's a directory, we can't drop it
	 * for fear of somebody re-populating it
	 * with children (even though dropping it
	 * would make it unreachable from the root,
	 * we might still populate it if it was a
	 * working directory or similar).
	 */
	_dspin_lock(dentry);
	if (tx_atomic_read(&parent(dentry)->d_count) > 1) {
		if (dentry->d_inode && S_ISDIR(d_get_inode(dentry)->i_mode)) {
			_dspin_unlock(dentry);
			spin_unlock(&dcache_lock);
			record_tx_unlock(&dcache_lock, SPIN_LOCK);
			return -EBUSY;
		}
	}

	__d_drop(dentry);
	_dspin_unlock(dentry);
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);
	return 0;
}

/* This should be called _only_ with dcache_lock held */

static inline struct dentry * __dget_locked(struct dentry *dentry)
{
	tx_atomic_inc(&dentry->d_count);
	if (!list_empty(&dentry->d_lru)) {
		dentry_stat.nr_unused--;
		list_del_init(&dentry->d_lru);
	}
	return dentry;
}

struct dentry * dget_locked(struct dentry *dentry)
{
	return __dget_locked(dentry);
}

/**
 * d_find_alias - grab a hashed alias of inode
 * @inode: inode in question
 * @want_discon:  flag, used by d_splice_alias, to request
 *          that only a DISCONNECTED alias be returned.
 *
 * If inode has a hashed alias, or is a directory and has any alias,
 * acquire the reference to alias and return it. Otherwise return NULL.
 * Notice that if inode is a directory there can be only one alias and
 * it can be unhashed only if it has no children, or if it is the root
 * of a filesystem.
 *
 * If the inode has an IS_ROOT, DCACHE_DISCONNECTED alias, then prefer
 * any other hashed alias over that one unless @want_discon is set,
 * in which case only return an IS_ROOT, DCACHE_DISCONNECTED alias.
 */

static struct _dentry * __d_find_alias(struct _inode *inode, int want_discon)
{
	struct dentry *alias;
	struct _dentry *_alias, *discon_alias = NULL;
	struct tx_list2_iterator iter;

	tx_list2_get_iterator(&iter, &parent(inode)->i_dentry);
	while (tx_list2_iter_next(&iter)){

		alias = tx_list2_iter_entry(&iter, struct dentry, d_alias);
		_alias = tx_cache_get_dentry_ro(alias);
 		if (S_ISDIR(inode->i_mode) || !d_unhashed(_alias)) {
			if (IS_ROOT(_alias) &&
			    (_alias->d_flags & DCACHE_DISCONNECTED))
				discon_alias = _alias;
			else if (!want_discon) {
				__dget_locked(alias);
				tx_list2_put_iterator(&iter);
				return _alias;
			}
		}
	}
	tx_list2_put_iterator(&iter);
	if (discon_alias)
		__dget_locked(parent(discon_alias));
	return discon_alias;
}

struct _dentry * d_find_alias(struct _inode *inode)
{
	struct _dentry *de = NULL;

	if (!tx_list2_empty(&parent(inode)->i_dentry)) {
		spin_lock(&dcache_lock);
		record_tx_lock(&dcache_lock, SPIN_LOCK);
		de = __d_find_alias(inode, 0);
		spin_unlock(&dcache_lock);
		record_tx_unlock(&dcache_lock, SPIN_LOCK);
	}
	return de;
}

/*
 *	Try to kill dentries associated with this inode.
 * WARNING: you must own a reference to inode.
 */
void d_prune_aliases(struct _inode *inode)
{
	struct dentry *dentry;
	struct _dentry *_dentry;
	struct tx_list2_iterator iter;
	
restart:
	spin_lock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);
	tx_list2_get_iterator(&iter, &parent(inode)->i_dentry);
	while(tx_list2_iter_next(&iter)){
		dentry = tx_list2_iter_entry(&iter, struct dentry, d_alias);
		_dentry = tx_cache_get_dentry_ro(dentry);
		dspin_lock(dentry);
		if (!tx_atomic_read(&dentry->d_count)) {
			__dget_locked(dentry);
			__d_drop(_dentry);
			dspin_unlock(dentry);
			spin_unlock(&dcache_lock);
			record_tx_unlock(&dcache_lock, SPIN_LOCK);
			tx_list2_put_iterator(&iter);
			dput(dentry);
			goto restart;
		}
		dspin_unlock(dentry);
	}
	tx_list2_put_iterator(&iter);
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);
}

/*
 * Throw away a dentry - free the inode, dput the parent.  This requires that
 * the LRU list has already been removed.
 *
 * If prune_parents is true, try to prune ancestors as well.
 *
 * Called with dcache_lock, drops it and then regains.
 * Called with dentry->d_lock held, drops it.
 */
static void prune_one_dentry(struct _dentry * dentry, int prune_parents)
{
	__d_drop(dentry);
	dentry = tx_cache_get_dentry(d_kill(dentry));
	if (!prune_parents) {
		dput(parent(dentry));
		spin_lock(&dcache_lock);
		record_tx_lock(&dcache_lock, SPIN_LOCK);
		return;
	}

	/*
	 * Prune ancestors.  Locking is simpler than in dput(),
	 * because dcache_lock needs to be taken anyway.
	 */
	spin_lock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);
	while (dentry) {
		if (!tx_atomic_dec_and_lock(&parent(dentry)->d_count, &parent(dentry)->d_lock))
			return;

		if (dentry->d_op && dentry->d_op->d_delete)
			dentry->d_op->d_delete(dentry);
		if (!list_empty(&parent(dentry)->d_lru)) {
			list_del(&parent(dentry)->d_lru);
			dentry_stat.nr_unused--;
		}
		__d_drop(dentry);
		dentry = tx_cache_get_dentry(d_kill(dentry));
		spin_lock(&dcache_lock);
		record_tx_lock(&dcache_lock, SPIN_LOCK);
	}
}

/**
 * prune_dcache - shrink the dcache
 * @count: number of entries to try and free
 * @sb: if given, ignore dentries for other superblocks
 *         which are being unmounted.
 * @prune_parents: if true, try to prune ancestors as well in one go
 *
 * Shrink the dcache. This is done when we need
 * more memory, or simply when we need to unmount
 * something (at which point we need to unuse
 * all dentries).
 *
 * This function may fail to free any resources if
 * all the dentries are in use.
 */
 
static void prune_dcache(int count, struct super_block *sb, int prune_parents)
{
	BUG_ON(live_transaction());
	spin_lock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);
	for (; count ; count--) {
		struct dentry *dentry;
		struct _dentry *_dentry;
		struct list_head *tmp;
		struct rw_semaphore *s_umount;

		cond_resched_lock(&dcache_lock);

		tmp = dentry_unused.prev;
		if (sb) {
			/* Try to find a dentry for this sb, but don't try
			 * too hard, if they aren't near the tail they will
			 * be moved down again soon
			 */
			int skip = count;
			while (skip && tmp != &dentry_unused &&
			       list_entry(tmp, struct dentry, d_lru)->d_sb != sb) {
				skip--;
				tmp = tmp->prev;
			}
		}
		if (tmp == &dentry_unused)
			break;
		list_del_init(tmp);
		prefetch(dentry_unused.prev);
 		dentry_stat.nr_unused--;
		dentry = list_entry(tmp, struct dentry, d_lru);
		_dentry = tx_cache_get_dentry(dentry);

		/* Don't do conflict detection until we do something serious */
 		spin_lock(&dentry->d_lock);

		/*
		 * We found an inuse dentry which was not removed from
		 * dentry_unused because of laziness during lookup.  Do not free
		 * it - just keep it off the dentry_unused list.
		 */
 		if (atomic_read(&dentry->d_count)) {
 			spin_unlock(&dentry->d_lock);
			continue;
		}

		/* If the dentry was recently referenced, don't free it. */
		if (_dentry->d_flags & DCACHE_REFERENCED) {
			/* only set in dput, post-tx */
			_dentry->d_flags &= ~DCACHE_REFERENCED;
 			list_add(&dentry->d_lru, &dentry_unused);
 			dentry_stat.nr_unused++;
 			spin_unlock(&dentry->d_lock);
			continue;
		}

		/*
		 * If the dentry is not DCACHED_REFERENCED, it is time
		 * to remove it from the dcache, provided the super block is
		 * NULL (which means we are trying to reclaim memory)
		 * or this dentry belongs to the same super block that
		 * we want to shrink.
		 */
		/*
		 * If this dentry is for "my" filesystem, then I can prune it
		 * without taking the s_umount lock (I already hold it).
		 */
		if (sb && dentry->d_sb == sb) {
			/* DEP 4/20/09: Also, try to make kswapd play nicer with tx */
			if((atomic_read(&tx_count) == 0)
#ifndef CONFIG_DISABLE_LIST2

			   || !check_asymmetric_conflict(&(parent(_dentry)->d_child.entry.parent->xobj), ACCESS_RW, 
							1, 1)
#endif
				){
			  prune_one_dentry(_dentry, prune_parents);
			  continue;
			}
		}
		/*
		 * ...otherwise we need to be sure this filesystem isn't being
		 * unmounted, otherwise we could race with
		 * generic_shutdown_super(), and end up holding a reference to
		 * an inode while the filesystem is unmounted.
		 * So we try to get s_umount, and make sure s_root isn't NULL.
		 * (Take a local copy of s_umount to avoid a use-after-free of
		 * `dentry').
		 */
		s_umount = &dentry->d_sb->s_umount;
		if (down_read_trylock(s_umount)) {
			/* DEP 4/20/09: Also, try to make kswapd play nicer with tx */
			if((atomic_read(&tx_count) == 0)
#ifndef CONFIG_DISABLE_LIST2
			   || !check_asymmetric_conflict(&(parent(_dentry)->d_child.entry.parent->xobj), ACCESS_RW, 
							 1, 1)
#endif
				){
			  if (dentry->d_sb->s_root != NULL) {
			    prune_one_dentry(_dentry, prune_parents);
			    up_read(s_umount);
			    continue;
			  }
			}
			up_read(s_umount);
		}
		spin_unlock(&dentry->d_lock);
		/*
		 * Insert dentry at the head of the list as inserting at the
		 * tail leads to a cycle.
		 */
 		list_add(&dentry->d_lru, &dentry_unused);
		dentry_stat.nr_unused++;
	}
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);
}

/*
 * Shrink the dcache for the specified super block.
 * This allows us to unmount a device without disturbing
 * the dcache for the other devices.
 *
 * This implementation makes just two traversals of the
 * unused list.  On the first pass we move the selected
 * dentries to the most recent end, and on the second
 * pass we free them.  The second pass must restart after
 * each dput(), but since the target dentries are all at
 * the end, it's really just a single traversal.
 */

/**
 * shrink_dcache_sb - shrink dcache for a superblock
 * @sb: superblock
 *
 * Shrink the dcache for the specified super block. This
 * is used to free the dcache before unmounting a file
 * system
 */

void shrink_dcache_sb(struct super_block * sb)
{
	struct list_head *tmp, *next;
	struct dentry *dentry;
	BUG_ON(live_transaction());

	/*
	 * Pass one ... move the dentries for the specified
	 * superblock to the most recent end of the unused list.
	 */
	spin_lock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);
	list_for_each_safe(tmp, next, &dentry_unused) {
		dentry = list_entry(tmp, struct dentry, d_lru);
		if (dentry->d_sb != sb)
			continue;
		list_move(tmp, &dentry_unused);
	}

	/*
	 * Pass two ... free the dentries for this superblock.
	 */
repeat:
	list_for_each_safe(tmp, next, &dentry_unused) {
		dentry = list_entry(tmp, struct dentry, d_lru);
		if (dentry->d_sb != sb)
			continue;
		dentry_stat.nr_unused--;
		list_del_init(tmp);
		dspin_lock(dentry);
		if (atomic_read(&dentry->d_count)) {
			dspin_unlock(dentry);
			continue;
		}
		prune_one_dentry(tx_cache_get_dentry(dentry), 1);
		cond_resched_lock(&dcache_lock);
		goto repeat;
	}
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);
}

/*
 * destroy a single subtree of dentries for unmount
 * - see the comments on shrink_dcache_for_umount() for a description of the
 *   locking
 */
static void shrink_dcache_for_umount_subtree(struct dentry *dentry)
{
	struct dentry *parent;
	unsigned detached = 0;
	struct _dentry *_dentry = tx_cache_get_dentry(dentry);

	BUG_ON(live_transaction());
	BUG_ON(!IS_ROOT(_dentry));


	/* detach this root from the system */
	spin_lock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);
	if (!list_empty(&dentry->d_lru)) {
		dentry_stat.nr_unused--;
		list_del_init(&dentry->d_lru);
	}
	__d_drop(_dentry);
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);

	for (;;) {

		/* descend to the first leaf in the current subtree */
		while (!tx_list2_empty(&dentry->d_subdirs)) {
			struct dentry *loop;

			struct tx_list2_iterator iter;
		
			/* this is a branch with children - detach all of them
			 * from the system in one go */
			spin_lock(&dcache_lock);
			record_tx_lock(&dcache_lock, SPIN_LOCK);

			tx_list2_get_iterator(&iter, &dentry->d_subdirs);			
			while(tx_list2_iter_next(&iter)){
				loop = tx_list2_iter_entry(&iter, struct dentry, d_child);
				if (!list_empty(&loop->d_lru)) {
					dentry_stat.nr_unused--;
					list_del_init(&loop->d_lru);
				}

				__d_drop(tx_cache_get_dentry(loop));
				cond_resched_lock(&dcache_lock);
			}
			/* move to the first child */
			dentry = tx_list2_first_entry(&dentry->d_subdirs, struct dentry, d_child);
			tx_list2_put_iterator(&iter);

			spin_unlock(&dcache_lock);
			record_tx_unlock(&dcache_lock, SPIN_LOCK);

			_dentry = tx_cache_get_dentry(dentry);
		}

		/* consume the dentries from this leaf up through its parents
		 * until we find one with children or run out altogether */
		do {
			struct inode *inode;

			if (atomic_read(&dentry->d_count) != 0) {
				printk(KERN_ERR
				       "BUG: Dentry %p{i=%lx,n=%s}"
				       " still in use (%d)"
				       " [unmount of %s %s]\n",
				       dentry,
				       _dentry->d_inode ?
				       _dentry->d_inode->i_contents->i_ino : 0UL,
				       _dentry->d_name.name,
				       atomic_read(&dentry->d_count),
				       dentry->d_sb->s_type->name,
				       dentry->d_sb->s_id);
				BUG();
			}

			parent = _dentry->d_parent;
			if (parent == dentry)
				parent = NULL;
			else
				tx_atomic_dec(&parent->d_count);

			tx_list2_del(&dentry->d_child);
			detached++;

			inode = _dentry->d_inode;
			if (inode) {
				_dentry->d_inode = NULL;
				tx_list2_del_init(&dentry->d_alias);
				if (_dentry->d_op && _dentry->d_op->d_iput)
					_dentry->d_op->d_iput(dentry, inode);
				else
					iput(inode);
			}

			d_free(dentry);

			/* finished when we fall off the top of the tree,
			 * otherwise we ascend to the parent and move to the
			 * next sibling if there is one */
			if (!parent)
				goto out;

			dentry = parent;

		} while (tx_list2_empty(&dentry->d_subdirs));

		LOCK_LIST(&dentry->d_subdirs);
		check_list2_asymmetric_conflict(&dentry->d_subdirs, NULL, ACCESS_RW);
		dentry = tx_list2_first_entry(&dentry->d_subdirs, struct dentry, d_child); 
		UNLOCK_LIST(&dentry->d_subdirs);

		_dentry = tx_cache_get_dentry(dentry);
	}
out:
	/* several dentries were freed, need to correct nr_dentry */
	spin_lock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);
	dentry_stat.nr_dentry -= detached;
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);
}

/*
 * destroy the dentries attached to a superblock on unmounting
 * - we don't need to use dentry->d_lock, and only need dcache_lock when
 *   removing the dentry from the system lists and hashes because:
 *   - the superblock is detached from all mountings and open files, so the
 *     dentry trees will not be rearranged by the VFS
 *   - s_umount is write-locked, so the memory pressure shrinker will ignore
 *     any dentries belonging to this superblock that it comes across
 *   - the filesystem itself is no longer permitted to rearrange the dentries
 *     in this superblock
 */
void shrink_dcache_for_umount(struct super_block *sb)
{
	struct dentry *dentry;

	if (down_read_trylock(&sb->s_umount))
		BUG();

	dentry = sb->s_root;
	sb->s_root = NULL;
	tx_atomic_dec(&dentry->d_count);
	shrink_dcache_for_umount_subtree(dentry);

	/* DEP: This is going to take some work to get right with superblocks */
	KSTM_BUG_ON(active_transaction());

	while (!tx_list2_empty(&sb->s_anon)) {
		dentry = tx_list2_first_entry(&sb->s_anon, struct dentry, d_hash);
		shrink_dcache_for_umount_subtree(dentry);
	}
}

/*
 * Search for at least 1 mount point in the dentry's subdirs.
 * We descend to the next level whenever the d_subdirs
 * list is non-empty and continue searching.
 */
 
/**
 * have_submounts - check for mounts over a dentry
 * @parent: dentry to check.
 *
 * Return true if the parent or its subdirectories contain
 * a mount point
 */
 
int have_submounts(struct dentry *parent)
{
	struct dentry *this_parent = parent;
	struct tx_list2_iterator iter;

	spin_lock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);
	if (d_mountpoint(parent))
		goto positive;
repeat:
	tx_list2_get_iterator(&iter, &this_parent->d_subdirs);			
resume:
	while (tx_list2_iter_next(&iter)){
		struct dentry *dentry = tx_list2_iter_entry(&iter, struct dentry, d_child);
		/* Have we found a mount point ? */
		if (d_mountpoint(dentry)){
			tx_list2_put_iterator(&iter);
			goto positive;
		}
		if (!tx_list2_empty(&dentry->d_subdirs)) {
			tx_list2_put_iterator(&iter);
			this_parent = dentry;
			goto repeat;
		}
	}
	tx_list2_put_iterator(&iter);
	/*
	 * All done at this level ... ascend and resume the search.
	 */
	if (this_parent != parent){
		tx_list2_get_iterator_pos(&iter, &this_parent->d_child);		      
		this_parent = tx_cache_get_dentry_ro(this_parent)->d_parent;
		goto resume;
	}
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);
	return 0; /* No mount points found in tree */
positive:
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);
	return 1;
}

/*
 * Search the dentry child list for the specified parent,
 * and move any unused dentries to the end of the unused
 * list for prune_dcache(). We descend to the next level
 * whenever the d_subdirs list is non-empty and continue
 * searching.
 *
 * It returns zero iff there are no unused children,
 * otherwise  it returns the number of children moved to
 * the end of the unused list. This may not be the total
 * number of unused children, because select_parent can
 * drop the lock and return early due to latency
 * constraints.
 */
static int select_parent(struct dentry * parent)
{
	struct dentry *this_parent = parent;
	struct tx_list2_iterator iter;
	int found = 0;

	spin_lock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);
repeat:
	tx_list2_get_iterator(&iter, &this_parent->d_subdirs);			
resume:
	while (tx_list2_iter_next(&iter)){
		struct dentry *dentry = tx_list2_iter_entry(&iter, struct dentry, d_child);

		if (!list_empty(&dentry->d_lru)) {
			dentry_stat.nr_unused--;
			list_del_init(&dentry->d_lru);
		}
		/* 
		 * move only zero ref count dentries to the end 
		 * of the unused list for prune_dcache
		 */
		if (!atomic_read(&dentry->d_count)) {
			list_add_tail(&dentry->d_lru, &dentry_unused);
			dentry_stat.nr_unused++;
			found++;
		}

		/*
		 * We can return to the caller if we have found some (this
		 * ensures forward progress). We'll be coming back to find
		 * the rest.
		 */
		if (found && need_resched()){
			tx_list2_put_iterator(&iter);
			goto out;
		}

		/*
		 * Descend a level if the d_subdirs list is non-empty.
		 */
		if (!tx_list2_empty_locked(&dentry->d_subdirs)) {
			this_parent = dentry;
			tx_list2_put_iterator(&iter);
			
			goto repeat;
		}
	}
	tx_list2_put_iterator(&iter);
	/*
	 * All done at this level ... ascend and resume the search.
	 */
	if (this_parent != parent) {
		tx_list2_get_iterator_pos(&iter, &this_parent->d_child);
		this_parent = tx_cache_get_dentry_ro(this_parent)->d_parent;
		goto resume;
	}
out:
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);
	return found;
}

/**
 * shrink_dcache_parent - prune dcache
 * @parent: parent of entries to prune
 *
 * Prune the dcache to remove unused children of the parent dentry.
 */
 
void shrink_dcache_parent(struct dentry * parent)
{
	int found;

	while ((found = select_parent(parent)) != 0)
		prune_dcache(found, parent->d_sb, 1);
}

/*
 * Scan `nr' dentries and return the number which remain.
 *
 * We need to avoid reentering the filesystem if the caller is performing a
 * GFP_NOFS allocation attempt.  One example deadlock is:
 *
 * ext2_new_block->getblk->GFP->shrink_dcache_memory->prune_dcache->
 * prune_one_dentry->dput->dentry_iput->iput->inode->i_sb->s_op->put_inode->
 * ext2_discard_prealloc->ext2_free_blocks->lock_super->DEADLOCK.
 *
 * In this case we return -1 to tell the caller that we baled.
 */

static struct transaction shrinker_alter_ego = { status : {TX_INACTIVE, 0}};

static int shrink_dcache_memory(int nr, gfp_t gfp_mask)
{

	if (nr) {
		struct transaction *tx = NULL;
		if (!(gfp_mask & __GFP_FS))
			return -1;

		/* Assume a non-tx alter-ego for the shrinkage.  We
		 * may get aborted.  Oh well.
		 */
		if(active_transaction()){
			DEBUG_BREAKPOINT();
			tx = current->transaction;
			current->transaction = &shrinker_alter_ego;
		}

		prune_dcache(nr, NULL, 1);
		if(tx)
			current->transaction = tx;
	}
	return (dentry_stat.nr_unused / 100) * sysctl_vfs_cache_pressure;
}

/**
 * d_alloc	-	allocate a dcache entry
 * @parent: parent of entry to allocate
 * @name: qstr of the name
 *
 * Allocates a dentry. It returns %NULL if there is insufficient memory
 * available. On a success the dentry is returned. The name passed in is
 * copied and the copy passed in may be reused after this call.
 */
 
struct dentry *d_alloc(struct _dentry * parent, const struct qstr *name)
{
	struct dentry *dentry;
	struct _dentry *_dentry;
	char *dname;

	dentry = kmem_cache_alloc(dentry_cache, GFP_KERNEL); 

	if (!dentry)
		return NULL;

	_dentry = kmem_cache_alloc(_dentry_cache, GFP_KERNEL);
	
	if (!_dentry){
		kmem_cache_free(dentry_cache, dentry);
		return NULL;
	}

	dentry->d_contents = _dentry;
	_dentry->parent = dentry;
#ifdef CONFIG_TX_KSTM
	_dentry->shadow = NULL;
	_dentry->rw = ACCESS_R;
	atomic_set(&_dentry->tx_refcount, 0);
	atomic_set(&_dentry->tx_readcount, 0);
#endif

	if (name->len > DNAME_INLINE_LEN-1) {
		dname = kmalloc(name->len + 1, GFP_KERNEL);
		if (!dname) {
			kmem_cache_free(dentry_cache, dentry); 
			return NULL;
		}
	} else  {
		dname = _dentry->d_iname;
	}	
	_dentry->d_name.name = dname;

	_dentry->d_name.len = name->len;
	_dentry->d_name.hash = name->hash;
	memcpy(dname, name->name, name->len);
	dname[name->len] = 0;

	atomic_set(&dentry->d_count, 1);
	_dentry->d_flags = DCACHE_UNHASHED;
	spin_lock_init(&dentry->d_lock);
	_dentry->d_inode = NULL;
	_dentry->d_parent = NULL;
	dentry->d_sb = NULL;
	_dentry->d_op = NULL;
	dentry->d_fsdata = NULL;
	dentry->d_mounted = 0;
#ifdef CONFIG_PROFILING
	_dentry->d_cookie = NULL;
#endif
	INIT_TX_LIST2_REF(&dentry->d_hash);
	INIT_LIST_HEAD(&dentry->d_lru);
	INIT_TX_LIST2_HEAD(&dentry->d_subdirs);
	INIT_TX_LIST2_REF(&dentry->d_child);
	INIT_TX_LIST2_REF(&dentry->d_alias);

#ifdef CONFIG_TX_KSTM
	init_tx_object(&dentry->xobj, TYPE_DENTRY);
#endif

	if (parent) {
		_dentry->d_parent = dget(parent(parent));
		dentry->d_sb = parent(parent)->d_sb;
	}

	/* DEP: At this point, make the new dentry transactional if we
	 * are in a tx */
	_dentry = tx_cache_get_dentry(dentry);

	spin_lock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);
	if (parent){
		tx_list2_add(&dentry->d_child, &parent(parent)->d_subdirs);
	}

	dentry_stat.nr_dentry++;
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);

	return dentry;
}

struct dentry *d_alloc_name(struct _dentry *parent, const char *name)
{
	struct qstr q;

	q.name = name;
	q.len = strlen(name);
	q.hash = full_name_hash(q.name, q.len);
	return d_alloc(parent, &q);
}

/**
 * d_instantiate - fill in inode information for a dentry
 * @entry: dentry to complete
 * @inode: inode to attach to this dentry
 *
 * Fill in inode information in the entry.
 *
 * This turns negative dentries into productive full members
 * of society.
 *
 * NOTE! This assumes that the inode count has been incremented
 * (or otherwise set) by the caller to indicate that it is now
 * in use by the dcache.
 */
 
void d_instantiate(struct _dentry *entry, struct _inode * inode)
{
	BUG_ON(!tx_list2_unreferenced(&parent(entry)->d_alias));

	/* DEP 12/30/08: Don't need the dcache lock if we are in a tx */
	if(!(live_transaction()))
		spin_lock(&dcache_lock);

	if (inode){
		tx_list2_add(&parent(entry)->d_alias, &parent(inode)->i_dentry);
		entry->d_inode = parent(inode);
	} else
		entry->d_inode = NULL;
	fsnotify_d_instantiate(entry, entry->d_inode);

	if(!(live_transaction()))
		spin_unlock(&dcache_lock);

	security_d_instantiate(entry, inode);
}

/**
 * d_instantiate_unique - instantiate a non-aliased dentry
 * @entry: dentry to instantiate
 * @inode: inode to attach to this dentry
 *
 * Fill in inode information in the entry. On success, it returns NULL.
 * If an unhashed alias of "entry" already exists, then we return the
 * aliased dentry instead and drop one reference to inode.
 *
 * Note that in order to avoid conflicts with rename() etc, the caller
 * had better be holding the parent directory semaphore.
 *
 * This also assumes that the inode count has been incremented
 * (or otherwise set) by the caller to indicate that it is now
 * in use by the dcache.
 */
static struct _dentry *__d_instantiate_unique(struct _dentry *entry,
					      struct _inode *inode)
{
	struct dentry *alias;
	struct _dentry *_alias;
	int len = entry->d_name.len;
	const char *name = entry->d_name.name;
	unsigned int hash = entry->d_name.hash;
	struct tx_list2_iterator iter;

	if (!inode) {
		entry->d_inode = NULL;
		return NULL;
	}

	tx_list2_get_iterator(&iter, &parent(inode)->i_dentry);
	while (tx_list2_iter_next(&iter)){
		struct qstr *qstr;
		alias = tx_list2_iter_entry(&iter, struct dentry, d_alias);
		_alias = tx_cache_get_dentry_ro(alias);

		qstr = &_alias->d_name;

		if (qstr->hash != hash)
			continue;
		if (_alias->d_parent != entry->d_parent)
			continue;
		if (qstr->len != len)
			continue;
		if (memcmp(qstr->name, name, len))
			continue;
		tx_list2_put_iterator(&iter);
		dget_locked(alias);
		return _alias;
	}
	tx_list2_put_iterator(&iter);

	// Upgrade to RW mode
	entry = tx_cache_get_dentry(parent(entry));

	tx_list2_add(&parent(entry)->d_alias, &parent(inode)->i_dentry);
	entry->d_inode = parent(inode);
	fsnotify_d_instantiate(entry, parent(inode));
	return NULL;
}

struct _dentry *d_instantiate_unique(struct _dentry *entry, struct _inode *inode)
{
	struct _dentry *result;

	BUG_ON(!tx_list2_unreferenced(&parent(entry)->d_alias));

	spin_lock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);
	result = __d_instantiate_unique(entry, inode);
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);

	if (!result) {
		security_d_instantiate(entry, inode);
		return NULL;
	}

	BUG_ON(!d_unhashed(result));
	iput(parent(inode));
	return result;
}

EXPORT_SYMBOL(d_instantiate_unique);

/**
 * d_alloc_root - allocate root dentry
 * @root_inode: inode to allocate the root for
 *
 * Allocate a root ("/") dentry for the inode given. The inode is
 * instantiated and returned. %NULL is returned if there is insufficient
 * memory or the inode passed is %NULL.
 */
 
struct dentry * d_alloc_root(struct _inode * root_inode)
{
	struct dentry *res = NULL;

	if (root_inode) {
		static const struct qstr name = { .name = "/", .len = 1 };

		res = d_alloc(NULL, &name);
		if (res) {
			struct _dentry *_res = tx_cache_get_dentry(res);
			res->d_sb = root_inode->i_sb;
			_res->d_parent = res;
			d_instantiate(_res, root_inode);
		}
	}
	return res;
}

static inline struct tx_list2_head *d_hash(struct dentry *parent,
					   unsigned long hash)
{
	hash += ((unsigned long) parent ^ GOLDEN_RATIO_PRIME) / L1_CACHE_BYTES;
	hash = hash ^ ((hash ^ GOLDEN_RATIO_PRIME) >> D_HASHBITS);
	return dentry_hashtable + (hash & D_HASHMASK);
}

static inline struct tx_list2_head *d_hash_ro(struct dentry *parent,
					      unsigned long hash)
{
	hash += ((unsigned long) parent ^ GOLDEN_RATIO_PRIME) / L1_CACHE_BYTES;
	hash = hash ^ ((hash ^ GOLDEN_RATIO_PRIME) >> D_HASHBITS);
	return dentry_hashtable + (hash & D_HASHMASK);
}

/**
 * d_alloc_anon - allocate an anonymous dentry
 * @inode: inode to allocate the dentry for
 *
 * This is similar to d_alloc_root.  It is used by filesystems when
 * creating a dentry for a given inode, often in the process of 
 * mapping a filehandle to a dentry.  The returned dentry may be
 * anonymous, or may have a full name (if the inode was already
 * in the cache).  The file system may need to make further
 * efforts to connect this dentry into the dcache properly.
 *
 * When called on a directory inode, we must ensure that
 * the inode only ever has one dentry.  If a dentry is
 * found, that is returned instead of allocating a new one.
 *
 * On successful return, the reference to the inode has been transferred
 * to the dentry.  If %NULL is returned (indicating kmalloc failure),
 * the reference on the inode has not been released.
 */

struct dentry * d_alloc_anon(struct _inode *inode)
{
	static const struct qstr anonstring = { .name = "" };
	struct dentry *tmp, *res;
	struct _dentry *_res, *_tmp;

	if ((_res = d_find_alias(inode))) {
		iput(parent(inode));
		return parent(_res);
	}

	tmp = d_alloc(NULL, &anonstring);
	if (!tmp)
		return NULL;

	_tmp = tx_cache_get_dentry(tmp);
	_tmp->d_parent = tmp; /* make sure dput doesn't croak */
	
	spin_lock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);
	_res = __d_find_alias(inode, 0);
	if (!_res) {
		/* attach a disconnected dentry */
		res = tmp;
		_res = _tmp;
		tmp = NULL;
		dspin_lock(res);
		res->d_sb = inode->i_sb;
		_res->d_parent = res;
		_res->d_inode = parent(inode);
		_res->d_flags |= DCACHE_DISCONNECTED;
		_res->d_flags &= ~DCACHE_UNHASHED;
		/* DEP: This is going to take some work to get right with superblocks */
		BUG();
		tx_list2_add(&res->d_alias, &parent(inode)->i_dentry);
		tx_list2_add(&res->d_hash, &inode->i_sb->s_anon);
		dspin_unlock(res);

		inode = NULL; /* don't drop reference */
	} else
		res = parent(_res);
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);

	if (inode)
		iput(parent(inode));
	if (tmp)
		dput(tmp);
	return res;
}


/**
 * d_splice_alias - splice a disconnected dentry into the tree if one exists
 * @inode:  the inode which may have a disconnected dentry
 * @dentry: a negative dentry which we want to point to the inode.
 *
 * If inode is a directory and has a 'disconnected' dentry (i.e. IS_ROOT and
 * DCACHE_DISCONNECTED), then d_move that in place of the given dentry
 * and return it, else simply d_add the inode to the dentry and return NULL.
 *
 * This is needed in the lookup routine of any filesystem that is exportable
 * (via knfsd) so that we can build dcache paths to directories effectively.
 *
 * If a dentry was found and moved, then it is returned.  Otherwise NULL
 * is returned.  This matches the expected return value of ->lookup.
 *
 */
struct _dentry *d_splice_alias(struct _inode *inode, struct _dentry *dentry)
{
	struct _dentry *new = NULL;

	if (inode && S_ISDIR(inode->i_mode)) {
		spin_lock(&dcache_lock);
		record_tx_lock(&dcache_lock, SPIN_LOCK);
		new = __d_find_alias(inode, 1);
		if (new) {
			BUG_ON(!(new->d_flags & DCACHE_DISCONNECTED));
			fsnotify_d_instantiate(new, parent(inode));
			spin_unlock(&dcache_lock);
			record_tx_unlock(&dcache_lock, SPIN_LOCK);
			security_d_instantiate(new, inode);
			d_rehash(dentry);
			d_move(new, dentry);
			iput(parent(inode));
		} else {
			/* d_instantiate takes dcache_lock, so we do it by hand */
			tx_list2_add(&parent(dentry)->d_alias, &parent(inode)->i_dentry);
			dentry->d_inode = parent(inode);
			fsnotify_d_instantiate(dentry, parent(inode));
			spin_unlock(&dcache_lock);
			record_tx_unlock(&dcache_lock, SPIN_LOCK);
			security_d_instantiate(dentry, inode);
			d_rehash(dentry);
		}
	} else
		d_add(dentry, inode);
	return new;
}


/**
 * d_lookup - search for a dentry
 * @parent: parent dentry
 * @name: qstr of name we wish to find
 *
 * Searches the children of the parent dentry for the name in question. If
 * the dentry is found its reference count is incremented and the dentry
 * is returned. The caller must use d_put to free the entry when it has
 * finished using it. %NULL is returned on failure.
 *
 * __d_lookup is dcache_lock free. The hash list is protected using RCU.
 * Memory barriers are used while updating and doing lockless traversal. 
 * To avoid races with d_move while rename is happening, d_lock is used.
 *
 * Overflows in memcmp(), while d_move, are avoided by keeping the length
 * and name pointer in one structure pointed by d_qstr.
 *
 * rcu_read_lock() and rcu_read_unlock() are used to disable preemption while
 * lookup is going on.
 *
 * dentry_unused list is not updated even if lookup finds the required dentry
 * in there. It is updated in places such as prune_dcache, shrink_dcache_sb,
 * select_parent and __dget_locked. This laziness saves lookup from dcache_lock
 * acquisition.
 *
 * d_lookup() is protected against the concurrent renames in some unrelated
 * directory using the seqlockt_t rename_lock.
 */

struct _dentry * d_lookup(struct _dentry ** parent, struct qstr * name)
{
	struct _dentry * dentry = NULL;
	unsigned long seq;

        do {
                seq = read_seqbegin(&rename_lock);
                dentry = __d_lookup(parent, name);
                if (dentry)
			break;
	} while (read_seqretry(&rename_lock, seq));
	return dentry;
}

struct _dentry * __d_lookup(struct _dentry ** parent, struct qstr * name)
{
	unsigned int len = name->len;
	unsigned int hash = name->hash;
	const unsigned char *str = name->name;
	struct dentry *parentp = parent(*parent);
	enum access_mode rw = (*parent)->rw;
	struct tx_list2_head *head = d_hash_ro(parentp,hash);
	struct _dentry *found = NULL;
	struct dentry *dentry;
	struct _dentry *_dentry;
	struct tx_list2_iterator iter;

	
#ifdef CONFIG_TX_KSTM
	struct transaction *winner;
stall_retry:
#endif

	rcu_read_lock();

	tx_list2_get_iterator(&iter, head);
	while (tx_list2_iter_next(&iter)){
		struct qstr *qstr;
		dentry = tx_list2_iter_entry(&iter, struct dentry, d_hash);
		tx_list2_put_iterator(&iter);

		_dentry = tx_cache_get_dentry_ro(dentry);

		if (_dentry->d_name.hash != hash)
			goto next_unlocked;

		if (_dentry->d_parent != parentp)
			goto next_unlocked;


#ifdef CONFIG_TX_KSTM
		/* DEP 4/26/08: Beaucoup hacking to stall on
		 * conflict. We are only read-protecting this bad boy,
		 * so only asymmetric conflict it that way too.
		 */
		if(!live_transaction()){
			spin_lock(&dentry->d_lock);

			// Must kick out transactions with the lock held so
			// that we don't have a race
			while((atomic_read(&tx_count) != 0)
			      && (winner = 
				  check_asymmetric_conflict(&dentry->xobj, ACCESS_R, 
							    tx_preemptible(3), 0)
				      )){

				/* Drop the locks */
				spin_unlock(&dentry->d_lock);
				rcu_read_unlock();

				/* Sleep until the winner commits */
				wait_on_tx(winner);

				*parent = rw == ACCESS_R 
					? tx_cache_get_dentry_ro(parentp)
					: tx_cache_get_dentry(parentp);


				/* Try again */
				goto stall_retry;
			}
		} else 
			dspin_lock(dentry);
			
#else
		spin_lock(&dentry->d_lock);

#endif // CONFIG_TX_KSTM

		/*
		 * Recheck the dentry after taking the lock - d_move may have
		 * changed things.  Don't bother checking the hash because we're
		 * about to compare the whole name anyway.
		 */
		if (_dentry->d_parent != parentp)
			goto next;

		/*
		 * It is safe to compare names since d_move() cannot
		 * change the qstr (protected by d_lock).
		 */
		qstr = &_dentry->d_name;
		if ((*parent)->d_op && (*parent)->d_op->d_compare) {
			if ((*parent)->d_op->d_compare(parentp, qstr, name))
				goto next;
		} else {
			if (qstr->len != len)
				goto next;

			if (memcmp(qstr->name, str, len))
				goto next;
		}

		if (!d_unhashed(_dentry)) {
			tx_atomic_inc(&dentry->d_count);
			found = _dentry;
		}

		dspin_unlock(dentry);
		goto out;
next:
		dspin_unlock(dentry);

next_unlocked:
		/* If entry gets orphaned from the list, restart searching
		 * head.  Really need something more like hlist_del_rcu
		 * semantics here, but this is a slower approximation.
		 */
		if(tx_list2_get_iterator_pos(&iter, &dentry->d_hash))
			goto stall_retry;
 	}
	tx_list2_put_iterator(&iter);
out:
 	rcu_read_unlock();

 	return found;
}

/**
 * d_hash_and_lookup - hash the qstr then search for a dentry
 * @dir: Directory to search in
 * @name: qstr of name we wish to find
 *
 * On hash failure or on lookup failure NULL is returned.
 */
struct _dentry *d_hash_and_lookup(struct _dentry **dirp, struct qstr *name)
{
	struct _dentry *dentry = NULL;
	struct _dentry *dir = *dirp;

	/*
	 * Check for a fs-specific hash function. Note that we must
	 * calculate the standard hash first, as the d_op->d_hash()
	 * routine may choose to leave the hash value unchanged.
	 */
	name->hash = full_name_hash(name->name, name->len);
	if (dir->d_op && dir->d_op->d_hash) {
		if (dir->d_op->d_hash(parent(dir), name) < 0)
			goto out;
	}
	dentry = d_lookup(dirp, name);
out:
	return dentry;
}

/**
 * d_validate - verify dentry provided from insecure source
 * @dentry: The dentry alleged to be valid child of @dparent
 * @dparent: The parent dentry (known to be valid)
 * @hash: Hash of the dentry
 * @len: Length of the name
 *
 * An insecure source has sent us a dentry, here we verify it and dget() it.
 * This is used by ncpfs in its readdir implementation.
 * Zero is returned in the dentry is invalid.
 */
 
int d_validate(struct _dentry *_dentry, struct _dentry *dparent)
{
	struct tx_list2_head *base;
	struct tx_list2_iterator iter;
	struct dentry *dentry = parent(_dentry);

	/* Check whether the ptr might be valid at all.. */
	if (!kmem_ptr_validate(dentry_cache, dentry))
		goto out;

	if (_dentry->d_parent != parent(dparent))
		goto out;

	spin_lock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);
	base = d_hash(parent(dparent), _dentry->d_name.hash);
	tx_list2_get_iterator(&iter, base);
	while (tx_list2_iter_next(&iter)){
		if(dentry == tx_list2_iter_entry(&iter, struct dentry, d_hash)){
			/* Upgrade to RW */
			_dentry = tx_cache_get_dentry(parent(_dentry));
			__dget_locked(dentry);
			tx_list2_put_iterator(&iter);
			spin_unlock(&dcache_lock);
			record_tx_unlock(&dcache_lock, SPIN_LOCK);
			return 1;
		}
	}
	tx_list2_put_iterator(&iter);
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);
out:
	return 0;
}

/*
 * When a file is deleted, we have two options:
 * - turn this dentry into a negative dentry
 * - unhash this dentry and free it.
 *
 * Usually, we want to just turn this into
 * a negative dentry, but if anybody else is
 * currently using the dentry or the inode
 * we can't do that and we fall back on removing
 * it from the hash queues and waiting for
 * it to be deleted later when it has no users
 */
 
/**
 * d_delete - delete a dentry
 * @dentry: The dentry to delete
 *
 * Turn the dentry into a negative dentry if possible, otherwise
 * remove it from the hash queues so it can be deleted later
 */
 
void d_delete(struct _dentry * dentry)
{
	int isdir = 0;
	struct _inode *_inode;
	/*
	 * Are we the only user?
	 */
	spin_lock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);
	_dspin_lock(dentry);

	// We can end up with an early iput under deferred unlink.
	// Just don't do it twice
	_inode = d_get_inode(dentry);
	if(_inode){
		isdir = S_ISDIR(_inode->i_mode);
		if (tx_atomic_read(&parent(dentry)->d_count) == 1) {
			dentry_iput(dentry);
			fsnotify_nameremove(parent(dentry), isdir);

			/* remove this and other inotify debug checks after 2.6.18 */
			dentry->d_flags &= ~DCACHE_INOTIFY_PARENT_WATCHED;
			return;
		}
	}

	if (!d_unhashed(dentry))
		__d_drop(dentry);

	_dspin_unlock(dentry);
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);

	/* Only notify on a nameremove if the inode is still defined.
	 * Otherwise we probably already notified.*/
	if(_inode)
		fsnotify_nameremove(parent(dentry), isdir);
}

static void __d_rehash(struct _dentry * entry, struct tx_list2_head *list)
{
	if(unlikely(IS_ERR(entry) || IS_ERR(list)))
		return;
 	entry->d_flags &= ~DCACHE_UNHASHED;
 	tx_list2_add(&parent(entry)->d_hash, list);
}

static void _d_rehash(struct _dentry * entry)
{
	__d_rehash(entry, d_hash(entry->d_parent, entry->d_name.hash));
}

/**
 * d_rehash	- add an entry back to the hash
 * @entry: dentry to add to the hash
 *
 * Adds a dentry to the hash according to its name.
 */
 
void d_rehash(struct _dentry * entry)
{
	spin_lock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);
	_dspin_lock(entry);
	_d_rehash(entry);
	_dspin_unlock(entry);
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);
}

#define do_switch(x,y) do { \
	__typeof__ (x) __tmp = x; \
	x = y; y = __tmp; } while (0)

/*
 * When switching names, the actual string doesn't strictly have to
 * be preserved in the target - because we're dropping the target
 * anyway. As such, we can just do a simple memcpy() to copy over
 * the new name before we switch.
 *
 * Note that we have to be a lot more careful about getting the hash
 * switched - we have to switch the hash value properly even if it
 * then no longer matches the actual (corrupted) string of the target.
 * The hash value has to match the hash queue that the dentry is on..
 */
static void switch_names(struct _dentry *dentry, struct _dentry *target)
{
	if (dname_external(target)) {
		if (dname_external(dentry)) {
			/*
			 * Both external: swap the pointers
			 */
			do_switch(target->d_name.name, dentry->d_name.name);
		} else {
			/*
			 * dentry:internal, target:external.  Steal target's
			 * storage and make target internal.
			 */
			dentry->d_name.name = target->d_name.name;
			target->d_name.name = target->d_iname;
		}
	} else {
		if (dname_external(dentry)) {
			/*
			 * dentry:external, target:internal.  Give dentry's
			 * storage to target and make dentry internal
			 */
			memcpy(dentry->d_iname, target->d_name.name,
					target->d_name.len + 1);
			target->d_name.name = dentry->d_name.name;
			dentry->d_name.name = dentry->d_iname;
		} else {
			/*
			 * Both are internal.  Just copy target to dentry
			 */
			memcpy(dentry->d_iname, target->d_name.name,
					target->d_name.len + 1);
		}
	}
}

/*
 * We cannibalize "target" when moving dentry on top of it,
 * because it's going to be thrown away anyway. We could be more
 * polite about it, though.
 *
 * This forceful removal will result in ugly /proc output if
 * somebody holds a file open that got deleted due to a rename.
 * We could be nicer about the deleted file, and let it show
 * up under the name it got deleted rather than the name that
 * deleted it.
 */
 
/*
 * d_move_locked - move a dentry
 * @dentry: entry to move
 * @target: new dentry
 *
 * Update the dcache to reflect the move of a file name. Negative
 * dcache entries should not be moved in this way.
 */
static void d_move_locked(struct _dentry * dentry, struct _dentry * target)
{
	struct tx_list2_head *list;
	struct dentry *pdentry = parent(dentry), *ptarget = parent(target);

	if (!dentry->d_inode)
		printk(KERN_WARNING "VFS: moving negative dcache entry\n");

	KSTM_BUG_ON(pdentry == ptarget);

	write_seqlock(&rename_lock);
	/*
	 * XXXX: do we really need to take target->d_lock?
	 */
	if (ptarget < pdentry) {
		dspin_lock(ptarget);
		dspin_lock_nested(pdentry, DENTRY_D_LOCK_NESTED);
	} else {
		dspin_lock(pdentry);
		dspin_lock_nested(ptarget, DENTRY_D_LOCK_NESTED);
	}

	/* Move the dentry to the target hash queue, if on different bucket */
	if (dentry->d_flags & DCACHE_UNHASHED)
		goto already_unhashed;

	tx_list2_del(&pdentry->d_hash);

already_unhashed:
	list = d_hash(target->d_parent, target->d_name.hash);
	__d_rehash(dentry, list);

	/* Unhash the target: dput() will then get rid of it */
	__d_drop(target);

	tx_list2_del(&pdentry->d_child);
	tx_list2_del(&ptarget->d_child);

	/* Switch the names.. */
	switch_names(dentry, target);
	do_switch(dentry->d_name.len, target->d_name.len);
	do_switch(dentry->d_name.hash, target->d_name.hash);

	/* ... and switch the parents */
	if (IS_ROOT(dentry)) {
		dentry->d_parent = target->d_parent;
		target->d_parent = parent(target);
		INIT_TX_LIST2_REF(&pdentry->d_child);
	} else {
		do_switch(dentry->d_parent, target->d_parent);

		/* And add them back to the (new) parent lists */
		tx_list2_add(&ptarget->d_child, 
			     &(target->d_parent)->d_subdirs);
	}

	tx_list2_add(&pdentry->d_child, 
		     &(dentry->d_parent)->d_subdirs);
	dspin_unlock(ptarget);
	fsnotify_d_move(parent(dentry));
	dspin_unlock(pdentry);
	write_sequnlock(&rename_lock);
}

/**
 * d_move - move a dentry
 * @dentry: entry to move
 * @target: new dentry
 *
 * Update the dcache to reflect the move of a file name. Negative
 * dcache entries should not be moved in this way.
 */

void d_move(struct _dentry * dentry, struct _dentry * target)
{
	spin_lock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);
	d_move_locked(dentry, target);
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);
}

/*
 * Helper that returns 1 if p1 is a parent of p2, else 0
 */
static int d_isparent(struct _dentry *p1, struct _dentry *p2)
{
	struct _dentry *p;

	for (p = p2; p->d_parent != parent(p);
	     p = tx_cache_get_dentry_ro(p->d_parent)) {
		if (p->d_parent == parent(p1))
			return 1;
	}
	return 0;
}

/*
 * This helper attempts to cope with remotely renamed directories
 *
 * It assumes that the caller is already holding
 * dentry->d_parent->d_inode->i_mutex and the dcache_lock
 *
 * Note: If ever the locking in lock_rename() changes, then please
 * remember to update this too...
 *
 * On return, dcache_lock will have been unlocked.
 */
static struct _dentry *__d_unalias(struct _dentry *dentry, struct _dentry *alias)
{
	struct mutex *m1 = NULL, *m2 = NULL;
	struct _dentry *ret;

	/* If alias and dentry share a parent, then no extra locks required */
	if (alias->d_parent == dentry->d_parent)
		goto out_unalias;

	/* Check for loops */
	ret = ERR_PTR(-ELOOP);
	if (d_isparent(alias, dentry))
		goto out_err;

	/* See lock_rename() */
	ret = ERR_PTR(-EBUSY);
	if (!mutex_trylock(&parent(dentry)->d_sb->s_vfs_rename_mutex))
		goto out_err;

	/* XXX: These locks need to be recorded */
	m1 = &parent(dentry)->d_sb->s_vfs_rename_mutex;
	m2 = &tx_cache_get_dentry_ro(alias->d_parent)->d_inode->i_mutex;
	if (!mutex_trylock(m2)){
		m2 = NULL;
		goto out_err;
	}
out_unalias:
	d_move_locked(alias, dentry);
	ret = alias;
out_err:
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);
	if (m2)
		mutex_unlock(m2);
	if (m1)
		mutex_unlock(m1);
	return ret;
}

/*
 * Prepare an anonymous dentry for life in the superblock's dentry tree as a
 * named dentry in place of the dentry to be replaced.
 */
static void __d_materialise_dentry(struct _dentry *dentry, struct _dentry *anon)
{
	struct _dentry *dparent, *aparent;

	switch_names(dentry, anon);
	do_switch(dentry->d_name.len, anon->d_name.len);
	do_switch(dentry->d_name.hash, anon->d_name.hash);

	dparent = tx_cache_get_dentry(dentry->d_parent);
	aparent = tx_cache_get_dentry(anon->d_parent);

	dentry->d_parent = (aparent == anon) ? parent(dentry) : parent(aparent);
	tx_list2_del(&parent(dentry)->d_child);
	if (!IS_ROOT(dentry))
		tx_list2_add(&parent(dentry)->d_child, 
			    &(dentry->d_parent)->d_subdirs);
	else
		INIT_TX_LIST2_REF(&parent(dentry)->d_child);

	anon->d_parent = (dparent == dentry) ? parent(anon) : parent(dparent);
	tx_list2_del(&parent(anon)->d_child);
	if (!IS_ROOT(anon))
		tx_list2_add(&parent(anon)->d_child, 
			    &(anon->d_parent)->d_subdirs);
	else
		INIT_TX_LIST2_REF(&parent(anon)->d_child);

	anon->d_flags &= ~DCACHE_DISCONNECTED;
}

/**
 * d_materialise_unique - introduce an inode into the tree
 * @dentry: candidate dentry
 * @inode: inode to bind to the dentry, to which aliases may be attached
 *
 * Introduces an dentry into the tree, substituting an extant disconnected
 * root directory alias in its place if there is one
 */
struct _dentry *d_materialise_unique(struct _dentry *dentry, struct _inode *inode)
{
	struct _dentry *actual;

	BUG_ON(!d_unhashed(dentry));

	spin_lock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);

	if (!inode) {
		actual = dentry;
		dentry->d_inode = NULL;
		goto found_lock;
	}

	if (S_ISDIR(inode->i_mode)) {
		struct _dentry *alias;

		/* Does an aliased dentry already exist? */
		alias = __d_find_alias(inode, 0);
		if (alias) {
			actual = alias;
			/* Is this an anonymous mountpoint that we could splice
			 * into our tree? */
			if (IS_ROOT(alias)) {
				_dspin_lock(alias);
				__d_materialise_dentry(dentry, alias);
				__d_drop(alias);
				goto found;
			}
			/* Nope, but we must(!) avoid directory aliasing */
			actual = __d_unalias(dentry, alias);
			if (IS_ERR(actual))
				dput(parent(alias));
			goto out_nolock;
		}
	}

	/* Add a unique reference */
	actual = __d_instantiate_unique(dentry, inode);
	if (!actual)
		actual = dentry;
	else if (unlikely(!d_unhashed(actual)))
		goto shouldnt_be_hashed;

found_lock:
	_dspin_lock(actual);
found:
	_d_rehash(actual);
	_dspin_unlock(actual);
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);
out_nolock:
	if (actual == dentry) {
		security_d_instantiate(dentry, inode);
		return NULL;
	}

	iput(parent(inode));
	return actual;

shouldnt_be_hashed:
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);
	BUG();
	goto shouldnt_be_hashed;
}

/**
 * d_path - return the path of a dentry
 * @dentry: dentry to report
 * @vfsmnt: vfsmnt to which the dentry belongs
 * @root: root dentry
 * @rootmnt: vfsmnt to which the root dentry belongs
 * @buffer: buffer to return value in
 * @buflen: buffer length
 *
 * Convert a dentry into an ASCII path name. If the entry has been deleted
 * the string " (deleted)" is appended. Note that this is ambiguous.
 *
 * Returns the buffer or an error code if the path was too long.
 *
 * "buflen" should be positive. Caller holds the dcache_lock.
 */
static char * __d_path( const struct _dentry *dentry, struct vfsmount *vfsmnt,
			const struct _dentry *root, struct vfsmount *rootmnt,
			char *buffer, int buflen)
{
	char * end = buffer+buflen;
	char * retval;
	int namelen;

	*--end = '\0';
	buflen--;
	if (!IS_ROOT(dentry) && d_unhashed(dentry)) {
		buflen -= 10;
		end -= 10;
		if (buflen < 0)
			goto Elong;
		memcpy(end, " (deleted)", 10);
	}

	if (buflen < 1)
		goto Elong;
	/* Get '/' right */
	retval = end-1;
	*retval = '/';

	for (;;) {
		struct _dentry * parent;

		if (dentry == root && vfsmnt == rootmnt)
			break;
		if (parent(dentry) == vfsmnt->mnt_root || IS_ROOT(dentry)) {
			/* Global root? */
			spin_lock(&vfsmount_lock);
			if (vfsmnt->mnt_parent == vfsmnt) {
				spin_unlock(&vfsmount_lock);
				goto global_root;
			}
			dentry = tx_cache_get_dentry_ro(vfsmnt->mnt_mountpoint);
			vfsmnt = vfsmnt->mnt_parent;
			spin_unlock(&vfsmount_lock);
			continue;
		}
		parent = tx_cache_get_dentry_ro(dentry->d_parent);
		prefetch(parent);
		namelen = dentry->d_name.len;
		buflen -= namelen + 1;
		if (buflen < 0)
			goto Elong;
		end -= namelen;
		memcpy(end, dentry->d_name.name, namelen);
		*--end = '/';
		retval = end;
		dentry = parent;
	}

	return retval;

global_root:
	namelen = dentry->d_name.len;
	buflen -= namelen;
	if (buflen < 0)
		goto Elong;
	retval -= namelen-1;	/* hit the slash */
	memcpy(retval, dentry->d_name.name, namelen);
	return retval;
Elong:
	return ERR_PTR(-ENAMETOOLONG);
}

/* write full pathname into buffer and return start of pathname */
char * d_path(const struct _dentry *dentry, struct vfsmount *vfsmnt,
				char *buf, int buflen)
{
	char *res;
	struct vfsmount *rootmnt;
	struct _dentry *root;

	/*
	 * We have various synthetic filesystems that never get mounted.  On
	 * these filesystems dentries are never used for lookup purposes, and
	 * thus don't need to be hashed.  They also don't need a name until a
	 * user wants to identify the object in /proc/pid/fd/.  The little hack
	 * below allows us to generate a name for these objects on demand:
	 */
	if (dentry->d_op && dentry->d_op->d_dname)
		return dentry->d_op->d_dname(dentry, buf, buflen);

	read_lock(&current->fs->lock);
	rootmnt = mntget(current->fs->rootmnt);
	root = tx_cache_get_dentry_ro(dget(current->fs->root));
	read_unlock(&current->fs->lock);
	spin_lock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);
	res = __d_path(dentry, vfsmnt, root, rootmnt, buf, buflen);
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);
	dput(parent(root));
	mntput(rootmnt);
	return res;
}

/*
 * Helper function for dentry_operations.d_dname() members
 */
char *dynamic_dname(const struct _dentry *dentry, char *buffer, int buflen,
		    const char *fmt, ...)
{
	va_list args;
	char temp[64];
	int sz;

	va_start(args, fmt);
	sz = vsnprintf(temp, sizeof(temp), fmt, args) + 1;
	va_end(args);

	if (sz > sizeof(temp) || sz > buflen)
		return ERR_PTR(-ENAMETOOLONG);

	buffer += buflen - sz;
	return memcpy(buffer, temp, sz);
}

/*
 * NOTE! The user-level library version returns a
 * character pointer. The kernel system call just
 * returns the length of the buffer filled (which
 * includes the ending '\0' character), or a negative
 * error value. So libc would do something like
 *
 *	char *getcwd(char * buf, size_t size)
 *	{
 *		int retval;
 *
 *		retval = sys_getcwd(buf, size);
 *		if (retval >= 0)
 *			return buf;
 *		errno = -retval;
 *		return NULL;
 *	}
 */
asmlinkage long sys_getcwd(char __user *buf, unsigned long size)
{
	int error;
	struct vfsmount *pwdmnt, *rootmnt;
	const struct _dentry *pwd, *root;
	char *page = (char *) __get_free_page(GFP_USER);

	if (!page)
		return -ENOMEM;

	read_lock(&current->fs->lock);
	pwdmnt = mntget(current->fs->pwdmnt);
	pwd = tx_cache_get_dentry_ro(dget(current->fs->pwd));
	rootmnt = mntget(current->fs->rootmnt);
	root = tx_cache_get_dentry_ro(dget(current->fs->root));
	read_unlock(&current->fs->lock);

	error = -ENOENT;
	/* Has the current directory has been unlinked? */
	spin_lock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);
	if (pwd->d_parent == parent(pwd) || !d_unhashed(pwd)) {
		unsigned long len;
		char * cwd;

		cwd = __d_path(pwd, pwdmnt, root, rootmnt, page, PAGE_SIZE);
		spin_unlock(&dcache_lock);
		record_tx_unlock(&dcache_lock, SPIN_LOCK);

		error = PTR_ERR(cwd);
		if (IS_ERR(cwd))
			goto out;

		error = -ERANGE;
		len = PAGE_SIZE + page - cwd;
		if (len <= size) {
			error = len;
			if (copy_to_user(buf, cwd, len))
				error = -EFAULT;
		}
	} else {
		spin_unlock(&dcache_lock);
		record_tx_unlock(&dcache_lock, SPIN_LOCK);
	}

out:
	dput(parent(pwd));
	mntput(pwdmnt);
	dput(parent(root));
	mntput(rootmnt);
	free_page((unsigned long) page);
	return error;
}

/*
 * Test whether new_dentry is a subdirectory of old_dentry.
 *
 * Trivially implemented using the dcache structure
 */

/**
 * is_subdir - is new dentry a subdirectory of old_dentry
 * @new_dentry: new dentry
 * @old_dentry: old dentry
 *
 * Returns 1 if new_dentry is a subdirectory of the parent (at any depth).
 * Returns 0 otherwise.
 * Caller must ensure that "new_dentry" is pinned before calling is_subdir()
 */
  
int is_subdir(const struct _dentry * new_dentry, const struct _dentry * old_dentry)
{
	int result;
	const struct _dentry * saved = new_dentry;
	unsigned long seq;

	/* need rcu_readlock to protect against the d_parent trashing due to
	 * d_move
	 */
	rcu_read_lock();
        do {
		/* for restarting inner loop in case of seq retry */
		new_dentry = saved;
		result = 0;
		seq = read_seqbegin(&rename_lock);
		for (;;) {
			if (new_dentry != old_dentry) {
				struct _dentry * parent = 
					tx_cache_get_dentry_ro(new_dentry->d_parent);
				if (parent == new_dentry)
					break;
				new_dentry = parent;
				continue;
			}
			result = 1;
			break;
		}
	} while (read_seqretry(&rename_lock, seq));
	rcu_read_unlock();

	return result;
}

void d_genocide(struct _dentry *root)
{
	struct dentry *this_parent = parent(root);
	struct tx_list2_iterator iter;

	spin_lock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);
repeat:
	tx_list2_get_iterator(&iter, &this_parent->d_subdirs);
resume:
	while (tx_list2_iter_next(&iter)){
		struct dentry *dentry  = tx_list2_iter_entry(&iter, struct dentry, d_child);
		struct _dentry *_dentry = tx_cache_get_dentry_ro(dentry);

		if (d_unhashed(_dentry)||!_dentry->d_inode)
			continue;
		if (!tx_list2_empty(&dentry->d_subdirs)) {
			this_parent = dentry;
			tx_list2_put_iterator(&iter);
			goto repeat;
		}
		tx_atomic_dec(&dentry->d_count);
	}
	tx_list2_put_iterator(&iter);
	if (this_parent != parent(root)) {
		tx_list2_get_iterator_pos(&iter, &this_parent->d_child);		      
		this_parent = tx_cache_get_dentry_ro(this_parent)->d_parent;
		tx_atomic_dec(&this_parent->d_count);
		goto resume;
	}
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);
}

/**
 * find_inode_number - check for dentry with name
 * @dir: directory to check
 * @name: Name to find.
 *
 * Check whether a dentry already exists for the given name,
 * and return the inode number if it has an inode. Otherwise
 * 0 is returned.
 *
 * This routine is used to post-process directory listings for
 * filesystems using synthetic inode numbers, and is necessary
 * to keep getcwd() working.
 */
 
ino_t find_inode_number(struct _dentry **dir, struct qstr *name)
{
	struct _dentry * dentry;
	ino_t ino = 0;

	dentry = d_hash_and_lookup(dir, name);
	if (dentry) {
		if (dentry->d_inode)
			ino = d_get_inode(dentry)->i_ino;
		dput(parent(dentry));
	}
	return ino;
}

static __initdata unsigned long dhash_entries;
static int __init set_dhash_entries(char *str)
{
	if (!str)
		return 0;
	dhash_entries = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("dhash_entries=", set_dhash_entries);

static void __init dcache_init_early(void)
{
	int loop;
	/* If hashes are distributed across NUMA nodes, defer
	 * hash allocation until vmalloc space is available.
	 */
	if (hashdist)
		return;

	dentry_hashtable =
		alloc_large_system_hash("Dentry cache",
					sizeof(struct tx_list2_head),
					dhash_entries,
					13,
					HASH_EARLY,
					&d_hash_shift,
					&d_hash_mask,
					0);

	for (loop = 0; loop < (1 << d_hash_shift); loop++)
		INIT_TX_LIST2_HEAD(&dentry_hashtable[loop]);

}

static void __init dcache_init(unsigned long mempages)
{
	int loop;

	/* 
	 * A constructor could be added for stable state like the lists,
	 * but it is probably not worth it because of the cache nature
	 * of the dcache. 
	 */
	dentry_cache = KMEM_CACHE(dentry,
		SLAB_RECLAIM_ACCOUNT|SLAB_PANIC|SLAB_MEM_SPREAD);

	_dentry_cache = KMEM_CACHE(_dentry,
		SLAB_RECLAIM_ACCOUNT|SLAB_PANIC|SLAB_MEM_SPREAD);
	
	set_shrinker(DEFAULT_SEEKS, shrink_dcache_memory);

	/* Hash may have been set up in dcache_init_early */
	if (!hashdist)
		return;

	dentry_hashtable =
		alloc_large_system_hash("Dentry cache",
					sizeof(struct tx_list2_head),
					dhash_entries,
					13,
					0,
					&d_hash_shift,
					&d_hash_mask,
					0);

	for (loop = 0; loop < (1 << d_hash_shift); loop++)
		INIT_TX_LIST2_HEAD(&dentry_hashtable[loop]);

}

/* SLAB cache for __getname() consumers */
struct kmem_cache *names_cachep __read_mostly;

/* SLAB cache for file structures */
struct kmem_cache *filp_cachep __read_mostly;
struct kmem_cache *_filp_cachep __read_mostly;

EXPORT_SYMBOL(d_genocide);

void __init vfs_caches_init_early(void)
{
	dcache_init_early();
	inode_init_early();
}

void __init vfs_caches_init(unsigned long mempages)
{
	unsigned long reserve;

	super_cache_init();

	/* Base hash sizes on available memory, with a reserve equal to
           150% of current kernel size */

	reserve = min((mempages - nr_free_pages()) * 3/2, mempages - 1);
	mempages -= reserve;

	names_cachep = kmem_cache_create("names_cache", PATH_MAX, 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);

	filp_cachep = kmem_cache_create("filp", sizeof(struct file), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);

	_filp_cachep = kmem_cache_create("_filp", sizeof(struct _file), 0,
					 SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);

	dcache_init(mempages);
	inode_init(mempages);
	files_init(mempages);
	mnt_init(mempages);
	bdev_cache_init();
	chrdev_init();
}

/**
 *	dget, dget_locked	-	get a reference to a dentry
 *	@dentry: dentry to get a reference to
 *
 *	Given a dentry or %NULL pointer increment the reference count
 *	if appropriate and return the dentry. A dentry will not be 
 *	destroyed when it has references. dget() should never be
 *	called for dentries with zero reference counter. For these cases
 *	(preferably none, functions in dcache.c are sufficient for normal
 *	needs and they take necessary precautions) you should hold dcache_lock
 *	and call dget_locked() instead of dget().
 */
 
struct dentry *dget(struct dentry *dentry)
{
	if (dentry) {
		BUG_ON(!atomic_read(&dentry->d_count));
		tx_atomic_inc(&dentry->d_count);
		return dentry;
	}
	return dentry;
}

EXPORT_SYMBOL(d_alloc);
EXPORT_SYMBOL(d_alloc_anon);
EXPORT_SYMBOL(d_alloc_root);
EXPORT_SYMBOL(d_delete);
EXPORT_SYMBOL(d_find_alias);
EXPORT_SYMBOL(d_instantiate);
EXPORT_SYMBOL(d_invalidate);
EXPORT_SYMBOL(d_lookup);
EXPORT_SYMBOL(d_move);
EXPORT_SYMBOL_GPL(d_materialise_unique);
EXPORT_SYMBOL(d_path);
EXPORT_SYMBOL(d_prune_aliases);
EXPORT_SYMBOL(d_rehash);
EXPORT_SYMBOL(d_splice_alias);
EXPORT_SYMBOL(d_validate);
EXPORT_SYMBOL(dget_locked);
EXPORT_SYMBOL(dget);
EXPORT_SYMBOL(dput_core);
EXPORT_SYMBOL(find_inode_number);
EXPORT_SYMBOL(have_submounts);
EXPORT_SYMBOL(names_cachep);
EXPORT_SYMBOL(shrink_dcache_parent);
EXPORT_SYMBOL(shrink_dcache_sb);
