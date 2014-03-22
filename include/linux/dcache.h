#ifndef __LINUX_DCACHE_H
#define __LINUX_DCACHE_H

#ifdef __KERNEL__

#include <asm/atomic.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/cache.h>
#include <linux/rcupdate.h>
#include <linux/tx_list.h>
#include <linux/tx_list2.h>

struct nameidata;
struct vfsmount;
struct _inode;

/*
 * linux/include/linux/dcache.h
 *
 * Dirent cache data structures
 *
 * (C) Copyright 1997 Thomas Schoebel-Theuer,
 * with heavy changes by Linus Torvalds
 */

#define IS_ROOT(x) (parent(x) == (x)->d_parent)

/*
 * "quick string" -- eases parameter passing, but more importantly
 * saves "metadata" about the string (ie length and the hash).
 *
 * hash comes first so it snuggles against d_parent in the
 * dentry.
 */
struct qstr {
	unsigned int hash;
	unsigned int len;
	const unsigned char *name;
};

struct dentry_stat_t {
	int nr_dentry;
	int nr_unused;
	int age_limit;          /* age in seconds */
	int want_pages;         /* pages requested by system */
	int dummy[2];
};
extern struct dentry_stat_t dentry_stat;

/* Name hashing routines. Initial hash value */
/* Hash courtesy of the R5 hash in reiserfs modulo sign bits */
#define init_name_hash()		0

/* partial hash update function. Assume roughly 4 bits per character */
static inline unsigned long
partial_name_hash(unsigned long c, unsigned long prevhash)
{
	return (prevhash + (c << 4) + (c >> 4)) * 11;
}

/*
 * Finally: cut down the number of bits to a int value (and try to avoid
 * losing bits)
 */
static inline unsigned long end_name_hash(unsigned long hash)
{
	return (unsigned int) hash;
}

/* Compute the hash for a name string. */
static inline unsigned int
full_name_hash(const unsigned char *name, unsigned int len)
{
	unsigned long hash = init_name_hash();
	while (len--)
		hash = partial_name_hash(*name++, hash);
	return end_name_hash(hash);
}

struct dcookie_struct;

#define DNAME_INLINE_LEN_MIN 36

struct _dentry {
	unsigned int d_flags;		/* protected by d_lock */
	struct inode *d_inode;		/* Where the name belongs to - NULL is
					 * negative */
		/*
	 * The next three fields are touched by __d_lookup.  Place them here
	 * so they all fit in a cache line.
	 */
	struct dentry *d_parent;	/* parent directory */
	struct qstr d_name;
	unsigned long d_time;		/* used by d_revalidate */
	struct dentry_operations *d_op;

#ifdef CONFIG_PROFILING
	struct dcookie_struct *d_cookie; /* cookie, if any */
#endif
	struct dentry           *parent; /* Stable counterpart */
#ifdef CONFIG_TX_KSTM
	struct _dentry          *shadow; /* Null if committed, pointer to stable otherwise */
	enum access_mode        rw;        /* Only used if speculative */
	atomic_t                tx_refcount; /* How many tx are currently using this */
	atomic_t                tx_readcount; /* How many tx are read-sharing this */
	struct rcu_head         _d_rcu; /* Deferred deletion, for ro, non-tx fields  */
#endif	
	unsigned char d_iname[DNAME_INLINE_LEN_MIN];	/* small names */	
};

struct dentry {
	tx_atomic_t d_count;
	spinlock_t d_lock;		/* per dentry lock */

	struct list_head d_lru; 	/* LRU list */
	struct super_block *d_sb;	/* The root of the dentry tree */

	struct tx_list2_head d_subdirs;	/* our children */
	struct tx_list2_entry_ref d_child; /* child of parent list */

	struct tx_list2_entry_ref d_alias; /* inode alias list */

	//struct tx_hlist_node d_hash;	/* lookup hash list */
	struct tx_list2_entry_ref d_hash;  /* lookup hash list */


	/*
	 * d_child and d_rcu can share memory
	 * DEP: Not in the TX case
	 */
	//union {
	struct rcu_head d_rcu;
	//} d_u;

	void *d_fsdata;			/* fs-specific data */
	int d_mounted;

	struct _dentry           *d_contents; /* Committed state */
#ifdef CONFIG_TX_KSTM
	struct transactional_object xobj; /* Transactional bookkeeping */
#endif
};

/*
 * dentry->d_lock spinlock nesting subclasses:
 *
 * 0: normal
 * 1: nested
 */
enum dentry_d_lock_class
{
	DENTRY_D_LOCK_NORMAL, /* implicitly used by plain spin_lock() APIs. */
	DENTRY_D_LOCK_NESTED
};

struct dentry_operations {
	int (*d_revalidate)(struct _dentry *, struct nameidata *);
	int (*d_hash) (struct dentry *, struct qstr *);
	int (*d_compare) (struct dentry *, struct qstr *, struct qstr *);
	int (*d_delete)(struct _dentry *);
	void (*d_release)(struct dentry *);
	void (*d_iput)(struct dentry *, struct inode *);
	char *(*d_dname)(const struct _dentry *, char *, int);
};

/* the dentry parameter passed to d_hash and d_compare is the parent
 * directory of the entries to be compared. It is used in case these
 * functions need any directory specific information for determining
 * equivalency classes.  Using the dentry itself might not work, as it
 * might be a negative dentry which has no information associated with
 * it */

/*
locking rules:
		big lock	dcache_lock	d_lock   may block
d_revalidate:	no		no		no       yes
d_hash		no		no		no       yes
d_compare:	no		yes		yes      no
d_delete:	no		yes		no       no
d_release:	no		no		no       yes
d_iput:		no		no		no       yes
 */

/* d_flags entries */
#define DCACHE_AUTOFS_PENDING 0x0001    /* autofs: "under construction" */
#define DCACHE_NFSFS_RENAMED  0x0002    /* this dentry has been "silly
					 * renamed" and has to be
					 * deleted on the last dput()
					 */
#define	DCACHE_DISCONNECTED 0x0004
     /* This dentry is possibly not currently connected to the dcache tree,
      * in which case its parent will either be itself, or will have this
      * flag as well.  nfsd will not use a dentry with this bit set, but will
      * first endeavour to clear the bit either by discovering that it is
      * connected, or by performing lookup operations.   Any filesystem which
      * supports nfsd_operations MUST have a lookup function which, if it finds
      * a directory inode with a DCACHE_DISCONNECTED dentry, will d_move
      * that dentry into place and return that dentry rather than the passed one,
      * typically using d_splice_alias.
      */

#define DCACHE_REFERENCED	0x0008  /* Recently used, don't discard. */
#define DCACHE_UNHASHED		0x0010	

#define DCACHE_INOTIFY_PARENT_WATCHED	0x0020 /* Parent inode is watched */
#define DCACHE_SPECULATIVE_CREATE 0x0080 /* Speculative creation */

extern spinlock_t dcache_lock;

#ifdef CONFIG_TX_KSTM

static inline void __dspin_lock(struct dentry *dentry, enum access_mode mode){
	struct transaction *winner = NULL;
	check_int();

	/* Never lock a dentry in a transaction, except explicitly in tx code */
	if(live_transaction()){
		if(atomic_read(&current->transaction->task_count) > 1){
			spin_lock(&dentry->d_lock);
			record_tx_lock(&dentry->d_lock, SPIN_LOCK);
		}
		return;
	}

	spin_lock(&dentry->d_lock);
	
	// Must kick out transactions with the lock held so
	// that we don't have a race
	while((atomic_read(&tx_count) != 0)
	      && inactive_transaction()
	      && (winner = 
		  check_asymmetric_conflict(&dentry->xobj, mode, 
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



static inline void dspin_unlock(struct dentry *dentry){

	check_int();
	/* Never lock a dentry in a transaction, except explicitly in tx code */
	if(live_transaction()){
		if(atomic_read(&current->transaction->task_count) > 1){
			spin_unlock(&dentry->d_lock);
			record_tx_unlock(&dentry->d_lock, SPIN_LOCK);
		}
		return;
	}

	spin_unlock(&dentry->d_lock);
}

#define dspin_lock(dentry) __dspin_lock(dentry, ACCESS_RW)
#define dspin_lock_ro(dentry) __dspin_lock(dentry, ACCESS_R)

#else

#define dspin_lock(dentry, mode) spin_lock(&dentry->d_lock)
#define dspin_unlock(dentry) spin_unlock(&dentry->d_lock)

#endif

/**
 * d_drop - drop a dentry
 * @dentry: dentry to drop
 *
 * d_drop() unhashes the entry from the parent dentry hashes, so that it won't
 * be found through a VFS lookup any more. Note that this is different from
 * deleting the dentry - d_delete will try to mark the dentry negative if
 * possible, giving a successful _negative_ lookup, while d_drop will
 * just make the cache lookup fail.
 *
 * d_drop() is used mainly for stuff that wants to invalidate a dentry for some
 * reason (NFS timeouts or autofs deletes).
 *
 * __d_drop requires dentry->d_lock.
 */

static void __d_drop(struct _dentry *dentry)
{
	if (!(dentry->d_flags & DCACHE_UNHASHED)) {
		dentry->d_flags |= DCACHE_UNHASHED;
		tx_list2_del(&parent(dentry)->d_hash);
	}
}

static inline void d_drop(struct _dentry *dentry)
{
	spin_lock(&dcache_lock);
	dspin_lock(parent(dentry));
 	__d_drop(dentry);
	dspin_unlock(parent(dentry));
	spin_unlock(&dcache_lock);
}

static inline int dname_external(struct _dentry *dentry)
{
	return dentry->d_name.name != dentry->d_iname;
}

/*
 * These are the low-level FS interfaces to the dcache..
 */
extern void d_instantiate(struct _dentry *, struct _inode *);
extern struct _dentry * d_instantiate_unique(struct _dentry *, struct _inode *);
extern struct _dentry * d_materialise_unique(struct _dentry *, struct _inode *);
extern void d_delete(struct _dentry *);

/* allocate/de-allocate */
extern struct dentry * d_alloc(struct _dentry *, const struct qstr *);
extern struct dentry * d_alloc_anon(struct _inode *);
extern struct _dentry * d_splice_alias(struct _inode *, struct _dentry *);
extern void shrink_dcache_sb(struct super_block *);
extern void shrink_dcache_parent(struct dentry *);
extern void shrink_dcache_for_umount(struct super_block *);
extern int d_invalidate(struct _dentry *);

/* only used at mount-time */
extern struct dentry * d_alloc_root(struct _inode *);

/* <clickety>-<click> the ramfs-type tree */
extern void d_genocide(struct _dentry *);

extern struct _dentry *d_find_alias(struct _inode *);
extern void d_prune_aliases(struct _inode *);

/* test whether we have any submounts in a subdir tree */
extern int have_submounts(struct dentry *);

/*
 * This adds the entry to the hash queues.
 */
extern void d_rehash(struct _dentry *);

/**
 * d_add - add dentry to hash queues
 * @entry: dentry to add
 * @inode: The inode to attach to this dentry
 *
 * This adds the entry to the hash queues and initializes @inode.
 * The entry was actually filled in earlier during d_alloc().
 */
 
static inline void d_add(struct _dentry *entry, struct _inode *inode)
{
	d_instantiate(entry, inode);
	d_rehash(entry);
}

/**
 * d_add_unique - add dentry to hash queues without aliasing
 * @entry: dentry to add
 * @inode: The inode to attach to this dentry
 *
 * This adds the entry to the hash queues and initializes @inode.
 * The entry was actually filled in earlier during d_alloc().
 */
static inline struct _dentry *d_add_unique(struct _dentry *entry, struct _inode *inode)
{
	struct _dentry *res;

	res = d_instantiate_unique(entry, inode);
	d_rehash(res != NULL ? res : entry);
	return res;
}

/* used for rename() and baskets */
extern void d_move(struct _dentry *, struct _dentry *);

/* appendix may either be NULL or be used for transname suffixes */
extern struct _dentry * d_lookup(struct _dentry **, struct qstr *);
extern struct _dentry * __d_lookup(struct _dentry **, struct qstr *);
extern struct _dentry * d_hash_and_lookup(struct _dentry **, struct qstr *);

/* validate "insecure" dentry pointer */
extern int d_validate(struct _dentry *, struct _dentry *);

/*
 * helper function for dentry_operations.d_dname() members
 */
extern char *dynamic_dname(const struct _dentry *, char *, int, const char *, ...);

extern char * d_path(const struct _dentry *, struct vfsmount *, char *, int);
  
/* Allocation counts.. */

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
 
extern struct dentry *dget(struct dentry *dentry);

extern struct dentry * dget_locked(struct dentry *);

/**
 *	d_unhashed -	is dentry hashed
 *	@dentry: entry to check
 *
 *	Returns true if the dentry passed is not currently hashed.
 */
 
static inline int d_unhashed(const struct _dentry *dentry)
{
	return (dentry->d_flags & DCACHE_UNHASHED);
}

static inline struct dentry *dget_parent(struct _dentry *dentry)
{
	struct dentry *ret;

	dspin_lock(parent(dentry));
	ret = dget(dentry->d_parent);
	dspin_unlock(parent(dentry));
	return ret;
}

extern void dput_core(struct dentry *);
#define dput(dentry) dput_core(dentry)

static inline int d_mountpoint(const struct dentry *dentry)
{
	return dentry->d_mounted;
}

extern struct vfsmount *lookup_mnt(struct vfsmount *, struct dentry *);
extern struct vfsmount *__lookup_mnt(struct vfsmount *, struct dentry *, int);
extern struct _dentry *lookup_create(struct nameidata *nd, int is_dir);

extern int sysctl_vfs_cache_pressure;

#endif /* __KERNEL__ */

#endif	/* __LINUX_DCACHE_H */
