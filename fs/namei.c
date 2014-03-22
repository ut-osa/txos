/*
 *  linux/fs/namei.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * Some corrections by tytso.
 */

/* [Feb 1997 T. Schoebel-Theuer] Complete rewrite of the pathname
 * lookup logic.
 */
/* [Feb-Apr 2000, AV] Rewrite to the new namespace architecture.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/quotaops.h>
#include <linux/pagemap.h>
#include <linux/fsnotify.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/namei.h>
#include <asm/namei.h>
#include <asm/uaccess.h>
#include <linux/tx_inodes.h>
#include <linux/tx_dentry.h>
#include <linux/tx_super.h>
#include <linux/osamagic.h>
#include <linux/tx_file.h>

#define ACC_MODE(x) ("\000\004\002\006"[(x)&O_ACCMODE])

/* [Feb-1997 T. Schoebel-Theuer]
 * Fundamental changes in the pathname lookup mechanisms (namei)
 * were necessary because of omirr.  The reason is that omirr needs
 * to know the _real_ pathname, not the user-supplied one, in case
 * of symlinks (and also when transname replacements occur).
 *
 * The new code replaces the old recursive symlink resolution with
 * an iterative one (in case of non-nested symlink chains).  It does
 * this with calls to <fs>_follow_link().
 * As a side effect, dir_namei(), _namei() and follow_link() are now 
 * replaced with a single function lookup_dentry() that can handle all 
 * the special cases of the former code.
 *
 * With the new dcache, the pathname is stored at each inode, at least as
 * long as the refcount of the inode is positive.  As a side effect, the
 * size of the dcache depends on the inode cache and thus is dynamic.
 *
 * [29-Apr-1998 C. Scott Ananian] Updated above description of symlink
 * resolution to correspond with current state of the code.
 *
 * Note that the symlink resolution is not *completely* iterative.
 * There is still a significant amount of tail- and mid- recursion in
 * the algorithm.  Also, note that <fs>_readlink() is not used in
 * lookup_dentry(): lookup_dentry() on the result of <fs>_readlink()
 * may return different results than <fs>_follow_link().  Many virtual
 * filesystems (including /proc) exhibit this behavior.
 */

/* [24-Feb-97 T. Schoebel-Theuer] Side effects caused by new implementation:
 * New symlink semantics: when open() is called with flags O_CREAT | O_EXCL
 * and the name already exists in form of a symlink, try to create the new
 * name indicated by the symlink. The old code always complained that the
 * name already exists, due to not following the symlink even if its target
 * is nonexistent.  The new semantics affects also mknod() and link() when
 * the name is a symlink pointing to a non-existant name.
 *
 * I don't know which semantics is the right one, since I have no access
 * to standards. But I found by trial that HP-UX 9.0 has the full "new"
 * semantics implemented, while SunOS 4.1.1 and Solaris (SunOS 5.4) have the
 * "old" one. Personally, I think the new semantics is much more logical.
 * Note that "ln old new" where "new" is a symlink pointing to a non-existing
 * file does succeed in both HP-UX and SunOs, but not in Solaris
 * and in the old Linux semantics.
 */

/* [16-Dec-97 Kevin Buhr] For security reasons, we change some symlink
 * semantics.  See the comments in "open_namei" and "do_link" below.
 *
 * [10-Sep-98 Alan Modra] Another symlink change.
 */

/* [Feb-Apr 2000 AV] Complete rewrite. Rules for symlinks:
 *	inside the path - always follow.
 *	in the last component in creation/removal/renaming - never follow.
 *	if LOOKUP_FOLLOW passed - follow.
 *	if the pathname has trailing slashes - follow.
 *	otherwise - don't follow.
 * (applied in that order).
 *
 * [Jun 2000 AV] Inconsistent behaviour of open() in case if flags==O_CREAT
 * restored for 2.4. This is the last surviving part of old 4.2BSD bug.
 * During the 2.4 we need to fix the userland stuff depending on it -
 * hopefully we will be able to get rid of that wart in 2.5. So far only
 * XEmacs seems to be relying on it...
 */
/*
 * [Sep 2001 AV] Single-semaphore locking scheme (kudos to David Holland)
 * implemented.  Let's see if raised priority of ->s_vfs_rename_mutex gives
 * any extra contention...
 */

/* In order to reduce some races, while at the same time doing additional
 * checking and hopefully speeding things up, we copy filenames to the
 * kernel data space before using them..
 *
 * POSIX.1 2.4: an empty pathname is invalid (ENOENT).
 * PATH_MAX includes the nul terminator --RR.
 */
static int do_getname(const char __user *filename, char *page)
{
	int retval;
	unsigned long len = PATH_MAX;

	if (!segment_eq(get_fs(), KERNEL_DS)) {
		if ((unsigned long) filename >= TASK_SIZE)
			return -EFAULT;
		if (TASK_SIZE - (unsigned long) filename < PATH_MAX)
			len = TASK_SIZE - (unsigned long) filename;
	}

	retval = strncpy_from_user(page, filename, len);
	if (retval > 0) {
		if (retval < len)
			return 0;
		return -ENAMETOOLONG;
	} else if (!retval)
		retval = -ENOENT;
	return retval;
}

char * getname(const char __user * filename)
{
	char *tmp, *result;

	result = ERR_PTR(-ENOMEM);
	tmp = __getname();
	if (tmp)  {
		int retval = do_getname(filename, tmp);

		result = tmp;
		if (retval < 0) {
			__putname(tmp);
			result = ERR_PTR(retval);
		}
	}
	audit_getname(result);
	return result;
}

#ifdef CONFIG_AUDITSYSCALL
void putname(const char *name)
{
	if (unlikely(!audit_dummy_context()))
		audit_putname(name);
	else
		__putname(name);
}
EXPORT_SYMBOL(putname);
#endif


/**
 * generic_permission  -  check for access rights on a Posix-like filesystem
 * @inode:	inode to check access rights for
 * @mask:	right to check for (%MAY_READ, %MAY_WRITE, %MAY_EXEC)
 * @check_acl:	optional callback to check for Posix ACLs
 *
 * Used to check for read/write/execute permissions on a file.
 * We use "fsuid" for this, letting us set arbitrary permissions
 * for filesystem access without changing the "normal" uids which
 * are used for other things..
 */
int generic_permission(const struct _inode *inode, int mask,
		int (*check_acl)(const struct _inode *inode, int mask))
{
	umode_t			mode = inode->i_mode;

	if (current->fsuid == inode->i_uid)
		mode >>= 6;
	else {
		if (IS_POSIXACL(inode) && (mode & S_IRWXG) && check_acl) {
			int error = check_acl(inode, mask);
			if (error == -EACCES)
				goto check_capabilities;
			else if (error != -EAGAIN)
				return error;
		}

		if (in_group_p(inode->i_gid))
			mode >>= 3;
	}

	/*
	 * If the DACs are ok we don't need any capability check.
	 */
	if (((mode & mask & (MAY_READ|MAY_WRITE|MAY_EXEC)) == mask))
		return 0;

 check_capabilities:
	/*
	 * Read/write DACs are always overridable.
	 * Executable DACs are overridable if at least one exec bit is set.
	 */
	if (!(mask & MAY_EXEC) ||
	    (inode->i_mode & S_IXUGO) || S_ISDIR(inode->i_mode))
		if (capable(CAP_DAC_OVERRIDE))
			return 0;

	/*
	 * Searching includes executable on directories, else just read.
	 */
	if (mask == MAY_READ || (S_ISDIR(inode->i_mode) && !(mask & MAY_WRITE)))
		if (capable(CAP_DAC_READ_SEARCH))
			return 0;

	return -EACCES;
}

int permission(const struct _inode *inode, int mask, struct nameidata *nd)
{
	umode_t mode = inode->i_mode;
	int retval, submask;

	if (mask & MAY_WRITE) {

		/*
		 * Nobody gets write access to a read-only fs.
		 */
		if (IS_RDONLY(inode) &&
		    (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)))
			return -EROFS;

		/*
		 * Nobody gets write access to an immutable file.
		 */
		if (IS_IMMUTABLE(inode))
			return -EACCES;
	}


	/*
	 * MAY_EXEC on regular files requires special handling: We override
	 * filesystem execute permissions if the mode bits aren't set or
	 * the fs is mounted with the "noexec" flag.
	 */
	if ((mask & MAY_EXEC) && S_ISREG(mode) && (!(mode & S_IXUGO) ||
			(nd && nd->mnt && (nd->mnt->mnt_flags & MNT_NOEXEC))))
		return -EACCES;

	/* Ordinary permission routines do not understand MAY_APPEND. */
	submask = mask & ~MAY_APPEND;
	if (inode->i_op && inode->i_op->permission)
		retval = inode->i_op->permission(inode, submask, nd);
	else
		retval = generic_permission(inode, submask, NULL);
	if (retval)
		return retval;

	return security_inode_permission(inode, mask, nd);
}

/**
 * vfs_permission  -  check for access rights to a given path
 * @nd:		lookup result that describes the path
 * @mask:	right to check for (%MAY_READ, %MAY_WRITE, %MAY_EXEC)
 *
 * Used to check for read/write/execute permissions on a path.
 * We use "fsuid" for this, letting us set arbitrary permissions
 * for filesystem access without changing the "normal" uids which
 * are used for other things.
 */
int vfs_permission(const struct _inode *inode, struct nameidata *nd, int mask)
{
	return permission(inode, mask, nd);
}

/**
 * file_permission  -  check for additional access rights to a given file
 * @file:	file to check access rights for
 * @mask:	right to check for (%MAY_READ, %MAY_WRITE, %MAY_EXEC)
 *
 * Used to check for read/write/execute permissions on an already opened
 * file.
 *
 * Note:
 *	Do not use this function in new code.  All access checks should
 *	be done using vfs_permission().
 */
int file_permission(struct file *file, int mask)
{
	return permission(d_get_inode(file_get_dentry(file)), mask, NULL);
}

/*
 * get_write_access() gets write permission for a file.
 * put_write_access() releases this write permission.
 * This is used for regular files.
 * We cannot support write (and maybe mmap read-write shared) accesses and
 * MAP_DENYWRITE mmappings simultaneously. The i_writecount field of an inode
 * can have the following values:
 * 0: no writers, no VM_DENYWRITE mappings
 * < 0: (-i_writecount) vm_area_structs with VM_DENYWRITE set exist
 * > 0: (i_writecount) users are writing to the file.
 *
 * Normally we operate on that counter with atomic_{inc,dec} and it's safe
 * except for the cases where we don't hold i_writecount yet. Then we need to
 * use {get,deny}_write_access() - these functions check the sign and refuse
 * to do the change if sign is wrong. Exclusion between them is provided by
 * the inode->i_lock spinlock.
 */

int get_write_access(struct inode * inode)
{
	/* No need for conflict detection here.  The writecount isn't
	 * versioned.
	 */
	spin_lock(&inode->i_lock);
	if (atomic_read(&inode->i_writecount) < 0) {
		spin_unlock(&inode->i_lock);
		return -ETXTBSY;
	}
	tx_atomic_inc(&inode->i_writecount);
	spin_unlock(&inode->i_lock);

	return 0;
}

void put_write_access(struct inode * inode)
{
	tx_atomic_dec(&inode->i_writecount);
}

int deny_write_access(struct file * file)
{
	struct _inode *_inode = d_get_inode(file_get_dentry(file));
	struct inode *inode = parent(_inode);
	/* No need for conflict detection here.  The writecount isn't
	 * versioned.
	 */
	spin_lock(&inode->i_lock);
	if (atomic_read(&inode->i_writecount) > 0) {
		spin_unlock(&inode->i_lock);
		return -ETXTBSY;
	}
	tx_atomic_dec(&inode->i_writecount);
	spin_unlock(&inode->i_lock);

	return 0;
}

void allow_write_access(struct file *file)
{
	if (file){
		struct _inode *_inode = d_get_inode_ro(file_get_dentry_ro(file));
		struct inode *inode = parent(_inode);
		
		tx_atomic_inc(&inode->i_writecount);
	}
}


void path_release(struct nameidata *nd)
{
	dput(parent(nd->dentry));
	mntput(nd->mnt);
}

/*
 * umount() mustn't call path_release()/mntput() as that would clear
 * mnt_expiry_mark
 */
void path_release_on_umount(struct nameidata *nd)
{
	dput(parent(nd->dentry));
	mntput_no_expire(nd->mnt);
}

/**
 * release_open_intent - free up open intent resources
 * @nd: pointer to nameidata
 */
void release_open_intent(struct nameidata *nd)
{
	if (tx_cache_get_file_ro(nd->intent.open.file)->f_path.dentry == NULL){
		/* This is essentially an error path, where we create
		 * an empty fd and add it to our workset.  For some
		 * reason the open didn't succeed, so drop the
		 * uninitialized fd from our workset. 
		 */
		if(live_transaction())
			early_release(&nd->intent.open.file->xobj, 1);
		put_filp(nd->intent.open.file);
	} else
		fput(nd->intent.open.file);
}

static inline struct _dentry *
do_revalidate(struct _dentry *dentry, struct nameidata *nd)
{
	int status = dentry->d_op->d_revalidate(dentry, nd);
	if (unlikely(status <= 0)) {
		/*
		 * The dentry failed validation.
		 * If d_revalidate returned 0 attempt to invalidate
		 * the dentry otherwise d_revalidate is asking us
		 * to return a fail status.
		 */
		if (!status) {
			if (!d_invalidate(dentry)) {
				dput(parent(dentry));
				dentry = NULL;
			}
		} else {
			dput(parent(dentry));
			dentry = ERR_PTR(status);
		}
	}
	return dentry;
}

/*
 * Internal lookup() using the new generic dcache.
 * SMP-safe
 */
static struct _dentry * cached_lookup(struct _dentry ** parent, struct qstr * name, struct nameidata *nd)
{
	struct _dentry * dentry = __d_lookup(parent, name);

	/* lockess __d_lookup may fail due to concurrent d_move() 
	 * in some unrelated directory, so try with d_lookup
	 */
	if (!dentry)
		dentry = d_lookup(parent, name);

	if (dentry && dentry->d_op && dentry->d_op->d_revalidate)
		dentry = do_revalidate(dentry, nd);

	return dentry;
}

/*
 * Short-cut version of permission(), for calling by
 * path_walk(), when dcache lock is held.  Combines parts
 * of permission() and generic_permission(), and tests ONLY for
 * MAY_EXEC permission.
 *
 * If appropriate, check DAC only.  If not appropriate, or
 * short-cut DAC fails, then call permission() to do more
 * complete permission check.
 */
static int exec_permission_lite(struct _inode *inode,
				struct nameidata *nd)
{
	umode_t	mode = inode->i_mode;

	if (inode->i_op && inode->i_op->permission)
		return -EAGAIN;

	if (current->fsuid == inode->i_uid)
		mode >>= 6;
	else if (in_group_p(inode->i_gid))
		mode >>= 3;

	if (mode & MAY_EXEC)
		goto ok;

	if ((inode->i_mode & S_IXUGO) && capable(CAP_DAC_OVERRIDE))
		goto ok;

	if (S_ISDIR(inode->i_mode) && capable(CAP_DAC_OVERRIDE))
		goto ok;

	if (S_ISDIR(inode->i_mode) && capable(CAP_DAC_READ_SEARCH))
		goto ok;

	return -EACCES;
ok:
	return security_inode_permission(inode, MAY_EXEC, nd);
}

/*
 * This is called when everything else fails, and we actually have
 * to go to the low-level filesystem to find out what we should do..
 *
 * We get the directory semaphore, and after getting that we also
 * make sure that nobody added the entry to the dcache in the meantime..
 * SMP-safe
 */
static struct _dentry * real_lookup(struct _dentry ** parent, struct qstr * name, struct nameidata *nd)
{
	struct _dentry * result;
	struct _inode *dir = d_get_inode_ro(*parent);
	struct inode *dirp = parent(dir);

	imutex_lock(dirp);
	/*
	 * First re-do the cached lookup just in case it was created
	 * while we waited for the directory semaphore..
	 *
	 * FIXME! This could use version numbering or similar to
	 * avoid unnecessary cache lookups.
	 *
	 * The "dcache_lock" is purely to protect the RCU list walker
	 * from concurrent renames at this point (we mustn't get false
	 * negatives from the RCU list walk here, unlike the optimistic
	 * fast walk).
	 *
	 * so doing d_lookup() (with seqlock), instead of lockfree __d_lookup
	 */
	result = d_lookup(parent, name);
	if(unlikely(IS_ERR(result))) return result;

	if (!result) {
		struct dentry * dentry = d_alloc(*parent, name);
		result = ERR_PTR(-ENOMEM);
		if (dentry) {
			struct _dentry *_dentry = tx_cache_get_dentry(dentry);
			/* XXX: lookup can sleep, so we should
			 * revalidate this _dentry */
			struct dentry *nd_dentry = parent(nd->dentry);
			enum access_mode rw = nd->dentry->rw;
			struct dentry *parentp = parent(*parent);
			enum access_mode parent_rw = (*parent)->rw;
			/* dir needs to be rw here */
			dir = tx_cache_get_inode(dirp);
			result = dir->i_op->lookup(dir, _dentry, nd);
			nd->dentry = rw == ACCESS_R 
				? tx_cache_get_dentry_ro(nd_dentry)
				: tx_cache_get_dentry(nd_dentry);
			*parent = parent_rw == ACCESS_R 
				? tx_cache_get_dentry_ro(parentp)
				: tx_cache_get_dentry(parentp);

			if (result)
				dput(dentry);
			else
				result = _dentry;
		}
		imutex_unlock(dirp);
		return result;
	}

	/*
	 * Uhhuh! Nasty case: the cache was re-populated while
	 * we waited on the semaphore. Need to revalidate.
	 */
	imutex_unlock(dirp);
	if (result->d_op && result->d_op->d_revalidate) {
		result = do_revalidate(result, nd);
		if (!result)
			result = ERR_PTR(-ENOENT);
	}
	return result;
}

static int __emul_lookup_dentry(const char *, struct nameidata *);

/* SMP-safe */
static __always_inline int
walk_init_root(const char *name, struct nameidata *nd)
{
	struct fs_struct *fs = current->fs;

	read_lock(&fs->lock);
	record_tx_lock(&fs->lock, READ_LOCK);
	if (fs->altroot && !(nd->flags & LOOKUP_NOALT)) {
		nd->mnt = mntget(fs->altrootmnt);
		nd->dentry = tx_cache_get_dentry(dget(fs->altroot));
		read_unlock(&fs->lock);
		record_tx_unlock(&fs->lock, READ_LOCK);
		if (__emul_lookup_dentry(name,nd))
			return 0;
		read_lock(&fs->lock);
		record_tx_lock(&fs->lock, READ_LOCK);
	}
	nd->mnt = mntget(fs->rootmnt);
	nd->dentry = tx_cache_get_dentry(dget(fs->root));
	read_unlock(&fs->lock);
	record_tx_unlock(&fs->lock, READ_LOCK);
	return 1;
}

static __always_inline int __vfs_follow_link(struct nameidata *nd, const char *link)
{
	int res = 0;
	char *name;
	if (IS_ERR(link))
		goto fail;

	if (*link == '/') {
		path_release(nd);
		if (!walk_init_root(link, nd))
			/* weird __emul_prefix() stuff did it */
			goto out;
	}
	res = link_path_walk(link, nd);
out:
	if (nd->depth || res || nd->last_type!=LAST_NORM)
		return res;
	/*
	 * If it is an iterative symlinks resolution in open_namei() we
	 * have to copy the last component. And all that crap because of
	 * bloody create() on broken symlinks. Furrfu...
	 */
	name = __getname();
	if (unlikely(!name)) {
		path_release(nd);
		return -ENOMEM;
	}
	strcpy(name, nd->last.name);
	nd->last.name = name;
	return 0;
fail:
	path_release(nd);
	return PTR_ERR(link);
}

static inline void dput_path(struct path *path, struct nameidata *nd)
{
	dput(path->dentry);
	if (path->mnt != nd->mnt)
		mntput(path->mnt);
}

static inline void path_to_nameidata(struct path *path, struct nameidata *nd)
{
	dput(parent(nd->dentry));
	if (nd->mnt != path->mnt)
		mntput(nd->mnt);
	nd->mnt = path->mnt;
	nd->dentry = tx_cache_get_dentry_ro(path->dentry);
}

static __always_inline int __do_follow_link(struct path *path, struct nameidata *nd)
{
	int error;
	void *cookie;
	struct _dentry *dentry = tx_cache_get_dentry(path->dentry);
	struct _inode *_inode = d_get_inode_ro(dentry);
	touch_atime(path->mnt, dentry);
	nd_set_link(nd, NULL);

	if (path->mnt != nd->mnt) {
		path_to_nameidata(path, nd);
		dget(parent(dentry));
	}
	mntget(path->mnt);
	cookie = _inode->i_op->follow_link(dentry, nd);
	error = PTR_ERR(cookie);
	if (!IS_ERR(cookie)) {
		char *s = nd_get_link(nd);
		error = 0;
		if (s)
			error = __vfs_follow_link(nd, s);
		if (_inode->i_op->put_link)
			_inode->i_op->put_link(dentry, nd, cookie);
	}
	dput(parent(dentry));
	mntput(path->mnt);

	return error;
}

/*
 * This limits recursive symlink follows to 8, while
 * limiting consecutive symlinks to 40.
 *
 * Without that kind of total limit, nasty chains of consecutive
 * symlinks can cause almost arbitrarily long lookups. 
 */
static inline int do_follow_link(struct path *path, struct nameidata *nd)
{
	int err = -ELOOP;
	if (current->link_count >= MAX_NESTED_LINKS)
		goto loop;
	if (current->total_link_count >= 40)
		goto loop;
	BUG_ON(nd->depth >= MAX_NESTED_LINKS);
	cond_resched();
	err = security_inode_follow_link(path->dentry, nd);
	if (err)
		goto loop;
	current->link_count++;
	current->total_link_count++;
	nd->depth++;
	err = __do_follow_link(path, nd);
	current->link_count--;
	nd->depth--;
	return err;
loop:
	dput_path(path, nd);
	path_release(nd);
	return err;
}

int follow_up(struct vfsmount **mnt, struct dentry **dentry)
{
	struct vfsmount *parent;
	struct dentry *mountpoint;
	spin_lock(&vfsmount_lock);
	record_tx_lock(&vfsmount_lock, SPIN_LOCK);
	parent=(*mnt)->mnt_parent;
	if (parent == *mnt) {
		spin_unlock(&vfsmount_lock);
		record_tx_unlock(&vfsmount_lock, SPIN_LOCK);
		return 0;
	}
	mntget(parent);
	mountpoint=dget((*mnt)->mnt_mountpoint);
	spin_unlock(&vfsmount_lock);
	record_tx_unlock(&vfsmount_lock, SPIN_LOCK);
	dput(*dentry);
	*dentry = mountpoint;
	mntput(*mnt);
	*mnt = parent;
	return 1;
}

/* no need for dcache_lock, as serialization is taken care in
 * namespace.c
 */
static int __follow_mount(struct path *path)
{
	int res = 0;
	while (d_mountpoint(path->dentry)){
		struct vfsmount *mounted = lookup_mnt(path->mnt, path->dentry);
		if (!mounted)
			break;
		dput(path->dentry);
		if (res)
			mntput(path->mnt);
		path->mnt = mounted;
		path->dentry = dget(mounted->mnt_root);
		res = 1;
	}
	return res;
}

static void follow_mount(struct vfsmount **mnt, struct _dentry **dentry)
{
	while (d_mountpoint(parent(*dentry))) {
		struct vfsmount *mounted = lookup_mnt(*mnt, parent(*dentry));
		if (!mounted)
			break;
		dput(parent(*dentry));
		mntput(*mnt);
		*mnt = mounted;
		*dentry = tx_cache_get_dentry_ro(dget(mounted->mnt_root));
	}
}

/* no need for dcache_lock, as serialization is taken care in
 * namespace.c
 */
int follow_down(struct vfsmount **mnt, struct dentry **dentry)
{
	struct vfsmount *mounted;

	mounted = lookup_mnt(*mnt, *dentry);
	if (mounted) {
		dput(*dentry);
		mntput(*mnt);
		*mnt = mounted;
		*dentry = dget(mounted->mnt_root);
		return 1;
	}
	return 0;
}

static __always_inline void follow_dotdot(struct nameidata *nd)
{
	struct fs_struct *fs = current->fs;

	while(1) {
		struct vfsmount *parent;
		struct _dentry *old = nd->dentry;

                read_lock(&fs->lock);
		record_tx_lock(&fs->lock, READ_LOCK);
		if (parent(nd->dentry) == fs->root &&
		    nd->mnt == fs->rootmnt) {
                        read_unlock(&fs->lock);
			break;
		}
                read_unlock(&fs->lock);
		record_tx_unlock(&fs->lock, READ_LOCK);
		spin_lock(&dcache_lock);
		record_tx_lock(&dcache_lock, SPIN_LOCK);
		if (parent(nd->dentry) != nd->mnt->mnt_root) {
			nd->dentry = tx_cache_get_dentry(dget(nd->dentry->d_parent));
			spin_unlock(&dcache_lock);
			record_tx_unlock(&dcache_lock, SPIN_LOCK);
			dput(parent(old));
			break;
		}
		spin_unlock(&dcache_lock);
		record_tx_unlock(&dcache_lock, SPIN_LOCK);
		spin_lock(&vfsmount_lock);
		record_tx_lock(&vfsmount_lock, SPIN_LOCK);
		parent = nd->mnt->mnt_parent;
		if (parent == nd->mnt) {
			spin_unlock(&vfsmount_lock);
			record_tx_unlock(&vfsmount_lock, SPIN_LOCK);
			break;
		}
		mntget(parent);
		nd->dentry = tx_cache_get_dentry(dget(nd->mnt->mnt_mountpoint));
		spin_unlock(&vfsmount_lock);
		record_tx_unlock(&vfsmount_lock, SPIN_LOCK);
		dput(parent(old));
		mntput(nd->mnt);
		nd->mnt = parent;
	}
	follow_mount(&nd->mnt, &nd->dentry);
}

/*
 *  It's more convoluted than I'd like it to be, but... it's still fairly
 *  small and for now I'd prefer to have fast path as straight as possible.
 *  It _is_ time-critical.
 */
static int do_lookup(struct nameidata *nd, struct qstr *name,
		     struct path *path)
{
	struct vfsmount *mnt = nd->mnt;
	struct _dentry *dentry = __d_lookup(&nd->dentry, name);

	if (!dentry)
		goto need_lookup;
	if (IS_ERR(dentry))
		goto fail;
	if (dentry->d_op && dentry->d_op->d_revalidate)
		goto need_revalidate;
done:
	path->mnt = mnt;
	path->dentry = parent(dentry);
	__follow_mount(path);
	return 0;

need_lookup:
	dentry = real_lookup(&nd->dentry, name, nd);

	if (IS_ERR(dentry))
		goto fail;
	goto done;

need_revalidate:
	dentry = do_revalidate(dentry, nd);

	if (!dentry)
		goto need_lookup;
	if (IS_ERR(dentry))
		goto fail;
	goto done;

fail:
	return PTR_ERR(dentry);
}

/*
 * Name resolution.
 * This is the basic name resolution function, turning a pathname into
 * the final dentry. We expect 'base' to be positive and a directory.
 *
 * Returns 0 and nd will have valid dentry and mnt on success.
 * Returns error and drops reference to input namei data on failure.
 */
static fastcall int __link_path_walk(const char * name, struct nameidata *nd)
{
	struct path next;
	struct _inode *inode;
	int err;
	unsigned int lookup_flags = nd->flags;

	while (*name=='/')
		name++;
	if (!*name)
		goto return_reval;

	/* XXX: Should be able to assume this is already a tx obj */
	inode = d_get_inode_ro(nd->dentry);

	if (nd->depth)
		lookup_flags = LOOKUP_FOLLOW | (nd->flags & LOOKUP_CONTINUE);

	/* At this point we know we have a real path component. */
	for(;;) {
		unsigned long hash;
		struct qstr this;
		unsigned int c;

		nd->flags |= LOOKUP_CONTINUE;
		err = exec_permission_lite(inode, nd);

		if (err == -EAGAIN) {
			err = vfs_permission(inode, nd, MAY_EXEC);
		}

 		if (err)
			break;

		this.name = name;
		c = *(const unsigned char *)name;

		hash = init_name_hash();
		do {
			name++;
			hash = partial_name_hash(c, hash);
			c = *(const unsigned char *)name;
		} while (c && (c != '/'));
		this.len = name - (const char *) this.name;
		this.hash = end_name_hash(hash);

		/* remove trailing slashes? */
		if (!c)
			goto last_component;
		while (*++name == '/');
		if (!*name)
			goto last_with_slashes;

		/*
		 * "." and ".." are special - ".." especially so because it has
		 * to be able to know about the current root directory and
		 * parent relationships.
		 */
		if (this.name[0] == '.') switch (this.len) {
			default:
				break;
			case 2:	
				if (this.name[1] != '.')
					break;
				follow_dotdot(nd);
				inode = d_get_inode_ro(nd->dentry);
				//assert_shadow(nd->mnt);
				/* fallthrough */
			case 1:
				continue;
		}
		/*
		 * See if the low-level filesystem might want
		 * to use its own hash..
		 */
		if (nd->dentry->d_op && nd->dentry->d_op->d_hash) {
			err = nd->dentry->d_op->d_hash(parent(nd->dentry), &this);
			if (err < 0)
				break;
		}

		/* This does the actual lookups.. */
		err = do_lookup(nd, &this, &next);
		if (err)
			break;

		//assert_shadow(nd->mnt);

		err = -ENOENT;
		inode = dentry_get_inode_ro(next.dentry);
		if (!inode) 
			goto out_dput;

		err = -ENOTDIR; 
		if (!inode->i_op)
			goto out_dput;

		if (inode->i_op->follow_link) {
			err = do_follow_link(&next, nd);
			if (err)
				goto return_err;

			err = -ENOENT;
			inode = d_get_inode_ro(nd->dentry);
			if (!inode)
				break;

			err = -ENOTDIR; 
			if (!inode->i_op)
				break;
		} else
			path_to_nameidata(&next, nd);

		//assert_shadow(nd->mnt);
		err = -ENOTDIR; 
		if (!inode->i_op->lookup)
			break;
		continue;
		/* here ends the main loop */

last_with_slashes:
		lookup_flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
last_component:
		/* Clear LOOKUP_CONTINUE iff it was previously unset */
		nd->flags &= lookup_flags | ~LOOKUP_CONTINUE;
		if (lookup_flags & LOOKUP_PARENT)
			goto lookup_parent;
		if (this.name[0] == '.') switch (this.len) {
			default:
				break;
			case 2:	
				if (this.name[1] != '.')
					break;
				follow_dotdot(nd);
				//assert_shadow(nd->mnt);
				inode = d_get_inode_ro(nd->dentry);
				/* fallthrough */
			case 1:
				goto return_reval;
		}
		if (nd->dentry->d_op && nd->dentry->d_op->d_hash) {
			err = nd->dentry->d_op->d_hash(parent(nd->dentry), &this);
			if (err < 0)
				break;
		}
		err = do_lookup(nd, &this, &next);
		//assert_shadow(nd->mnt);

		if (err)
			break;

		inode = dentry_get_inode_ro(next.dentry);

		if ((lookup_flags & LOOKUP_FOLLOW)
		    && inode && inode->i_op && inode->i_op->follow_link) {
			err = do_follow_link(&next, nd);
			if (err)
				goto return_err;

			inode = d_get_inode_ro(nd->dentry);
		} else 
			path_to_nameidata(&next, nd);

		//assert_shadow(nd->mnt);

		err = -ENOENT;
		if (!inode)
			break;

		if (lookup_flags & LOOKUP_DIRECTORY) {
			err = -ENOTDIR; 
			if (!inode->i_op || !inode->i_op->lookup)
				break;
		}
		goto return_base;
lookup_parent:
		nd->last = this;
		nd->last_type = LAST_NORM;
		if (this.name[0] != '.')
			goto return_base;
		if (this.len == 1)
			nd->last_type = LAST_DOT;
		else if (this.len == 2 && this.name[1] == '.')
			nd->last_type = LAST_DOTDOT;
		else
			goto return_base;
return_reval:
		/*
		 * We bypassed the ordinary revalidation routines.
		 * We may need to check the cached dentry for staleness.
		 */
		if (nd->dentry && parent(nd->dentry)->d_sb &&
		    (parent(nd->dentry)->d_sb->s_type->fs_flags & FS_REVAL_DOT)) {
			err = -ESTALE;
			/* Note: we do not d_invalidate() */
			if (!nd->dentry->d_op->d_revalidate(nd->dentry, nd))
				break;
		}
return_base:
		return 0;
out_dput:
		dput_path(&next, nd);
		break;
	}
	path_release(nd);
return_err:
	return err;
}

/*
 * Wrapper to retry pathname resolution whenever the underlying
 * file system returns an ESTALE.
 *
 * Retry the whole path once, forcing real lookup requests
 * instead of relying on the dcache.
 */
int fastcall link_path_walk(const char *name, struct nameidata *nd)
{
	struct nameidata save = *nd;
	int result;
	struct dentry * save_parent = parent(save.dentry);

	/* make sure the stuff we saved doesn't go away */
	dget(save_parent);
	mntget_ro(save.mnt);

	result = __link_path_walk(name, nd);
	if (result == -ESTALE) {
		*nd = save;
		dget(parent(nd->dentry));
		mntget(nd->mnt);
		nd->flags |= LOOKUP_REVAL;
		result = __link_path_walk(name, nd);
	}

	dput(save_parent);
	mntput(save.mnt);

	return result;
}

int fastcall path_walk(const char * name, struct nameidata *nd)
{
	current->total_link_count = 0;
	return link_path_walk(name, nd);
}

/* 
 * SMP-safe: Returns 1 and nd will have valid dentry and mnt, if
 * everything is done. Returns 0 and drops input nd, if lookup failed;
 */
static int __emul_lookup_dentry(const char *name, struct nameidata *nd)
{
	struct _inode *_inode;

	if (path_walk(name, nd))
		return 0;		/* something went wrong... */

	_inode = d_get_inode_ro(nd->dentry);
	if (!_inode || S_ISDIR(_inode->i_mode)) {
		struct _dentry *old_dentry = nd->dentry;
		struct vfsmount *old_mnt = nd->mnt;
		struct qstr last = nd->last;
		int last_type = nd->last_type;
		struct fs_struct *fs = current->fs;

		/*
		 * NAME was not found in alternate root or it's a directory.
		 * Try to find it in the normal root:
		 */
		nd->last_type = LAST_ROOT;
		read_lock(&fs->lock);
		record_tx_lock(&fs->lock, READ_LOCK);
		nd->mnt = mntget(fs->rootmnt);
		nd->dentry = tx_cache_get_dentry(dget(fs->root));
		read_unlock(&fs->lock);
		record_tx_unlock(&fs->lock, READ_LOCK);
		if (path_walk(name, nd) == 0) {
			if (nd->dentry->d_inode) {
				dput(parent(old_dentry));
				mntput(old_mnt);
				return 1;
			}
			path_release(nd);
		}
		nd->dentry = old_dentry;
		nd->mnt = old_mnt;
		nd->last = last;
		nd->last_type = last_type;
	}
	return 1;
}

void set_fs_altroot(void)
{
	char *emul = __emul_prefix();
	struct nameidata nd;
	struct vfsmount *mnt = NULL, *oldmnt;
	struct dentry *dentry = NULL, *olddentry;
	int err;
	struct fs_struct *fs = tx_cache_get_fs(current);

	if (!emul)
		goto set_it;
	err = path_lookup(emul, LOOKUP_FOLLOW|LOOKUP_DIRECTORY|LOOKUP_NOALT, &nd);
	if (!err) {
		mnt = nd.mnt;
		dentry = parent(nd.dentry);
	}
set_it:
	write_lock(&fs->lock);
	record_tx_lock(&fs->lock, WRITE_LOCK);
	oldmnt = fs->altrootmnt;
	olddentry = fs->altroot;
	fs->altrootmnt = mnt;
	fs->altroot = dentry;
	write_unlock(&fs->lock);
	record_tx_unlock(&fs->lock, WRITE_LOCK);
	if (olddentry) {
		dput(olddentry);
		mntput(oldmnt);
	}
}

/* Returns 0 and nd will be valid on success; Retuns error, otherwise. */
static int fastcall do_path_lookup(int dfd, const char *name,
				unsigned int flags, struct nameidata *nd)
{
	int retval = 0;
	int fput_needed;
	struct file *file;
	/* DEP: Doesn't seem that I need to transactionalize the
	 * fs_struct for now.
	 * ARB: Wrapper function tx_cache_get_fs not necessary since
	 * no writing occurs. current->fs is updated eagerly.
	 */
	struct fs_struct *fs = current->fs;

	nd->last_type = LAST_ROOT; /* if there are only slashes... */
	nd->flags = flags;
	nd->depth = 0;

	if (*name=='/') {
		read_lock(&fs->lock);
		record_tx_lock(&fs->lock, READ_LOCK);
		if (fs->altroot && !(nd->flags & LOOKUP_NOALT)) {
			nd->mnt = mntget_ro(fs->altrootmnt);
			nd->dentry = tx_cache_get_dentry(dget(fs->altroot));
			read_unlock(&fs->lock);
			record_tx_unlock(&fs->lock, READ_LOCK);
			if (__emul_lookup_dentry(name,nd))
				goto out; /* found in altroot */
			read_lock(&fs->lock);
			record_tx_lock(&fs->lock, READ_LOCK);
		}
		nd->mnt = mntget_ro(fs->rootmnt);
		nd->dentry = tx_cache_get_dentry_ro(dget(fs->root));
		read_unlock(&fs->lock);
		record_tx_unlock(&fs->lock, READ_LOCK);
	} else if (dfd == AT_FDCWD) {
		read_lock(&fs->lock);
		record_tx_lock(&fs->lock, READ_LOCK);
		nd->mnt = mntget_ro(fs->pwdmnt);
		nd->dentry = tx_cache_get_dentry_ro(dget(fs->pwd));
		read_unlock(&fs->lock);
		record_tx_unlock(&fs->lock, READ_LOCK);
	} else {
		struct dentry *dentry;
		struct _file *_file;

		file = fget_light(dfd, &fput_needed);
		retval = -EBADF;
		if (!file)
			goto out_fail;

		_file = tx_cache_get_file_ro(file);
		dentry = _file->f_path.dentry;

		retval = -ENOTDIR;
		if (!S_ISDIR(dentry_get_inode(dentry)->i_mode))
			goto fput_fail;

		retval = file_permission(file, MAY_EXEC);
		if (retval)
			goto fput_fail;

		nd->mnt = mntget_ro(_file->f_path.mnt);
		nd->dentry = tx_cache_get_dentry_ro(dget(dentry));

		fput_light(file, fput_needed);
	}

	//assert_shadow(nd->mnt);

	retval = path_walk(name, nd);
out:
        /* DEP: 10/31/08: Direct check ok here, only seeing if
	 * non-null pointer value.  Still get tx version in audit call.
	 * By defult this is a nop anyway.
	 */
	if (unlikely(!retval && !audit_dummy_context() && nd->dentry
		     && nd->dentry->d_inode))
		audit_inode(name, nd->dentry);
out_fail:
	return retval;

fput_fail:
	fput_light(file, fput_needed);
	goto out_fail;
}

int fastcall path_lookup(const char *name, unsigned int flags,
			struct nameidata *nd)
{
	return do_path_lookup(AT_FDCWD, name, flags, nd);
}

static int __path_lookup_intent_open(int dfd, const char *name,
		unsigned int lookup_flags, struct nameidata *nd,
		int open_flags, int create_mode)
{
	struct file *filp = get_empty_filp();
	int err;

	if (filp == NULL)
		return -ENFILE;
	nd->intent.open.file = filp;
	nd->intent.open.flags = open_flags;
	nd->intent.open.create_mode = create_mode;
	err = do_path_lookup(dfd, name, lookup_flags|LOOKUP_OPEN, nd);
	if (IS_ERR(nd->intent.open.file)) {
		if (err == 0) {
			err = PTR_ERR(nd->intent.open.file);
			path_release(nd);
		}
	} else if (err != 0)
		release_open_intent(nd);
	return err;
}

/**
 * path_lookup_open - lookup a file path with open intent
 * @dfd: the directory to use as base, or AT_FDCWD
 * @name: pointer to file name
 * @lookup_flags: lookup intent flags
 * @nd: pointer to nameidata
 * @open_flags: open intent flags
 */
int path_lookup_open(int dfd, const char *name, unsigned int lookup_flags,
		struct nameidata *nd, int open_flags)
{
	return __path_lookup_intent_open(dfd, name, lookup_flags, nd,
			open_flags, 0);
}

/**
 * path_lookup_create - lookup a file path with open + create intent
 * @dfd: the directory to use as base, or AT_FDCWD
 * @name: pointer to file name
 * @lookup_flags: lookup intent flags
 * @nd: pointer to nameidata
 * @open_flags: open intent flags
 * @create_mode: create intent flags
 */
static int path_lookup_create(int dfd, const char *name,
			      unsigned int lookup_flags, struct nameidata *nd,
			      int open_flags, int create_mode)
{
	return __path_lookup_intent_open(dfd, name, lookup_flags|LOOKUP_CREATE,
			nd, open_flags, create_mode);
}

int __user_path_lookup_open(const char __user *name, unsigned int lookup_flags,
		struct nameidata *nd, int open_flags)
{
	char *tmp = getname(name);
	int err = PTR_ERR(tmp);

	if (!IS_ERR(tmp)) {
		err = __path_lookup_intent_open(AT_FDCWD, tmp, lookup_flags, nd, open_flags, 0);
		putname(tmp);
	}
	return err;
}

static inline struct _dentry *__lookup_hash_kern(struct qstr *name, struct _dentry **base, struct nameidata *nd)
{
	struct _dentry *dentry;
	struct _inode *inode;
	int err;

	inode = d_get_inode(*base);

	/*
	 * See if the low-level filesystem might want
	 * to use its own hash..
	 */
	if ((*base)->d_op && (*base)->d_op->d_hash) {
		err = (*base)->d_op->d_hash(parent(*base), name);
		dentry = ERR_PTR(err);
		if (err < 0)
			goto out;
	}

	dentry = cached_lookup(base, name, nd);
	if (!dentry) {
		struct dentry *new = d_alloc(*base, name);
		struct _dentry *_new;
		dentry = ERR_PTR(-ENOMEM);
		if (!new)
			goto out;
		_new = tx_cache_get_dentry(new);
		dentry = inode->i_op->lookup(inode, _new, nd);
		if (!dentry)
			dentry = _new;
		else
			dput(new);
	}
out:
	return dentry;
}

/*
 * Restricted form of lookup. Doesn't follow links, single-component only,
 * needs parent already locked. Doesn't follow mounts.
 * SMP-safe.
 */
static inline struct _dentry * __lookup_hash(struct qstr *name, struct _dentry **base, struct nameidata *nd)
{
	struct _dentry *dentry;
	struct _inode *inode;
	int err;

	inode = d_get_inode(*base);

	err = permission(inode, MAY_EXEC, nd);
	dentry = ERR_PTR(err);
	if (err)
		goto out;

	dentry = __lookup_hash_kern(name, base, nd);
out:
	return dentry;
}

static struct _dentry *lookup_hash(struct nameidata *nd)
{
	return __lookup_hash(&nd->last, &nd->dentry, nd);
}

/* SMP-safe */
static inline int __lookup_one_len(const char *name, struct qstr *this, struct _dentry *base, int len)
{
	unsigned long hash;
	unsigned int c;

	this->name = name;
	this->len = len;
	if (!len)
		return -EACCES;

	hash = init_name_hash();
	while (len--) {
		c = *(const unsigned char *)name++;
		if (c == '/' || c == '\0')
			return -EACCES;
		hash = partial_name_hash(c, hash);
	}
	this->hash = end_name_hash(hash);
	return 0;
}

struct _dentry *lookup_one_len(const char *name, struct _dentry **base, int len)
{
	int err;
	struct qstr this;

	err = __lookup_one_len(name, &this, *base, len);
	if (err)
		return ERR_PTR(err);
	return __lookup_hash(&this, base, NULL);
}

struct _dentry *lookup_one_len_kern(const char *name, struct _dentry **base, int len)
{
	int err;
	struct qstr this;

	err = __lookup_one_len(name, &this, *base, len);
	if (err)
		return ERR_PTR(err);
	return __lookup_hash_kern(&this, base, NULL);
}

int fastcall __user_walk_fd(int dfd, const char __user *name, unsigned flags,
			    struct nameidata *nd)
{
	char *tmp = getname(name);
	int err = PTR_ERR(tmp);

	if (!IS_ERR(tmp)) {
		err = do_path_lookup(dfd, tmp, flags, nd);
		putname(tmp);
	}
	return err;
}

int fastcall __user_walk(const char __user *name, unsigned flags, struct nameidata *nd)
{
	return __user_walk_fd(AT_FDCWD, name, flags, nd);
}

/*
 * It's inline, so penalty for filesystems that don't use sticky bit is
 * minimal.
 */
static inline int check_sticky(struct _inode *dir, struct _inode *inode)
{
	if (!(dir->i_mode & S_ISVTX))
		return 0;
	if (inode->i_uid == current->fsuid)
		return 0;
	if (dir->i_uid == current->fsuid)
		return 0;
	return !capable(CAP_FOWNER);
}

/*
 *	Check whether we can remove a link victim from directory dir, check
 *  whether the type of victim is right.
 *  1. We can't do it if dir is read-only (done in permission())
 *  2. We should have write and exec permissions on dir
 *  3. We can't remove anything from append-only dir
 *  4. We can't do anything with immutable dir (done in permission())
 *  5. If the sticky bit on dir is set we should either
 *	a. be owner of dir, or
 *	b. be owner of victim, or
 *	c. have CAP_FOWNER capability
 *  6. If the victim is append-only or immutable we can't do antyhing with
 *     links pointing to it.
 *  7. If we were asked to remove a directory and victim isn't one - ENOTDIR.
 *  8. If we were asked to remove a non-directory and victim isn't one - EISDIR.
 *  9. We can't remove a root or mountpoint.
 * 10. We don't allow removal of NFS sillyrenamed files; it's handled by
 *     nfs_async_unlink().
 */
static int may_delete(struct _inode *dir, struct _dentry *victim, int isdir)
{
	int error;
	struct _inode *_victim_inode;

	if (!victim->d_inode)
		return -ENOENT;

	/* DP 12/19/08: Regular kernel BUG_ON, but why pull the parent into our workset? */
	KSTM_BUG_ON(tx_cache_get_dentry(victim->d_parent)->d_inode != parent(dir));
	audit_inode_child(victim->d_name.name, victim->d_inode, parent(dir));

	_victim_inode = d_get_inode(victim);

	error = permission(dir,MAY_WRITE | MAY_EXEC, NULL);
	if (error)
		return error;
	if (IS_APPEND(dir))
		return -EPERM;
	if (check_sticky(dir, _victim_inode)||IS_APPEND(_victim_inode)||
	    IS_IMMUTABLE(_victim_inode))
		return -EPERM;
	if (isdir) {
		if (!S_ISDIR(_victim_inode->i_mode))
			return -ENOTDIR;
		if (IS_ROOT(victim))
			return -EBUSY;
	} else if (S_ISDIR(_victim_inode->i_mode))
		return -EISDIR;
	if (IS_DEADDIR(dir))
		return -ENOENT;
	if (victim->d_flags & DCACHE_NFSFS_RENAMED)
		return -EBUSY;
	return 0;
}

/*	Check whether we can create an object with dentry child in directory
 *  dir.
 *  1. We can't do it if child already exists (open has special treatment for
 *     this case, but since we are inlined it's OK)
 *  2. We can't do it if dir is read-only (done in permission())
 *  3. We should have write and exec permissions on dir
 *  4. We can't do it if dir is immutable (done in permission())
 */
static inline int may_create(struct _inode *dir, const struct _dentry *child,
			     struct nameidata *nd)
{
	if (child->d_inode)
		return -EEXIST;
	if (IS_DEADDIR(dir))
		return -ENOENT;
	return permission(dir,MAY_WRITE | MAY_EXEC, nd);
}

/* 
 * O_DIRECTORY translates into forcing a directory lookup.
 */
static inline int lookup_flags(unsigned int f)
{
	unsigned long retval = LOOKUP_FOLLOW;

	if (f & O_NOFOLLOW)
		retval &= ~LOOKUP_FOLLOW;
	
	if (f & O_DIRECTORY)
		retval |= LOOKUP_DIRECTORY;

	return retval;
}

/*
 * p1 and p2 should be directories on the same fs.
 */
struct _dentry *lock_rename(struct _dentry *p1, struct _dentry *p2)
{
	struct _dentry * p;
	struct _inode *i1, *i2;

	i1 = d_get_inode(p1);

	if (p1 == p2) {
		_imutex_lock_nested(i1, I_MUTEX_PARENT);
		return NULL;
	}

	mutex_lock(&i1->i_sb->s_vfs_rename_mutex);

	i2 = d_get_inode(p2);

	for (p = p1; p->d_parent != parent(p); p = tx_cache_get_dentry_ro(p->d_parent)) {
		if (p->d_parent == parent(p2)) {
#ifdef CONFIG_TX_KSTM_LOCK_ORDERING
			inode_double_lock(parent(i1), parent(i2));
#else
			_imutex_lock_nested(i2, I_MUTEX_PARENT);
			_imutex_lock_nested(i1, I_MUTEX_CHILD);
#endif
			return p;
		}
	}

	for (p = p2; p->d_parent != parent(p); p = tx_cache_get_dentry_ro(p->d_parent)) {
		if (p->d_parent == parent(p1)) {
#ifdef CONFIG_TX_KSTM_LOCK_ORDERING
			inode_double_lock(parent(i1), parent(i2));
#else
			_imutex_lock_nested(i1, I_MUTEX_PARENT);
			_imutex_lock_nested(i2, I_MUTEX_CHILD);
#endif
			return p;
		}
	}
	_imutex_lock_nested(i1, I_MUTEX_PARENT);
	_imutex_lock_nested(i2, I_MUTEX_CHILD);

	return NULL;
}


void unlock_rename(struct _dentry *p1, struct _dentry *p2)
{
	struct _inode *i1 = d_get_inode(p1);
	struct _inode *i2 = d_get_inode(p2);

	_imutex_unlock(i1);
	if (p1 != p2) {
		_imutex_unlock(i2);
		mutex_unlock(&i1->i_sb->s_vfs_rename_mutex);
	}
}

int vfs_create(struct _inode *dir, struct _dentry *dentry, int mode,
		struct nameidata *nd)
{
	int error = may_create(dir, dentry, nd);

	if (error)
		return error;

	if (!dir->i_op || !dir->i_op->create)
		return -EACCES;	/* shouldn't it be ENOSYS? */
	mode &= S_IALLUGO;
	mode |= S_IFREG;
	error = security_inode_create(dir, dentry, mode);
	if (error)
		return error;

	/* Upgrade to RW mode */
	if(live_transaction()){
		dentry = tx_cache_get_dentry(parent(dentry));
		dir = tx_cache_get_inode(parent(dir));
	} else {
		upgrade_imutex_write(parent(dir));
	}

	DQUOT_INIT(dir);
	error = dir->i_op->create(dir, dentry, mode, nd);
	if(live_transaction())
		dentry->d_flags |= DCACHE_SPECULATIVE_CREATE;

	if (!error)
		fsnotify_create(parent(dir), parent(dentry));
	return error;
}

int may_open(struct nameidata *nd, int acc_mode, int flag)
{
	struct _dentry *dentry = nd->dentry;
	struct _inode *inode = d_get_inode(dentry);
	int error;

	if (!inode)
		return -ENOENT;

	if (S_ISLNK(inode->i_mode))
		return -ELOOP;
	
	if (S_ISDIR(inode->i_mode) && (flag & FMODE_WRITE))
		return -EISDIR;

	error = vfs_permission(inode, nd, acc_mode);
	if (error)
		return error;

	/*
	 * FIFO's, sockets and device files are special: they don't
	 * actually live on the filesystem itself, and as such you
	 * can write to them even if the filesystem is read-only.
	 */
	if (S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode)) {
	    	flag &= ~O_TRUNC;
	} else if (S_ISBLK(inode->i_mode) || S_ISCHR(inode->i_mode)) {
		if (nd->mnt->mnt_flags & MNT_NODEV)
			return -EACCES;

		flag &= ~O_TRUNC;
	} else if (IS_RDONLY(inode) && (flag & FMODE_WRITE))
		return -EROFS;
	/*
	 * An append-only file must be opened in append mode for writing.
	 */
	if (IS_APPEND(inode)) {
		if  ((flag & FMODE_WRITE) && !(flag & O_APPEND))
			return -EPERM;
		if (flag & O_TRUNC)
			return -EPERM;
	}

	/* O_NOATIME can only be set by the owner or superuser */
	if (flag & O_NOATIME)
		if (current->fsuid != inode->i_uid && !capable(CAP_FOWNER))
			return -EPERM;

	/*
	 * Ensure there are no outstanding leases on the file.
	 */
	error = break_lease(parent(inode), flag);
	if (error)
		return error;

	if (flag & O_TRUNC) {
		error = get_write_access(parent(inode));
		if (error)
			return error;

		/*
		 * Refuse to truncate files with mandatory locks held on them.
		 */
		error = locks_verify_locked(inode);
		if (!error) {
			DQUOT_INIT(inode);
			
			error = do_truncate(dentry, 0, ATTR_MTIME|ATTR_CTIME, NULL);
		}
		put_write_access(parent(inode));
		if (error)
			return error;
	} else
		if (flag & FMODE_WRITE)
			DQUOT_INIT(inode);

	return 0;
}

static int open_namei_create(struct nameidata *nd, struct path *path,
				int flag, int mode)
{
	int error;
	struct _dentry *dir = nd->dentry;
	struct _inode *_inode = d_get_inode(dir);
	struct _dentry *path_dentry = tx_cache_get_dentry(path->dentry);

	if (!IS_POSIXACL(_inode))
		mode &= ~current->fs->umask;
	error = vfs_create(_inode, path_dentry, mode, nd);
	_imutex_unlock(_inode);
	dput(parent(nd->dentry));
	nd->dentry = path_dentry;
	if (error)
		return error;
	/* Don't check for write permission, don't truncate */
	return may_open(nd, 0, flag & ~O_TRUNC);
}

/*
 *	open_namei()
 *
 * namei for open - this is in fact almost the whole open-routine.
 *
 * Note that the low bits of "flag" aren't the same as in the open
 * system call - they are 00 - no permissions needed
 *			  01 - read permission needed
 *			  10 - write permission needed
 *			  11 - read/write permissions needed
 * which is a lot more logical, and also allows the "no perm" needed
 * for symlinks (where the permissions are checked later).
 * SMP-safe
 */
int open_namei(int dfd, const char *pathname, int flag,
		int mode, struct nameidata *nd)
{
	int acc_mode, error;
	struct path path;
	struct _dentry *dir, *path_dentry;
	struct _inode *inode;
	int count = 0;

	acc_mode = ACC_MODE(flag);

	/* O_TRUNC implies we need access checks for write permissions */
	if (flag & O_TRUNC)
		acc_mode |= MAY_WRITE;

	/* Allow the LSM permission hook to distinguish append 
	   access from general write access. */
	if (flag & O_APPEND)
		acc_mode |= MAY_APPEND;

	/*
	 * The simplest case - just a plain lookup.
	 */
	if (!(flag & O_CREAT)) {
		error = path_lookup_open(dfd, pathname, lookup_flags(flag),
					 nd, flag);
		if (error)
			return error;
		goto ok;
	}

	/*
	 * Create - we need to know the parent.
	 */
	error = path_lookup_create(dfd,pathname,LOOKUP_PARENT,nd,flag,mode);
	if (error)
		return error;

	/*
	 * We have the parent and last component. First of all, check
	 * that we are not asked to creat(2) an obvious directory - that
	 * will not do.
	 */
	error = -EISDIR;
	if (nd->last_type != LAST_NORM || nd->last.name[nd->last.len])
		goto exit;

	dir = nd->dentry;
	nd->flags &= ~LOOKUP_PARENT;
	imutex_lock(dir->d_inode);
	path_dentry = lookup_hash(nd);
	if(unlikely(IS_ERR(path_dentry)))
		path.dentry = (struct dentry *)path_dentry;
	else
		path.dentry = parent(path_dentry);
	path.mnt = nd->mnt;

do_last:
	error = PTR_ERR(path.dentry);
	if (IS_ERR(path.dentry)) {
		imutex_unlock(dir->d_inode);
		goto exit;
	}

	if (IS_ERR(nd->intent.open.file)) {
		imutex_unlock(dir->d_inode);
		error = PTR_ERR(nd->intent.open.file);
		goto exit_dput;
	}

	/* Negative dentry, just create the file */
	if (!path_dentry->d_inode) {
		error = open_namei_create(nd, &path, flag, mode);
		if (error)
			goto exit;
		return 0;
	}

	/*
	 * It already exists.
	 */
	imutex_unlock(dir->d_inode);
	audit_inode(pathname, path_dentry->d_inode);

	error = -EEXIST;
	if (flag & O_EXCL)
		goto exit_dput;

	if (__follow_mount(&path)) {
		error = -ELOOP;
		if (flag & O_NOFOLLOW)
			goto exit_dput;
	}

	/* __follow_mount can change the path's dentry */
	path_dentry = tx_cache_get_dentry_ro(path.dentry);

	error = -ENOENT;
	if (!path_dentry->d_inode)
		goto exit_dput;
	inode = d_get_inode(path_dentry);
	if (inode->i_op && inode->i_op->follow_link)
		goto do_link;

	path_to_nameidata(&path, nd);
	error = -EISDIR;
	// Just in case we changed in the path_to_nameidata
	inode = dentry_get_inode(path.dentry);
	if (inode && S_ISDIR(inode->i_mode))
		goto exit;
ok:
	error = may_open(nd, acc_mode, flag);
	if (error)
		goto exit;
	return 0;

exit_dput:
	dput_path(&path, nd);
exit:
	if (!IS_ERR(nd->intent.open.file))
		release_open_intent(nd);
	path_release(nd);
	return error;

do_link:
	error = -ELOOP;
	if (flag & O_NOFOLLOW)
		goto exit_dput;
	/*
	 * This is subtle. Instead of calling do_follow_link() we do the
	 * thing by hands. The reason is that this way we have zero link_count
	 * and path_walk() (called from ->follow_link) honoring LOOKUP_PARENT.
	 * After that we have the parent and last component, i.e.
	 * we are in the same situation as after the first path_walk().
	 * Well, almost - if the last component is normal we get its copy
	 * stored in nd->last.name and we will have to putname() it when we
	 * are done. Procfs-like symlinks just set LAST_BIND.
	 */
	nd->flags |= LOOKUP_PARENT;
	error = security_inode_follow_link(path.dentry, nd);
	if (error)
		goto exit_dput;
	error = __do_follow_link(&path, nd);
	if (error) {
		/* Does someone understand code flow here? Or it is only
		 * me so stupid? Anathema to whoever designed this non-sense
		 * with "intent.open".
		 */
		release_open_intent(nd);
		return error;
	}
	nd->flags &= ~LOOKUP_PARENT;
	if (nd->last_type == LAST_BIND)
		goto ok;
	error = -EISDIR;
	if (nd->last_type != LAST_NORM)
		goto exit;
	if (nd->last.name[nd->last.len]) {
		__putname(nd->last.name);
		goto exit;
	}
	error = -ELOOP;
	if (count++==32) {
		__putname(nd->last.name);
		goto exit;
	}
	dir = nd->dentry;
	imutex_lock(dir->d_inode);
	path.dentry = parent(lookup_hash(nd));
	path.mnt = nd->mnt;
	__putname(nd->last.name);
	goto do_last;
}

/**
 * lookup_create - lookup a dentry, creating it if it doesn't exist
 * @nd: nameidata info
 * @is_dir: directory flag
 *
 * Simple function to lookup and return a dentry and create it
 * if it doesn't exist.  Is SMP-safe.
 *
 * Returns with nd->dentry->d_inode->i_mutex locked.
 */
struct _dentry *lookup_create(struct nameidata *nd, int is_dir)
{
	struct _dentry *dentry = ERR_PTR(-EEXIST);
	struct _inode *inode = d_get_inode(nd->dentry);

	// Make sure inode is good
	if(unlikely(IS_ERR(inode))){
		return ERR_PTR(PTR_ERR(inode));
	}

	_imutex_lock_nested_ro(inode, I_MUTEX_PARENT);
	/*
	 * Yucky last component or no last component at all?
	 * (foo/., foo/.., /////)
	 */
	if (nd->last_type != LAST_NORM)
		goto fail;
	nd->flags &= ~LOOKUP_PARENT;
	nd->flags |= LOOKUP_CREATE;
	nd->intent.open.flags = O_EXCL;

	/*
	 * Do the final lookup.
	 */
	dentry = lookup_hash(nd);
	if (IS_ERR(dentry))
		goto fail;
	
	/*
	 * Special case - lookup gave negative, but... we had foo/bar/
	 * From the vfs_mknod() POV we just have a negative dentry -
	 * all is fine. Let's be bastards - you had / on the end, you've
	 * been asking for (non-existent) directory. -ENOENT for you.
	 */
	if (!is_dir && nd->last.name[nd->last.len] && !d_get_inode_ro(dentry))
		goto enoent;

	return dentry;
enoent:
	dput(parent(dentry));
	dentry = ERR_PTR(-ENOENT);
fail:
	return dentry;
}
EXPORT_SYMBOL_GPL(lookup_create);

int vfs_mknod(struct _inode *dir, struct _dentry *dentry, int mode, dev_t dev)
{
	int error = may_create(dir, dentry, NULL);

	if (error)
		return error;

	if ((S_ISCHR(mode) || S_ISBLK(mode)) && !capable(CAP_MKNOD))
		return -EPERM;

	if (!dir->i_op || !dir->i_op->mknod)
		return -EPERM;

	error = security_inode_mknod(dir, dentry, mode, dev);
	if (error)
		return error;

	/* Upgrade to RW mode */
	if(live_transaction()){
		dentry = tx_cache_get_dentry(parent(dentry));
		dir = tx_cache_get_inode(parent(dir));
	} else {
		upgrade_imutex_write(parent(dir));
	}


	DQUOT_INIT(dir);
	error = dir->i_op->mknod(dir, dentry, mode, dev);
	if(live_transaction())
		dentry->d_flags |= DCACHE_SPECULATIVE_CREATE;

	if (!error)
		fsnotify_create(parent(dir), parent(dentry));
	return error;
}

asmlinkage long sys_mknodat(int dfd, const char __user *filename, int mode,
				unsigned dev)
{
	int error = 0;
	char * tmp;
	struct _dentry * dentry;
	struct nameidata nd;
	struct _inode *inode;

	if (S_ISDIR(mode))
		return -EPERM;
	tmp = getname(filename);
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);

	error = do_path_lookup(dfd, tmp, LOOKUP_PARENT, &nd);
	if (error)
		goto out;

	inode = d_get_inode(nd.dentry);
	if(unlikely(IS_ERR(inode))){
		error = PTR_ERR(inode);
		goto out;
	}
	dentry = lookup_create(&nd, 0);
	error = PTR_ERR(dentry);

	if (!IS_POSIXACL(inode))
		mode &= ~current->fs->umask;
	if (!IS_ERR(dentry)) {
		switch (mode & S_IFMT) {
		case 0: case S_IFREG:
			error = vfs_create(d_get_inode(nd.dentry),dentry,mode,&nd);
			break;
		case S_IFCHR: case S_IFBLK:
			error = vfs_mknod(d_get_inode(nd.dentry),dentry,mode,
					new_decode_dev(dev));
			break;
		case S_IFIFO: case S_IFSOCK:
			error = vfs_mknod(d_get_inode(nd.dentry),dentry,mode,0);
			break;
		case S_IFDIR:
			error = -EPERM;
			break;
		default:
			error = -EINVAL;
		}
		dput(parent(dentry));
	}
	_imutex_unlock(inode);
	path_release(&nd);
out:
	putname(tmp);

	return error;
}

asmlinkage long sys_mknod(const char __user *filename, int mode, unsigned dev)
{
	return sys_mknodat(AT_FDCWD, filename, mode, dev);
}

int vfs_mkdir(struct _inode *dir, struct _dentry *dentry, int mode)
{
	int error = may_create(dir, dentry, NULL);

	if (error)
		return error;

	if (!dir->i_op || !dir->i_op->mkdir)
		return -EPERM;

	mode &= (S_IRWXUGO|S_ISVTX);
	error = security_inode_mkdir(dir, dentry, mode);
	if (error)
		return error;

	/* Upgrade to RW mode */
	if(live_transaction()){
		dentry = tx_cache_get_dentry(parent(dentry));
		dir = tx_cache_get_inode(parent(dir));
	} else {
		upgrade_imutex_write(parent(dir));
	}

	DQUOT_INIT(dir);
	error = dir->i_op->mkdir(dir, dentry, mode);
	if (!error)
		fsnotify_mkdir(parent(dir), parent(dentry));
	return error;
}

asmlinkage long sys_mkdirat(int dfd, const char __user *pathname, int mode)
{
	int error = 0;
	char * tmp;
	struct _dentry *dentry;
	struct _inode *inode;
	struct nameidata nd;

	tmp = getname(pathname);
	error = PTR_ERR(tmp);
	if (IS_ERR(tmp))
		goto out_err;

	error = do_path_lookup(dfd, tmp, LOOKUP_PARENT, &nd);
	if (error)
		goto out;
	inode = d_get_inode(nd.dentry);

	dentry = lookup_create(&nd, 1);
	error = PTR_ERR(dentry);
	if (IS_ERR(dentry))
		goto out_unlock;

	inode = d_get_inode(nd.dentry);

	if (!IS_POSIXACL(inode))
		mode &= ~current->fs->umask;

	error = vfs_mkdir(inode, dentry, mode);
	dput(parent(dentry));
out_unlock:
	_imutex_unlock(inode);
	path_release(&nd);
out:
	putname(tmp);
out_err:
	return error;
}

asmlinkage long sys_mkdir(const char __user *pathname, int mode)
{
	return sys_mkdirat(AT_FDCWD, pathname, mode);
}

/*
 * We try to drop the dentry early: we should have
 * a usage count of 2 if we're the only user of this
 * dentry, and if that is true (possibly after pruning
 * the dcache), then we drop the dentry now.
 *
 * A low-level filesystem can, if it choses, legally
 * do a
 *
 *	if (!d_unhashed(dentry))
 *		return -EBUSY;
 *
 * if it cannot handle the case of removing a directory
 * that is still in use by something else..
 */
void dentry_unhash(struct dentry *dentry)
{
	dget(dentry);
	shrink_dcache_parent(dentry);
	spin_lock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);
	dspin_lock(dentry);
	if (atomic_read(&dentry->d_count) == 2)
		__d_drop(tx_cache_get_dentry(dentry));
	dspin_unlock(dentry);
	spin_unlock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);
}

int vfs_rmdir(struct _inode *dir, struct _dentry *dentry)
{
	int error = may_delete(dir, dentry, 1);
	struct _inode *dentry_inode = d_get_inode(dentry);

	if (error)
		return error;

	if (!dir->i_op || !dir->i_op->rmdir)
		return -EPERM;

	if(unlikely(IS_ERR(dentry_inode)))
		return PTR_ERR(dentry_inode);

	DQUOT_INIT(dir);

	_imutex_lock(dentry_inode);

	dentry_unhash(parent(dentry));
	if (d_mountpoint(parent(dentry)))
		error = -EBUSY;
	else {
		error = security_inode_rmdir(dir, dentry);
		if (!error) {
			error = dir->i_op->rmdir(dir, dentry);
			if (!error)
				dentry_inode->i_flags |= S_DEAD;
		}
	}
	_imutex_unlock(dentry_inode);
	if (!error) {
		d_delete(dentry);
	}
	dput(parent(dentry));

	return error;
}

static long do_rmdir(int dfd, const char __user *pathname)
{
	int error = 0;
	char * name;
	struct _dentry *dentry;
	struct nameidata nd;
	struct _inode *inode;

	name = getname(pathname);
	if(IS_ERR(name))
		return PTR_ERR(name);

	error = do_path_lookup(dfd, name, LOOKUP_PARENT, &nd);
	if (error)
		goto exit;

	switch(nd.last_type) {
		case LAST_DOTDOT:
			error = -ENOTEMPTY;
			goto exit1;
		case LAST_DOT:
			error = -EINVAL;
			goto exit1;
		case LAST_ROOT:
			error = -EBUSY;
			goto exit1;
	}
	inode = d_get_inode(nd.dentry);
	_imutex_lock_nested(inode, I_MUTEX_PARENT);
	dentry = lookup_hash(&nd);
	error = PTR_ERR(dentry);
	if (IS_ERR(dentry))
		goto exit2;

	/* Upgrade to rw mode */
	if(live_transaction()){
		dentry = tx_cache_get_dentry(parent(dentry));
	}
	error = vfs_rmdir(inode, dentry);
	dput(parent(dentry));
exit2:
	_imutex_unlock(inode);
exit1:
	path_release(&nd);
exit:
	putname(name);
	return error;
}

asmlinkage long sys_rmdir(const char __user *pathname)
{
	return do_rmdir(AT_FDCWD, pathname);
}

int vfs_unlink(struct _inode *dir, struct _dentry *dentry)
{
	int error = may_delete(dir, dentry, 0);
	struct _inode *inode;

	if (error)
		return error;

	if (!dir->i_op || !dir->i_op->unlink)
		return -EPERM;

	DQUOT_INIT(dir);

	inode = d_get_inode(dentry);

	_imutex_lock(inode);
	if (d_mountpoint(parent(dentry)))
		error = -EBUSY;
	else {
		error = security_inode_unlink(dir, dentry);
		/* Upgrade to rw mode */
		if(live_transaction()){
			dentry = tx_cache_get_dentry(parent(dentry));
			dir = tx_cache_get_inode(parent(dir));
		}
		
		if (!error)
			error = dir->i_op->unlink(dir, dentry);
	}
	_imutex_unlock(inode);

	/* We don't d_delete() NFS sillyrenamed files--they still exist. */
	if (!error && !(dentry->d_flags & DCACHE_NFSFS_RENAMED)) {
		d_delete(dentry);
	}

	return error;
}

/*
 * Make sure that the actual truncation of the file will occur outside its
 * directory's i_mutex.  Truncate can take a long time if there is a lot of
 * writeout happening, and we don't want to prevent access to the directory
 * while waiting on the I/O.
 */
static long do_unlinkat(int dfd, const char __user *pathname)
{
	int error = 0;
	char * name;
	struct _dentry *dentry;
	struct nameidata nd;
	struct _inode *inode = NULL, *dentry_inode = NULL;

	name = getname(pathname);
	if(IS_ERR(name))
		return PTR_ERR(name);

	error = do_path_lookup(dfd, name, LOOKUP_PARENT, &nd);
	if (error)
		goto exit;
	error = -EISDIR;
	if (nd.last_type != LAST_NORM)
		goto exit1;

	dentry_inode = d_get_inode(nd.dentry);
	if(unlikely(PTR_ERR(dentry_inode) == -ETXABORT )){
		error = -ETXABORT;
		goto exit1;
	}

	_imutex_lock_nested(dentry_inode, I_MUTEX_PARENT);
	dentry = lookup_hash(&nd);
	error = PTR_ERR(dentry);
	if (!IS_ERR(dentry)) {
		/* Why not before? Because we want correct error value */
		if (nd.last.name[nd.last.len])
			goto slashes;
		inode = d_get_inode(dentry);
		if (inode && !IS_ERR(inode))
			tx_atomic_inc(&parent(inode)->i_count);
		error = vfs_unlink(dentry_inode, dentry);
	exit2:
		dput(parent(dentry));
	}
	_imutex_unlock(dentry_inode);
	if (inode)
		iput(parent(inode));	/* truncate the inode here */
exit1:
	path_release(&nd);
exit:
	putname(name);
	return error;

slashes:
	error = !dentry->d_inode ? -ENOENT :
	S_ISDIR(d_get_inode(dentry)->i_mode) ? -EISDIR : -ENOTDIR;
	goto exit2;
}

asmlinkage long sys_unlinkat(int dfd, const char __user *pathname, int flag)
{
	if ((flag & ~AT_REMOVEDIR) != 0)
		return -EINVAL;

	if (flag & AT_REMOVEDIR)
		return do_rmdir(dfd, pathname);

	return do_unlinkat(dfd, pathname);
}

asmlinkage long sys_unlink(const char __user *pathname)
{
	return do_unlinkat(AT_FDCWD, pathname);
}

int vfs_symlink(struct _inode *dir, struct _dentry *dentry, const char *oldname, int mode)
{
	int error = may_create(dir, dentry, NULL);

	//DEBUG
	/*
	printk(KERN_ERR "Attempting to create symlink! pid=%d prio=%d sprio=%d nprio=%d\n",
	       (int)current->pid, (int)current->prio,
	       (int)current->static_prio, (int)current->normal_prio);
	*/

	if (error)
		return error;

	if (!dir->i_op || !dir->i_op->symlink)
		return -EPERM;

	error = security_inode_symlink(dir, dentry, oldname);
	if (error)
		return error;

	/* Upgrade to RW mode */
	if(live_transaction()){
		dentry = tx_cache_get_dentry(parent(dentry));
		dir = tx_cache_get_inode(parent(dir));
	} else {
		upgrade_imutex_write(parent(dir));
	}


	DQUOT_INIT(dir);
	error = dir->i_op->symlink(dir, dentry, oldname);
	if(live_transaction())
		dentry->d_flags |= DCACHE_SPECULATIVE_CREATE;

	if (!error)
		fsnotify_create(parent(dir), parent(dentry));
	return error;
}

asmlinkage long sys_symlinkat(const char __user *oldname,
			      int newdfd, const char __user *newname)
{
	int error = 0;
	char * from;
	char * to;
	struct _dentry *dentry;
	struct _inode *inode;
	struct nameidata nd;

	from = getname(oldname);
	if(IS_ERR(from))
		return PTR_ERR(from);
	to = getname(newname);
	error = PTR_ERR(to);
	if (IS_ERR(to))
		goto out_putname;

	error = do_path_lookup(newdfd, to, LOOKUP_PARENT, &nd);
	if (error)
		goto out;
	inode = d_get_inode(nd.dentry);

	dentry = lookup_create(&nd, 0);
	inode = d_get_inode(nd.dentry);
	error = PTR_ERR(dentry);
	if (IS_ERR(dentry))
		goto out_unlock;

	error = vfs_symlink(inode, dentry, from, S_IALLUGO);
	dput(parent(dentry));
out_unlock:
	_imutex_unlock(inode);
	path_release(&nd);
out:
	putname(to);
out_putname:
	putname(from);
	return error;
}

asmlinkage long sys_symlink(const char __user *oldname, const char __user *newname)
{
	return sys_symlinkat(oldname, AT_FDCWD, newname);
}

int vfs_link(struct _dentry *old_dentry, struct _inode *dir, struct _dentry *new_dentry)
{
	struct _inode *inode = d_get_inode(old_dentry);
	int error;
	struct super_block *sb1, *sb2;

	if (!inode)
		return -ENOENT;

	error = may_create(dir, new_dentry, NULL);
	if (error)
		return error;

	/* Avoid pulling these pointers into our workset if we don't
	 * already have them.  The stable values should suffice
	 */
	sb1 = dir->i_sb;
	sb2 = inode->i_sb;
	
	if (sb1 != sb2)
		return -EXDEV;

	/*
	 * A link to an append-only or immutable file cannot be created.
	 */
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		return -EPERM;
	if (!dir->i_op || !dir->i_op->link)
		return -EPERM;
	if (S_ISDIR(inode->i_mode))
		return -EPERM;

	error = security_inode_link(old_dentry, dir, new_dentry);
	if (error)
		return error;

	/* Upgrade to RW mode */
	if(live_transaction()){
		old_dentry = tx_cache_get_dentry(parent(old_dentry));
		dir = tx_cache_get_inode(parent(dir));
	} else {
		upgrade_imutex_write(parent(dir));
	}


	_imutex_lock(inode);
	DQUOT_INIT(dir);
	error = dir->i_op->link(old_dentry, dir, new_dentry);
	if(live_transaction())
		new_dentry->d_flags |= DCACHE_SPECULATIVE_CREATE;

	_imutex_unlock(inode);
	if (!error)
		fsnotify_create(parent(dir), parent(new_dentry));
	return error;
}

/*
 * Hardlinks are often used in delicate situations.  We avoid
 * security-related surprises by not following symlinks on the
 * newname.  --KAB
 *
 * We don't follow them on the oldname either to be compatible
 * with linux 2.0, and to avoid hard-linking to directories
 * and other special files.  --ADM
 */
asmlinkage long sys_linkat(int olddfd, const char __user *oldname,
			   int newdfd, const char __user *newname,
			   int flags)
{
	struct _dentry *new_dentry;
	struct _inode *inode;
	struct nameidata nd, old_nd;
	int error;
	char * to;

	if ((flags & ~AT_SYMLINK_FOLLOW) != 0)
		return -EINVAL;

	to = getname(newname);
	if (IS_ERR(to))
		return PTR_ERR(to);

	error = __user_walk_fd(olddfd, oldname,
			       flags & AT_SYMLINK_FOLLOW ? LOOKUP_FOLLOW : 0,
			       &old_nd);
	if (error)
		goto exit;
	error = do_path_lookup(newdfd, to, LOOKUP_PARENT, &nd);
	if (error)
		goto out;
	error = -EXDEV;
	if (old_nd.mnt != nd.mnt)
		goto out_release;
	inode = d_get_inode(nd.dentry);
	if(unlikely(IS_ERR(inode))){
		error = PTR_ERR(inode);
		goto out;
	}
	new_dentry = lookup_create(&nd, 0);
	error = PTR_ERR(new_dentry);
	if (IS_ERR(new_dentry))
		goto out_unlock;

	/* Make sure new_dentry is in rw mode */
	if(live_transaction() && new_dentry->rw == ACCESS_R)
		new_dentry = tx_cache_get_dentry(parent(new_dentry));

	error = vfs_link(old_nd.dentry, inode, new_dentry);
	dput(parent(new_dentry));
out_unlock:
	_imutex_unlock(inode);
out_release:
	path_release(&nd);
out:
	path_release(&old_nd);
exit:
	putname(to);

	return error;
}

asmlinkage long sys_link(const char __user *oldname, const char __user *newname)
{
	return sys_linkat(AT_FDCWD, oldname, AT_FDCWD, newname, 0);
}

/*
 * The worst of all namespace operations - renaming directory. "Perverted"
 * doesn't even start to describe it. Somebody in UCB had a heck of a trip...
 * Problems:
 *	a) we can get into loop creation. Check is done in is_subdir().
 *	b) race potential - two innocent renames can create a loop together.
 *	   That's where 4.4 screws up. Current fix: serialization on
 *	   sb->s_vfs_rename_mutex. We might be more accurate, but that's another
 *	   story.
 *	c) we have to lock _three_ objects - parents and victim (if it exists).
 *	   And that - after we got ->i_mutex on parents (until then we don't know
 *	   whether the target exists).  Solution: try to be smart with locking
 *	   order for inodes.  We rely on the fact that tree topology may change
 *	   only under ->s_vfs_rename_mutex _and_ that parent of the object we
 *	   move will be locked.  Thus we can rank directories by the tree
 *	   (ancestors first) and rank all non-directories after them.
 *	   That works since everybody except rename does "lock parent, lookup,
 *	   lock child" and rename is under ->s_vfs_rename_mutex.
 *	   HOWEVER, it relies on the assumption that any object with ->lookup()
 *	   has no more than 1 dentry.  If "hybrid" objects will ever appear,
 *	   we'd better make sure that there's no link(2) for them.
 *	d) some filesystems don't support opened-but-unlinked directories,
 *	   either because of layout or because they are not ready to deal with
 *	   all cases correctly. The latter will be fixed (taking this sort of
 *	   stuff into VFS), but the former is not going away. Solution: the same
 *	   trick as in rmdir().
 *	e) conversion from fhandle to dentry may come in the wrong moment - when
 *	   we are removing the target. Solution: we will have to grab ->i_mutex
 *	   in the fhandle_to_dentry code. [FIXME - current nfsfh.c relies on
 *	   ->i_mutex on parents, which works but leads to some truely excessive
 *	   locking].
 */
static int vfs_rename_dir(struct _inode *old_dir, struct _dentry *old_dentry,
			  struct _inode *new_dir, struct _dentry *new_dentry)
{
	int error = 0;
	struct _inode *target;

	/*
	 * If we are going to change the parent - check write permissions,
	 * we'll need to flip '..'.
	 */
	if (new_dir != old_dir) {
		error = permission(d_get_inode(old_dentry), MAY_WRITE, NULL);
		if (error)
			return error;
	}

	error = security_inode_rename(old_dir, old_dentry, new_dir, new_dentry);
	if (error)
		return error;

	target = d_get_inode(new_dentry);
	if (target) {
		_imutex_lock(target);
		dentry_unhash(parent(new_dentry));
	}
	if (d_mountpoint(parent(old_dentry))||d_mountpoint(parent(new_dentry)))
		error = -EBUSY;
	else 
		error = old_dir->i_op->rename(old_dir, old_dentry, new_dir, new_dentry);
	if (target) {
		if (!error)
			target->i_flags |= S_DEAD;
		_imutex_unlock(target);
		if (d_unhashed(new_dentry))
			d_rehash(new_dentry);
		dput(parent(new_dentry));
	}
	if (!error)
		if (!(old_dir->i_sb->s_type->fs_flags & FS_RENAME_DOES_D_MOVE))
			d_move(old_dentry,new_dentry);
	return error;
}

static int vfs_rename_other(struct _inode *old_dir, struct _dentry *old_dentry,
			    struct _inode *new_dir, struct _dentry *new_dentry)
{
	struct _inode *target;
	int error;

	error = security_inode_rename(old_dir, old_dentry, new_dir, new_dentry);
	if (error)
		return error;

	dget(parent(new_dentry));
	target = d_get_inode(new_dentry);
	if (target)
		_imutex_lock(target);
	if (d_mountpoint(parent(old_dentry))||d_mountpoint(parent(new_dentry)))
		error = -EBUSY;
	else
		error = old_dir->i_op->rename(old_dir, old_dentry, new_dir, new_dentry);
	if (!error) {
		if (!(old_dir->i_sb->s_type->fs_flags & FS_RENAME_DOES_D_MOVE))
			d_move(old_dentry, new_dentry);
	}
	if (target)
		_imutex_unlock(target);
	dput(parent(new_dentry));
	return error;
}

int vfs_rename(struct _inode *old_dir, struct _dentry *old_dentry,
	       struct _inode *new_dir, struct _dentry *new_dentry)
{
	int error;
	struct _inode * old_dinode = d_get_inode(old_dentry);
	int is_dir = S_ISDIR(old_dinode->i_mode);
	const char *old_name;

	if (old_dentry->d_inode == new_dentry->d_inode)
 		return 0;
 
	error = may_delete(old_dir, old_dentry, is_dir);
	if (error)
		return error;

	if (!new_dentry->d_inode)
		error = may_create(new_dir, new_dentry, NULL);
	else
		error = may_delete(new_dir, new_dentry, is_dir);
	if (error)
		return error;

	if (!old_dir->i_op || !old_dir->i_op->rename)
		return -EPERM;

	DQUOT_INIT(old_dir);
	DQUOT_INIT(new_dir);

	old_name = fsnotify_oldname_init(old_dentry->d_name.name);

	if (is_dir)
		error = vfs_rename_dir(old_dir,old_dentry,new_dir,new_dentry);
	else
		error = vfs_rename_other(old_dir,old_dentry,new_dir,new_dentry);
	if (!error) {
		const char *new_name = old_dentry->d_name.name;
		fsnotify_move(parent(old_dir), parent(new_dir), old_name, new_name, is_dir,
			      new_dentry->d_inode, old_dentry->d_inode);
	}
	if(!live_transaction())
		fsnotify_oldname_free(old_name);

	return error;
}

static int do_rename(int olddfd, const char *oldname,
			int newdfd, const char *newname)
{
	int error = 0;
	struct _dentry * old_dir, * new_dir;
	struct _dentry * old_dentry, *new_dentry;
	struct _dentry * trap;
	struct nameidata oldnd, newnd;

	error = do_path_lookup(olddfd, oldname, LOOKUP_PARENT, &oldnd);
	if (error)
		goto exit;

	error = do_path_lookup(newdfd, newname, LOOKUP_PARENT, &newnd);
	if (error)
		goto exit1;

	error = -EXDEV;
	if (oldnd.mnt != newnd.mnt)
		goto exit2;

	old_dir = oldnd.dentry;
	error = -EBUSY;
	if (oldnd.last_type != LAST_NORM)
		goto exit2;

	new_dir = newnd.dentry;
	if (newnd.last_type != LAST_NORM)
		goto exit2;

	trap = lock_rename(new_dir, old_dir);

	old_dentry = lookup_hash(&oldnd);
	error = PTR_ERR(old_dentry);
	if (IS_ERR(old_dentry))
		goto exit3;
	/* source must exist */
	error = -ENOENT;
	if (!old_dentry->d_inode)
		goto exit4;
	/* unless the source is a directory trailing slashes give -ENOTDIR */
	if (!S_ISDIR((d_get_inode_ro(old_dentry))->i_mode)) {
		error = -ENOTDIR;
		if (oldnd.last.name[oldnd.last.len])
			goto exit4;
		if (newnd.last.name[newnd.last.len])
			goto exit4;
	}
	/* source should not be ancestor of target */
	error = -EINVAL;
	if (old_dentry == trap)
		goto exit4;
	new_dentry = lookup_hash(&newnd);
	error = PTR_ERR(new_dentry);
	if (IS_ERR(new_dentry))
		goto exit4;
	/* target should not be an ancestor of source */
	error = -ENOTEMPTY;
	if (new_dentry == trap)
		goto exit5;

	/* Upgrade to RW mode */
	if(live_transaction()){
		old_dentry = tx_cache_get_dentry(parent(old_dentry));
		new_dentry = tx_cache_get_dentry(parent(new_dentry));
	}


	error = vfs_rename(d_get_inode(old_dir), old_dentry,
			   d_get_inode(new_dir), new_dentry);
exit5:
	dput(parent(new_dentry));
exit4:
	dput(parent(old_dentry));
exit3:
	unlock_rename(new_dir, old_dir);
exit2:
	path_release(&newnd);
exit1:
	path_release(&oldnd);
exit:
	return error;
}

asmlinkage long sys_renameat(int olddfd, const char __user *oldname,
			     int newdfd, const char __user *newname)
{
	int error;
	char * from;
	char * to;

	from = getname(oldname);
	if(IS_ERR(from))
		return PTR_ERR(from);
	to = getname(newname);
	error = PTR_ERR(to);
	if (!IS_ERR(to)) {
		error = do_rename(olddfd, from, newdfd, to);
		putname(to);
	}
	putname(from);
	return error;
}

asmlinkage long sys_rename(const char __user *oldname, const char __user *newname)
{
	return sys_renameat(AT_FDCWD, oldname, AT_FDCWD, newname);
}

int vfs_readlink(struct _dentry *dentry, char __user *buffer, int buflen, const char *link)
{
	int len;

	len = PTR_ERR(link);
	if (IS_ERR(link))
		goto out;

	len = strlen(link);
	if (len > (unsigned) buflen)
		len = buflen;
	if (copy_to_user(buffer, link, len))
		len = -EFAULT;
out:
	return len;
}

/*
 * A helper for ->readlink().  This should be used *ONLY* for symlinks that
 * have ->follow_link() touching nd only in nd_set_link().  Using (or not
 * using) it for any given inode is up to filesystem.
 */
int generic_readlink(struct _dentry *dentry, char __user *buffer, int buflen)
{
	struct nameidata nd;
	void *cookie;
	struct _inode *inode;

	nd.depth = 0;
	inode = d_get_inode_ro(dentry);
	cookie = inode->i_op->follow_link(dentry, &nd);
	if (!IS_ERR(cookie)) {
		int res = vfs_readlink(dentry, buffer, buflen, nd_get_link(&nd));
		if (inode->i_op->put_link)
			inode->i_op->put_link(dentry, &nd, cookie);
		cookie = ERR_PTR(res);
	}
	return PTR_ERR(cookie);
}

int vfs_follow_link(struct nameidata *nd, const char *link)
{
	return __vfs_follow_link(nd, link);
}

/* get the link contents into pagecache */
static char *page_getlink(struct _dentry * dentry, struct page **ppage)
{
	struct page * page;
	struct address_space *mapping = d_get_inode_ro(dentry)->i_mapping;
	page = read_mapping_page(mapping, 0, NULL);
	if (IS_ERR(page))
		return (char*)page;
	*ppage = page;
	return kmap(page);
}

int page_readlink(struct _dentry *dentry, char __user *buffer, int buflen)
{
	struct page *page = NULL;
	char *s = page_getlink(dentry, &page);
	int res = vfs_readlink(dentry,buffer,buflen,s);
	if (page) {
		kunmap(page);
		page_cache_release(page);
	}
	return res;
}

void *page_follow_link_light(struct _dentry *dentry, struct nameidata *nd)
{
	struct page *page = NULL;
	nd_set_link(nd, page_getlink(dentry, &page));
	return page;
}

void page_put_link(struct _dentry *dentry, struct nameidata *nd, void *cookie)
{
	struct page *page = cookie;

	if (page) {
		kunmap(page);
		page_cache_release(page);
	}
}

int __page_symlink(struct _inode *inode, const char *symname, int len,
		gfp_t gfp_mask)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page;
	int err;
	char *kaddr;

retry:
	err = -ENOMEM;
	page = find_or_create_page(mapping, 0, gfp_mask);
	if (!page)
		goto fail;
	err = mapping->a_ops->prepare_write(NULL, page, 0, len-1);
	if (err == AOP_TRUNCATED_PAGE) {
		page_cache_release(page);
		goto retry;
	}
	if (err)
		goto fail_map;
	kaddr = kmap_atomic(page, KM_USER0);
	memcpy(kaddr, symname, len-1);
	kunmap_atomic(kaddr, KM_USER0);
	err = mapping->a_ops->commit_write(NULL, page, 0, len-1);
	if (err == AOP_TRUNCATED_PAGE) {
		page_cache_release(page);
		goto retry;
	}
	if (err)
		goto fail_map;
	/*
	 * Notice that we are _not_ going to block here - end of page is
	 * unmapped, so this will only try to map the rest of page, see
	 * that it is unmapped (typically even will not look into inode -
	 * ->i_size will be enough for everything) and zero it out.
	 * OTOH it's obviously correct and should make the page up-to-date.
	 */
	if (!PageUptodate(page)) {
		err = mapping->a_ops->readpage(NULL, page);
		if (err != AOP_TRUNCATED_PAGE)
			wait_on_page_locked(page);
	} else {
		unlock_page(page);
	}
	page_cache_release(page);
	if (err < 0)
		goto fail;
	mark_inode_dirty(parent(inode));
	return 0;
fail_map:
	unlock_page(page);
	page_cache_release(page);
fail:
	return err;
}

int page_symlink(struct inode *inode, const char *symname, int len)
{
	struct _inode *_inode = tx_cache_get_inode(inode);
	return __page_symlink(_inode, symname, len,
			mapping_gfp_mask(_inode->i_mapping));
}

const struct inode_operations page_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
};

EXPORT_SYMBOL(__user_walk);
EXPORT_SYMBOL(__user_walk_fd);
EXPORT_SYMBOL(follow_down);
EXPORT_SYMBOL(follow_up);
EXPORT_SYMBOL(get_write_access); /* binfmt_aout */
EXPORT_SYMBOL(allow_write_access);
EXPORT_SYMBOL(put_write_access);
EXPORT_SYMBOL(getname);
EXPORT_SYMBOL(lock_rename);
EXPORT_SYMBOL(lookup_one_len);
EXPORT_SYMBOL(page_follow_link_light);
EXPORT_SYMBOL(page_put_link);
EXPORT_SYMBOL(page_readlink);
EXPORT_SYMBOL(__page_symlink);
EXPORT_SYMBOL(page_symlink);
EXPORT_SYMBOL(page_symlink_inode_operations);
EXPORT_SYMBOL(path_lookup);
EXPORT_SYMBOL(path_release);
EXPORT_SYMBOL(path_walk);
EXPORT_SYMBOL(permission);
EXPORT_SYMBOL(vfs_permission);
EXPORT_SYMBOL(file_permission);
EXPORT_SYMBOL(unlock_rename);
EXPORT_SYMBOL(vfs_create);
EXPORT_SYMBOL(vfs_follow_link);
EXPORT_SYMBOL(vfs_link);
EXPORT_SYMBOL(vfs_mkdir);
EXPORT_SYMBOL(vfs_mknod);
EXPORT_SYMBOL(generic_permission);
EXPORT_SYMBOL(vfs_readlink);
EXPORT_SYMBOL(vfs_rename);
EXPORT_SYMBOL(vfs_rmdir);
EXPORT_SYMBOL(vfs_symlink);
EXPORT_SYMBOL(vfs_unlink);
EXPORT_SYMBOL(dentry_unhash);
EXPORT_SYMBOL(generic_readlink);
