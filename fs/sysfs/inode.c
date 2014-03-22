/*
 * inode.c - basic inode and dentry operations.
 *
 * sysfs is Copyright (c) 2001-3 Patrick Mochel
 *
 * Please see Documentation/filesystems/sysfs.txt for more information.
 */

#undef DEBUG 

#include <linux/pagemap.h>
#include <linux/namei.h>
#include <linux/backing-dev.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <asm/semaphore.h>
#include "sysfs.h"

#include <linux/transaction.h>
#include <linux/tx_inodes.h>
#include <linux/tx_super.h>

extern struct super_block * sysfs_sb;

static const struct address_space_operations sysfs_aops = {
	.readpage	= simple_readpage,
	.prepare_write	= simple_prepare_write,
	.commit_write	= simple_commit_write
};

static struct backing_dev_info sysfs_backing_dev_info = {
	.ra_pages	= 0,	/* No readahead */
	.capabilities	= BDI_CAP_NO_ACCT_DIRTY | BDI_CAP_NO_WRITEBACK,
};

static const struct inode_operations sysfs_inode_operations ={
	.setattr	= sysfs_setattr,
};

void sysfs_delete_inode(struct _inode *inode)
{
	/* Free the shadowed directory inode operations */
	if (sysfs_is_shadowed_inode(inode)) {
		kfree(inode->i_op);
		inode->i_op = NULL;
	}
	return generic_delete_inode(inode);
}

int sysfs_setattr(struct dentry * dentry, struct iattr * iattr)
{
	struct _inode * inode = dentry_get_inode(dentry);
	struct sysfs_dirent * sd = dentry->d_fsdata;
	struct iattr * sd_iattr;
	unsigned int ia_valid = iattr->ia_valid;
	int error;

	if (!sd)
		return -EINVAL;

	sd_iattr = sd->s_iattr;

	error = inode_change_ok(inode, iattr);
	if (error)
		return error;

	error = inode_setattr(inode, iattr);
	if (error)
		return error;

	if (!sd_iattr) {
		/* setting attributes for the first time, allocate now */
		sd_iattr = kzalloc(sizeof(struct iattr), GFP_KERNEL);
		if (!sd_iattr)
			return -ENOMEM;
		/* assign default attributes */
		sd_iattr->ia_mode = sd->s_mode;
		sd_iattr->ia_uid = 0;
		sd_iattr->ia_gid = 0;
		sd_iattr->ia_atime = sd_iattr->ia_mtime = sd_iattr->ia_ctime = CURRENT_TIME;
		sd->s_iattr = sd_iattr;
	}

	/* attributes were changed atleast once in past */

	if (ia_valid & ATTR_UID)
		sd_iattr->ia_uid = iattr->ia_uid;
	if (ia_valid & ATTR_GID)
		sd_iattr->ia_gid = iattr->ia_gid;
	if (ia_valid & ATTR_ATIME)
		sd_iattr->ia_atime = timespec_trunc(iattr->ia_atime,
						inode->i_sb->s_time_gran);
	if (ia_valid & ATTR_MTIME)
		sd_iattr->ia_mtime = timespec_trunc(iattr->ia_mtime,
						inode->i_sb->s_time_gran);
	if (ia_valid & ATTR_CTIME)
		sd_iattr->ia_ctime = timespec_trunc(iattr->ia_ctime,
						inode->i_sb->s_time_gran);
	if (ia_valid & ATTR_MODE) {
		umode_t mode = iattr->ia_mode;

		if (!in_group_p(inode->i_gid) && !capable(CAP_FSETID))
			mode &= ~S_ISGID;
		sd_iattr->ia_mode = sd->s_mode = mode;
	}

	return error;
}

static inline void set_default_inode_attr(struct _inode * inode, mode_t mode)
{
	inode->i_mode = mode;
	inode->i_uid = 0;
	inode->i_gid = 0;
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
}

static inline void set_inode_attr(struct _inode * inode, struct iattr * iattr)
{
	inode->i_mode = iattr->ia_mode;
	inode->i_uid = iattr->ia_uid;
	inode->i_gid = iattr->ia_gid;
	inode->i_atime = iattr->ia_atime;
	inode->i_mtime = iattr->ia_mtime;
	inode->i_ctime = iattr->ia_ctime;
}


/*
 * sysfs has a different i_mutex lock order behavior for i_mutex than other
 * filesystems; sysfs i_mutex is called in many places with subsystem locks
 * held. At the same time, many of the VFS locking rules do not apply to
 * sysfs at all (cross directory rename for example). To untangle this mess
 * (which gives false positives in lockdep), we're giving sysfs inodes their
 * own class for i_mutex.
 */
static struct lock_class_key sysfs_inode_imutex_key;

struct inode * sysfs_new_inode(mode_t mode, struct sysfs_dirent * sd)
{
	struct inode * inode = new_inode(sysfs_sb);
	if (inode) {
		struct _inode *_inode = tx_cache_get_inode(inode);
		inode->i_blocks = 0;
		_inode->i_mapping->a_ops = &sysfs_aops;
		_inode->i_mapping->backing_dev_info = &sysfs_backing_dev_info;
		_inode->i_op = &sysfs_inode_operations;
		_inode->i_ino = sd->s_ino;
		lockdep_set_class(&inode->i_mutex, &sysfs_inode_imutex_key);

		if (sd->s_iattr) {
			/* sysfs_dirent has non-default attributes
			 * get them for the new inode from persistent copy
			 * in sysfs_dirent
			 */
			set_inode_attr(_inode, sd->s_iattr);
		} else
			set_default_inode_attr(_inode, mode);
	}
	return inode;
}

int sysfs_create(struct _dentry * dentry, int mode, int (*init)(struct _inode *))
{
	int error = 0;
	struct inode * inode = NULL;
	if (dentry) {
		if (!dentry->d_inode) {
			struct sysfs_dirent * sd = parent(dentry)->d_fsdata;
			if ((inode = sysfs_new_inode(mode, sd))) {
				if (dentry->d_parent){
					struct _dentry *_parent = tx_cache_get_dentry(dentry->d_parent);
					if(_parent->d_inode) {
						struct _inode *p_inode = d_get_inode(_parent);
						p_inode->i_mtime = p_inode->i_ctime = CURRENT_TIME;
					}
				}
				goto Proceed;
			}
			else 
				error = -ENOMEM;
		} else
			error = -EEXIST;
	} else 
		error = -ENOENT;
	goto Done;

 Proceed:
	if (init)
		error = init(tx_cache_get_inode(inode));
	if (!error) {
		d_instantiate(dentry, tx_cache_get_inode(inode));
		if (S_ISDIR(mode))
			dget(parent(dentry));  /* pin only directory dentry in core */
	} else
		iput(inode);
 Done:
	return error;
}

/*
 * Get the name for corresponding element represented by the given sysfs_dirent
 */
const unsigned char * sysfs_get_name(struct sysfs_dirent *sd)
{
	struct attribute * attr;
	struct bin_attribute * bin_attr;
	struct sysfs_symlink  * sl;

	BUG_ON(!sd || !sd->s_element);

	switch (sd->s_type) {
		case SYSFS_DIR:
			/* Always have a dentry so use that */
			return tx_cache_get_dentry(sd->s_dentry)->d_name.name;

		case SYSFS_KOBJ_ATTR:
			attr = sd->s_element;
			return attr->name;

		case SYSFS_KOBJ_BIN_ATTR:
			bin_attr = sd->s_element;
			return bin_attr->attr.name;

		case SYSFS_KOBJ_LINK:
			sl = sd->s_element;
			return sl->link_name;
	}
	return NULL;
}

static inline void orphan_all_buffers(struct inode *node)
{
	struct sysfs_buffer_collection *set;
	struct sysfs_buffer *buf;

	mutex_lock_nested(&node->i_mutex, I_MUTEX_CHILD);
	set = node->i_private;
	if (set) {
		list_for_each_entry(buf, &set->associates, associates) {
			down(&buf->sem);
			buf->orphaned = 1;
			up(&buf->sem);
		}
	}
	mutex_unlock(&node->i_mutex);
}


/*
 * Unhashes the dentry corresponding to given sysfs_dirent
 * Called with parent inode's i_mutex held.
 */
void sysfs_drop_dentry(struct sysfs_dirent * sd, struct dentry * parent)
{
	struct dentry *dentry = NULL;
	struct _dentry *_dentry = NULL;
	struct inode *inode;

	/* We're not holding a reference to ->s_dentry dentry but the
	 * field will stay valid as long as sysfs_lock is held.
	 */
	spin_lock(&sysfs_lock);
	spin_lock(&dcache_lock);

	/* dget dentry if it's still alive */
	if (sd->s_dentry){
		_dentry = tx_cache_get_dentry(sd->s_dentry);
		if(_dentry->d_inode)
			dentry = dget_locked(sd->s_dentry);
	}

	spin_unlock(&dcache_lock);
	spin_unlock(&sysfs_lock);

	/* drop dentry */
	if (dentry) {
		spin_lock(&dcache_lock);
		spin_lock(&dentry->d_lock);
		if (!d_unhashed(_dentry) && _dentry->d_inode) {
			inode = _dentry->d_inode;
			spin_lock(&inode->i_lock);
			__iget(inode);
			spin_unlock(&inode->i_lock);
			dget_locked(dentry);
			__d_drop(_dentry);
			spin_unlock(&dentry->d_lock);
			spin_unlock(&dcache_lock);
			simple_unlink(dentry_get_inode(parent), _dentry);
			orphan_all_buffers(inode);
			iput(inode);
		} else {
			spin_unlock(&dentry->d_lock);
			spin_unlock(&dcache_lock);
		}

		dput(dentry);
	}
}

int sysfs_hash_and_remove(struct dentry * dir, const char * name)
{
	struct sysfs_dirent * sd;
	struct sysfs_dirent * parent_sd;
	int found = 0;
	struct inode *inode;

	if (!dir)
		return -ENOENT;

	inode = tx_cache_get_dentry(dir)->d_inode;
	if (inode == NULL)
		/* no inode means this hasn't been made visible yet */
		return -ENOENT;

	parent_sd = dir->d_fsdata;
	imutex_lock_nested(inode, I_MUTEX_PARENT);
	list_for_each_entry(sd, &parent_sd->s_children, s_sibling) {
		if (!sd->s_element)
			continue;
		if (!strcmp(sysfs_get_name(sd), name)) {
			list_del_init(&sd->s_sibling);
			sysfs_drop_dentry(sd, dir);
			sysfs_put(sd);
			found = 1;
			break;
		}
	}
	imutex_unlock(inode);

	return found ? 0 : -ENOENT;
}
