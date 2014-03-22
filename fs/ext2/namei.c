/*
 * linux/fs/ext2/namei.c
 *
 * Rewrite to pagecache. Almost all code had been changed, so blame me
 * if the things go wrong. Please, send bug reports to
 * viro@parcelfarce.linux.theplanet.co.uk
 *
 * Stuff here is basically a glue between the VFS and generic UNIXish
 * filesystem that keeps everything in pagecache. All knowledge of the
 * directory layout is in fs/ext2/dir.c - it turned out to be easily separatable
 * and it's easier to debug that way. In principle we might want to
 * generalize that a bit and turn it into a library. Or not.
 *
 * The only non-static object here is ext2_dir_inode_operations.
 *
 * TODO: get rid of kmap() use, add readahead.
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/namei.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include <linux/pagemap.h>
#include "ext2.h"
#include "xattr.h"
#include "acl.h"
#include "xip.h"
#include <linux/tx_inodes.h>
#include <linux/tx_super.h>
#include <linux/tx_dentry.h>

static inline int ext2_add_nondir(struct _dentry *dentry, struct _inode *inode)
{
	int err = ext2_add_link(dentry, inode);
	if (!err) {
		d_instantiate(dentry, inode);
		return 0;
	}
	inode_dec_link_count(inode);
	iput(parent(inode));
	return err;
}

/*
 * Methods themselves.
 */

static struct _dentry *ext2_lookup(struct _inode * dir, struct _dentry *dentry, struct nameidata *nd)
{
	struct inode * inode;
	struct _inode *_inode = NULL;
	ino_t ino;
	
	if (dentry->d_name.len > EXT2_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	ino = ext2_inode_by_name(dir, dentry);
	inode = NULL;
	if (ino) {
		inode = iget(dir->i_sb, ino);
		if (!inode)
			return ERR_PTR(-EACCES);
		_inode = tx_cache_get_inode(inode);
	}
	return d_splice_alias(_inode, dentry);
}

struct dentry *ext2_get_parent(struct _dentry *child)
{
	unsigned long ino;
	struct dentry *parent;
	struct inode *inode;
	struct _dentry dotdot;
	struct _inode *d_inode = d_get_inode(child);

	dotdot.d_name.name = "..";
	dotdot.d_name.len = 2;

	ino = ext2_inode_by_name(d_inode, &dotdot);
	if (!ino)
		return ERR_PTR(-ENOENT);
	inode = iget(d_inode->i_sb, ino);

	if (!inode)
		return ERR_PTR(-EACCES);
	parent = d_alloc_anon(tx_cache_get_inode(inode));
	if (!parent) {
		iput(inode);
		parent = ERR_PTR(-ENOMEM);
	}
	return parent;
} 

/*
 * By the time this is called, we already have created
 * the directory cache entry for the new file, but it
 * is so far negative - it has no inode.
 *
 * If the create succeeds, we fill in the inode information
 * with d_instantiate(). 
 */
static int ext2_create (struct _inode * dir, struct _dentry * dentry, int mode, struct nameidata *nd)
{
	struct inode * inode = ext2_new_inode (dir, mode);
	int err = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		struct _inode *_inode = tx_cache_get_inode(inode);
		struct _super_block *sb = i_get_sb(_inode);

		_inode->i_op = &ext2_file_inode_operations;
		if (ext2_use_xip(parent(sb))) {
			_inode->i_mapping->a_ops = &ext2_aops_xip;
			_inode->i_fop = &ext2_xip_file_operations;
		} else if (test_opt(sb, NOBH)) {
			_inode->i_mapping->a_ops = &ext2_nobh_aops;
			_inode->i_fop = &ext2_file_operations;
		} else {
			_inode->i_mapping->a_ops = &ext2_aops;
			_inode->i_fop = &ext2_file_operations;
		}
		mark_inode_dirty(inode);
		err = ext2_add_nondir(dentry, _inode);
	}
	return err;
}

static int ext2_mknod (struct _inode * dir, struct _dentry *dentry, int mode, dev_t rdev)
{
	struct inode * inode;
	int err;

	if (!new_valid_dev(rdev))
		return -EINVAL;

	inode = ext2_new_inode (dir, mode);
	err = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		struct _inode *_inode = tx_cache_get_inode(inode);
		init_special_inode(_inode, _inode->i_mode, rdev);
#ifdef CONFIG_EXT2_FS_XATTR
		_inode->i_op = &ext2_special_inode_operations;
#endif
		mark_inode_dirty(inode);
		err = ext2_add_nondir(dentry, _inode);
	}
	return err;
}

static int ext2_symlink (struct _inode * dir, struct _dentry * dentry,
	const char * symname)
{
	struct super_block * sb = dir->i_sb;
	int err = -ENAMETOOLONG;
	unsigned l = strlen(symname)+1;
	struct inode * inode;
	struct _inode * _inode;

	if (l > sb->s_blocksize)
		goto out;

	inode = ext2_new_inode (dir, S_IFLNK | S_IRWXUGO);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out;

	_inode = tx_cache_get_inode(inode);
	if (l > sizeof (EXT2_I(inode)->i_data)){
		/* slow symlink */
		_inode->i_op = &ext2_symlink_inode_operations;
		if (test_opt(i_get_sb(_inode), NOBH))
			_inode->i_mapping->a_ops = &ext2_nobh_aops;
		else
			_inode->i_mapping->a_ops = &ext2_aops;
		err = page_symlink(inode, symname, l);
		if (err)
			goto out_fail;
	} else {
		/* fast symlink */
		_inode->i_op = &ext2_fast_symlink_inode_operations;
		memcpy((char*)(EXT2_I(inode)->i_data),symname,l);
		_inode->i_size = l-1;
	}
	mark_inode_dirty(inode);

	err = ext2_add_nondir(dentry, _inode);
out:
	return err;

out_fail:
	inode_dec_link_count(_inode);
	iput (inode);
	goto out;
}

static int ext2_link (struct _dentry * old_dentry, struct _inode * dir,
		      struct _dentry *dentry)
{
	struct _inode *inode = d_get_inode(old_dentry);

	if (inode->i_nlink >= EXT2_LINK_MAX)
		return -EMLINK;

	inode->i_ctime = CURRENT_TIME_SEC;
	inode_inc_link_count(inode);
	/* DEP 4/4/10:  Don't double-compensate for this increment during abort */
	tx_atomic_inc_nolog(&parent(inode)->i_count);

	return ext2_add_nondir(dentry, inode);
}

static int ext2_mkdir(struct _inode * dir, struct _dentry * dentry, int mode)
{
	struct inode * inode;
	struct _inode * _inode;
	int err = -EMLINK;

	if (dir->i_nlink >= EXT2_LINK_MAX)
		goto out;

	inode_inc_link_count(dir);

	inode = ext2_new_inode (dir, S_IFDIR | mode);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out_dir;

	_inode = tx_cache_get_inode(inode);
	_inode->i_op = &ext2_dir_inode_operations;
	_inode->i_fop = &ext2_dir_operations;

	/* This has to be done manually, since we needed
	 * a speculative copy to assign i_op in the first
	 * place - osh */
	ext2_init_sdirents(_inode, ACCESS_RW);

	if (test_opt(i_get_sb(_inode), NOBH))
		_inode->i_mapping->a_ops = &ext2_nobh_aops;
	else
		_inode->i_mapping->a_ops = &ext2_aops;

	inode_inc_link_count(_inode);

	err = ext2_make_empty(_inode, dir);
	if (err)
		goto out_fail;

	err = ext2_add_link(dentry, _inode);
	if (err)
		goto out_fail;

	d_instantiate(dentry, _inode);
out:
	return err;

out_fail:
	inode_dec_link_count(_inode);
	inode_dec_link_count(_inode);
	iput(inode);
out_dir:
	inode_dec_link_count(dir);
	goto out;
}

static int ext2_unlink(struct _inode * dir, struct _dentry *dentry)
{
	struct _inode * inode = d_get_inode(dentry);
	struct ext2_cur_sdirent cur_de;
	struct page * page;
	int err = -ENOENT;

	ext2_find_entry (&cur_de, dir, dentry, &page);
	if (!cur_de.real_addr)
		goto out;

	err = ext2_delete_entry (&cur_de, page);
	if (err)
		goto out;

	inode->i_ctime = dir->i_ctime;
	inode_dec_link_count(inode);
	err = 0;
out:
	return err;
}

static int ext2_rmdir (struct _inode * dir, struct _dentry *dentry)
{
	struct _inode * inode = d_get_inode(dentry);
	int err = -ENOTEMPTY;

	if (ext2_empty_dir(inode)) {
		err = ext2_unlink(dir, dentry);
		if (!err) {
			inode->i_size = 0;
			inode_dec_link_count(inode);
			inode_dec_link_count(dir);
		}
	}
	return err;
}

static int ext2_rename (struct _inode * old_dir, struct _dentry * old_dentry,
			struct _inode * new_dir, struct _dentry * new_dentry )
{
	struct _inode * old_inode = d_get_inode(old_dentry);
	struct _inode * new_inode = d_get_inode(new_dentry);
	struct page * dir_page = NULL;
	struct ext2_cur_sdirent dir_de = {.real_addr = NULL};
	struct page * old_page;
	struct ext2_cur_sdirent old_de = {.real_addr = NULL};
	int err = -ENOENT;

	ext2_find_entry (&old_de, old_dir, old_dentry, &old_page);
	if (!old_de.real_addr)
		goto out;

	if (S_ISDIR(old_inode->i_mode)) {
		err = -EIO;
		ext2_dotdot(&dir_de, old_inode, &dir_page);
		if (!dir_de.real_addr)
			goto out_old;
	}

	if (new_inode) {
		struct page *new_page;
		struct ext2_cur_sdirent new_de;

		err = -ENOTEMPTY;
		if (dir_de.real_addr && !ext2_empty_dir (new_inode))
			goto out_dir;

		err = -ENOENT;
		ext2_find_entry (&new_de, new_dir, new_dentry, &new_page);
		if (!new_de.real_addr)
			goto out_dir;
		inode_inc_link_count(old_inode);
		ext2_set_link(new_dir, &new_de, new_page, old_inode);
		new_inode->i_ctime = CURRENT_TIME_SEC;
		if (dir_de.real_addr)
			drop_nlink(new_inode);
		inode_dec_link_count(new_inode);
	} else {
		if (dir_de.real_addr) {
			err = -EMLINK;
			if (new_dir->i_nlink >= EXT2_LINK_MAX)
				goto out_dir;
		}
		inode_inc_link_count(old_inode);
		err = ext2_add_link(new_dentry, old_inode);
		if (err) {
			inode_dec_link_count(old_inode);
			goto out_dir;
		}
		if (dir_de.real_addr)
			inode_inc_link_count(new_dir);
	}

	/*
	 * Like most other Unix systems, set the ctime for inodes on a
	 * rename.
	 * inode_dec_link_count() will mark the inode dirty.
	 */
	old_inode->i_ctime = CURRENT_TIME_SEC;

	ext2_delete_entry (&old_de, old_page);

	inode_dec_link_count(old_inode);
		
	if (dir_de.real_addr) {
		inode_dec_link_count(old_dir);
		ext2_set_link(old_inode, &dir_de, dir_page, new_dir);
	}

	return 0;


out_dir:
	if (dir_de.real_addr) {
		kunmap(dir_page);
		page_cache_release(dir_page);
	}
out_old:
	kunmap(old_page);
	page_cache_release(old_page);
out:
	return err;
}

/* Speculative directory entries should be committed and aborted
 * during the phase in which blocking locks are being released,
 * after non-blocking locks were released */
static void ext2_unlock_dir_inode(struct inode *inode, int blocking) {
	if(blocking) {
		struct ext2_inode_info *ei = EXT2_I(inode);
		switch(atomic_read(&current->transaction->status)) {
			case TX_ABORTING:
				ext2_abort_sdirents(ei);
				break;
			case TX_COMMITTING:
				BUG_ON(ext2_commit_sdirents(ei));
				break;
		}
	}
}

const struct inode_operations ext2_dir_inode_operations = {
	.create		= ext2_create,
	.lookup		= ext2_lookup,
	.link		= ext2_link,
	.unlink		= ext2_unlink,
	.symlink	= ext2_symlink,
	.mkdir		= ext2_mkdir,
	.rmdir		= ext2_rmdir,
	.mknod		= ext2_mknod,
	.rename		= ext2_rename,
#ifdef CONFIG_EXT2_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext2_listxattr,
	.removexattr	= generic_removexattr,
#endif
	.setattr	= ext2_setattr,
	.permission	= ext2_permission,
#ifdef CONFIG_TX_KSTM
	.validate		 = ext2_validate_inode,
	.unlock			 = ext2_unlock_dir_inode,
	.init_tx			 = ext2_init_sdirents,
#endif
};

const struct inode_operations ext2_special_inode_operations = {
#ifdef CONFIG_EXT2_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext2_listxattr,
	.removexattr	= generic_removexattr,
#endif
	.setattr	= ext2_setattr,
	.permission	= ext2_permission,
#ifdef CONFIG_TX_KSTM
	.validate       = ext2_validate_inode,
#endif
};
