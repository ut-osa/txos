/* -*- linux-c -*- --------------------------------------------------------- *
 *
 * linux/fs/devpts/inode.c
 *
 *  Copyright 1998-2004 H. Peter Anvin -- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * ------------------------------------------------------------------------- */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/tty.h>
#include <linux/devpts_fs.h>
#include <linux/parser.h>
#include <linux/fsnotify.h>
#include <linux/tx_dentry.h>

#define DEVPTS_SUPER_MAGIC 0x1cd1

static struct vfsmount *devpts_mnt;
static struct dentry *devpts_root;

static struct {
	int setuid;
	int setgid;
	uid_t   uid;
	gid_t   gid;
	umode_t mode;
} config = {.mode = 0600};

enum {
	Opt_uid, Opt_gid, Opt_mode,
	Opt_err
};

static match_table_t tokens = {
	{Opt_uid, "uid=%u"},
	{Opt_gid, "gid=%u"},
	{Opt_mode, "mode=%o"},
	{Opt_err, NULL}
};

static int devpts_remount(struct super_block *sb, int *flags, char *data)
{
	char *p;

	config.setuid  = 0;
	config.setgid  = 0;
	config.uid     = 0;
	config.gid     = 0;
	config.mode    = 0600;

	while ((p = strsep(&data, ",")) != NULL) {
		substring_t args[MAX_OPT_ARGS];
		int token;
		int option;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_uid:
			if (match_int(&args[0], &option))
				return -EINVAL;
			config.uid = option;
			config.setuid = 1;
			break;
		case Opt_gid:
			if (match_int(&args[0], &option))
				return -EINVAL;
			config.gid = option;
			config.setgid = 1;
			break;
		case Opt_mode:
			if (match_octal(&args[0], &option))
				return -EINVAL;
			config.mode = option & ~S_IFMT;
			break;
		default:
			printk(KERN_ERR "devpts: called with bogus options\n");
			return -EINVAL;
		}
	}

	return 0;
}

static const struct super_operations devpts_sops = {
	.statfs		= simple_statfs,
	.remount_fs	= devpts_remount,
};

static int
devpts_fill_super(struct super_block *s, void *data, int silent)
{
	struct inode * inode;
	struct _inode * _inode;

	s->s_blocksize = 1024;
	s->s_blocksize_bits = 10;
	s->s_magic = DEVPTS_SUPER_MAGIC;
	s->s_op = &devpts_sops;
	s->s_time_gran = 1;

	inode = new_inode(s);
	if (!inode)
		goto fail;
	_inode = tx_cache_get_inode(inode);
	_inode->i_ino = 1;
	_inode->i_mtime = _inode->i_atime = _inode->i_ctime = CURRENT_TIME;
	inode->i_blocks = 0;
	_inode->i_uid = _inode->i_gid = 0;
	_inode->i_mode = S_IFDIR | S_IRUGO | S_IXUGO | S_IWUSR;
	_inode->i_op = &simple_dir_inode_operations;
	_inode->i_fop = &simple_dir_operations;
	_inode->i_nlink = 2;

	devpts_root = s->s_root = d_alloc_root(_inode);
	if (s->s_root)
		return 0;
	
	printk("devpts: get root dentry failed\n");
	iput(inode);
fail:
	return -ENOMEM;
}

static int devpts_get_sb(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data, struct vfsmount *mnt)
{
	return get_sb_single(fs_type, flags, data, devpts_fill_super, mnt);
}

static struct file_system_type devpts_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "devpts",
	.get_sb		= devpts_get_sb,
	.kill_sb	= kill_anon_super,
};

/*
 * The normal naming convention is simply /dev/pts/<number>; this conforms
 * to the System V naming convention
 */

static struct _dentry *get_node(int num)
{
	char s[12];
	struct _dentry *root = tx_cache_get_dentry(devpts_root);
	mutex_lock(&root->d_inode->i_mutex);
	/* DEP 6/9/10 - As we approach more solid device support, we
	 * may want to revisit later.  For now, just manually lock
	 * these acquires.
	 */
	record_tx_lock(&root->d_inode->i_mutex, MUTEX);
	return lookup_one_len(s, &root, sprintf(s, "%d", num));
}

int devpts_pty_new(struct tty_struct *tty)
{
	int number = tty->index;
	struct tty_driver *driver = tty->driver;
	dev_t device = MKDEV(driver->major, driver->minor_start+number);
	struct _dentry *dentry;
	struct inode *inode = new_inode(devpts_mnt->mnt_sb);
	struct _inode *_inode;
	struct _dentry *root = tx_cache_get_dentry(devpts_root);

	/* We're supposed to be given the slave end of a pty */
	BUG_ON(driver->type != TTY_DRIVER_TYPE_PTY);
	BUG_ON(driver->subtype != PTY_TYPE_SLAVE);

	if (!inode)
		return -ENOMEM;

	_inode = tx_cache_get_inode(inode);
	_inode->i_ino = number+2;
	_inode->i_uid = config.setuid ? config.uid : current->fsuid;
	_inode->i_gid = config.setgid ? config.gid : current->fsgid;
	_inode->i_mtime = _inode->i_atime = _inode->i_ctime = CURRENT_TIME;
	init_special_inode(_inode, S_IFCHR|config.mode, device);
	inode->i_private = tty;

	dentry = get_node(number);
	if (!IS_ERR(dentry) && !dentry->d_inode) {
		d_instantiate(dentry, _inode);
		fsnotify_create(root->d_inode, parent(dentry));
	}

	mutex_unlock(&root->d_inode->i_mutex);
	record_tx_unlock(&root->d_inode->i_mutex, MUTEX);

	return 0;
}

struct tty_struct *devpts_get_tty(int number)
{
	struct _dentry *dentry = get_node(number);
	struct tty_struct *tty;
	struct inode *inode;

	tty = NULL;
	if (!IS_ERR(dentry)) {
		if (dentry->d_inode)
			tty = dentry->d_inode->i_private;
		dput(parent(dentry));
	}

	inode = tx_cache_get_dentry(devpts_root)->d_inode;
	mutex_unlock(&inode->i_mutex);
	record_tx_unlock(&inode->i_mutex, MUTEX);

	return tty;
}

void devpts_pty_kill(int number)
{
	struct _dentry *dentry = get_node(number);
	struct inode *inode;

	if (!IS_ERR(dentry)) {
		struct _inode *inode = d_get_inode(dentry);
		if (inode) {
			inode->i_nlink--;
			d_delete(dentry);
			dput(parent(dentry));
		}
		dput(parent(dentry));
	}
	inode = tx_cache_get_dentry(devpts_root)->d_inode;
	mutex_unlock(&inode->i_mutex);
	record_tx_unlock(&inode->i_mutex, MUTEX);
}

static int __init init_devpts_fs(void)
{
	int err = register_filesystem(&devpts_fs_type);
	if (!err) {
		devpts_mnt = kern_mount(&devpts_fs_type);
		if (IS_ERR(devpts_mnt))
			err = PTR_ERR(devpts_mnt);
	}
	return err;
}

static void __exit exit_devpts_fs(void)
{
	unregister_filesystem(&devpts_fs_type);
	mntput(devpts_mnt);
}

module_init(init_devpts_fs)
module_exit(exit_devpts_fs)
MODULE_LICENSE("GPL");
