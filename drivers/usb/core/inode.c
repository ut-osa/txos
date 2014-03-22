/*****************************************************************************/

/*
 *	inode.c  --  Inode/Dentry functions for the USB device file system.
 *
 *	Copyright (C) 2000 Thomas Sailer (sailer@ife.ee.ethz.ch)
 *	Copyright (C) 2001,2002,2004 Greg Kroah-Hartman (greg@kroah.com)
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *  History:
 *   0.1  04.01.2000  Created
 *   0.2  10.12.2001  converted to use the vfs layer better
 */

/*****************************************************************************/

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/usb.h>
#include <linux/namei.h>
#include <linux/usbdevice_fs.h>
#include <linux/parser.h>
#include <linux/notifier.h>
#include <asm/byteorder.h>
#include "usb.h"
#include "hcd.h"

#include <linux/tx_inodes.h>
#include <linux/tx_dentry.h>
#include <linux/tx_file.h>

static struct super_operations usbfs_ops;
static const struct file_operations default_file_operations;
static struct vfsmount *usbfs_mount;
static int usbfs_mount_count;	/* = 0 */
static int ignore_mount = 0;

static struct dentry *devices_usbfs_dentry;
static int num_buses;	/* = 0 */

static uid_t devuid;	/* = 0 */
static uid_t busuid;	/* = 0 */
static uid_t listuid;	/* = 0 */
static gid_t devgid;	/* = 0 */
static gid_t busgid;	/* = 0 */
static gid_t listgid;	/* = 0 */
static umode_t devmode = S_IWUSR | S_IRUGO;
static umode_t busmode = S_IXUGO | S_IRUGO;
static umode_t listmode = S_IRUGO;

enum {
	Opt_devuid, Opt_devgid, Opt_devmode,
	Opt_busuid, Opt_busgid, Opt_busmode,
	Opt_listuid, Opt_listgid, Opt_listmode,
	Opt_err,
};

static match_table_t tokens = {
	{Opt_devuid, "devuid=%u"},
	{Opt_devgid, "devgid=%u"},
	{Opt_devmode, "devmode=%o"},
	{Opt_busuid, "busuid=%u"},
	{Opt_busgid, "busgid=%u"},
	{Opt_busmode, "busmode=%o"},
	{Opt_listuid, "listuid=%u"},
	{Opt_listgid, "listgid=%u"},
	{Opt_listmode, "listmode=%o"},
	{Opt_err, NULL}
};

static int parse_options(struct super_block *s, char *data)
{
	char *p;
	int option;

	/* (re)set to defaults. */
	devuid = 0;
	busuid = 0;
	listuid = 0;
	devgid = 0;
	busgid = 0;
	listgid = 0;
	devmode = S_IWUSR | S_IRUGO;
	busmode = S_IXUGO | S_IRUGO;
	listmode = S_IRUGO;

	while ((p = strsep(&data, ",")) != NULL) {
		substring_t args[MAX_OPT_ARGS];
		int token;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_devuid:
			if (match_int(&args[0], &option))
			       return -EINVAL;
			devuid = option;
			break;
		case Opt_devgid:
			if (match_int(&args[0], &option))
			       return -EINVAL;
			devgid = option;
			break;
		case Opt_devmode:
			if (match_octal(&args[0], &option))
				return -EINVAL;
			devmode = option & S_IRWXUGO;
			break;
		case Opt_busuid:
			if (match_int(&args[0], &option))
			       return -EINVAL;
			busuid = option;
			break;
		case Opt_busgid:
			if (match_int(&args[0], &option))
			       return -EINVAL;
			busgid = option;
			break;
		case Opt_busmode:
			if (match_octal(&args[0], &option))
				return -EINVAL;
			busmode = option & S_IRWXUGO;
			break;
		case Opt_listuid:
			if (match_int(&args[0], &option))
			       return -EINVAL;
			listuid = option;
			break;
		case Opt_listgid:
			if (match_int(&args[0], &option))
			       return -EINVAL;
			listgid = option;
			break;
		case Opt_listmode:
			if (match_octal(&args[0], &option))
				return -EINVAL;
			listmode = option & S_IRWXUGO;
			break;
		default:
			err("usbfs: unrecognised mount option \"%s\" "
			    "or missing value\n", p);
			return -EINVAL;
		}
	}

	return 0;
}

static void update_special(struct _dentry *special)
{
	struct _inode *inode = d_get_inode(special);
	inode->i_uid = listuid;
	inode->i_gid = listgid;
	inode->i_mode = S_IFREG | listmode;
}

static void update_dev(struct _dentry *dev)
{
	struct _inode *inode = d_get_inode(dev);
	inode->i_uid = devuid;
	inode->i_gid = devgid;
	inode->i_mode = S_IFREG | devmode;
}

static void update_bus(struct dentry *bus)
{
	struct _inode *inode = dentry_get_inode(bus);
	struct tx_list2_iterator iter;

	inode->i_uid = busuid;
	inode->i_gid = busgid;
	inode->i_mode = S_IFDIR | busmode;

	_imutex_lock(inode);
	tx_list2_get_iterator(&iter, &bus->d_subdirs);
	while (tx_list2_iter_next(&iter)){
		struct dentry *dev = tx_list2_iter_entry(&iter, struct dentry, d_child);
		struct _dentry *_dev = tx_cache_get_dentry(dev);
		if (_dev->d_inode)
			update_dev(_dev);
	}
	tx_list2_put_iterator(&iter);

	_imutex_unlock(inode);
}

static void update_sb(struct super_block *sb)
{
	struct dentry *root = sb->s_root;
	struct dentry *bus = NULL;
	struct _dentry *_bus;
	struct inode *root_inode = tx_cache_get_dentry(root)->d_inode;
	struct tx_list2_iterator iter;

	if (!root)
		return;

	mutex_lock_nested(&root_inode->i_mutex, I_MUTEX_PARENT);

	tx_list2_get_iterator(&iter, &root->d_subdirs);
	while (tx_list2_iter_next(&iter)){
		bus = tx_list2_iter_entry(&iter, struct dentry, d_child);
		_bus = tx_cache_get_dentry(bus);
		
		if (_bus->d_inode) {
			struct _inode *bus_inode = d_get_inode(_bus);
			switch (S_IFMT & bus_inode->i_mode) {
			case S_IFDIR:
				update_bus(bus);
				break;
			case S_IFREG:
				update_special(_bus);
				break;
			default:
				warn("Unknown node %s mode %x found on remount!\n",_bus->d_name.name,bus_inode->i_mode);
				break;
			}
		}
	}
	tx_list2_put_iterator(&iter);

	mutex_unlock(&root_inode->i_mutex);
}

static int remount(struct super_block *sb, int *flags, char *data)
{
	/* If this is not a real mount,
	 * i.e. it's a simple_pin_fs from create_special_files,
	 * then ignore it.
	 */
	if (ignore_mount)
		return 0;

	if (parse_options(sb, data)) {
		warn("usbfs: mount parameter error:");
		return -EINVAL;
	}

	if (usbfs_mount && usbfs_mount->mnt_sb)
		update_sb(usbfs_mount->mnt_sb);

	return 0;
}

static struct inode *usbfs_get_inode (struct super_block *sb, int mode, dev_t dev)
{
	struct inode *inode = new_inode(sb);

	if (inode) {
		struct _inode *_inode = tx_cache_get_inode(inode);

		_inode->i_mode = mode;
		_inode->i_uid = current->fsuid;
		_inode->i_gid = current->fsgid;
		inode->i_blocks = 0;
		_inode->i_atime = _inode->i_mtime = _inode->i_ctime = CURRENT_TIME;
		switch (mode & S_IFMT) {
		default:
			init_special_inode(_inode, mode, dev);
			break;
		case S_IFREG:
			_inode->i_fop = &default_file_operations;
			break;
		case S_IFDIR:
			_inode->i_op = &simple_dir_inode_operations;
			_inode->i_fop = &simple_dir_operations;

			/* directory inodes start off with i_nlink == 2 (for "." entry) */
			inc_nlink(_inode);
			break;
		}
	}
	return inode; 
}

/* SMP-safe */
static int usbfs_mknod (struct _inode *dir, struct _dentry *dentry, int mode,
			dev_t dev)
{
	struct inode *inode = usbfs_get_inode(dir->i_sb, mode, dev);
	struct _inode *_inode = tx_cache_get_inode(inode);
	int error = -EPERM;

	if (dentry->d_inode)
		return -EEXIST;

	if (inode) {
		d_instantiate(dentry, _inode);
		dget(parent(dentry));
		error = 0;
	}
	return error;
}

static int usbfs_mkdir (struct _inode *dir, struct _dentry *dentry, int mode)
{
	int res;

	mode = (mode & (S_IRWXUGO | S_ISVTX)) | S_IFDIR;
	res = usbfs_mknod (dir, dentry, mode, 0);
	if (!res)
		inc_nlink(dir);
	return res;
}

static int usbfs_create (struct _inode *dir, struct _dentry *dentry, int mode)
{
	mode = (mode & S_IALLUGO) | S_IFREG;
	return usbfs_mknod (dir, dentry, mode, 0);
}

static inline int usbfs_positive (struct _dentry *dentry)
{
	return dentry->d_inode && !d_unhashed(dentry);
}

static int usbfs_empty (struct dentry *dentry)
{
	struct tx_list2_iterator iter;

	spin_lock(&dcache_lock);

	tx_list2_get_iterator(&iter, &dentry->d_subdirs);
	while (tx_list2_iter_next(&iter)){
		struct dentry *de = tx_list2_iter_entry(&iter, struct dentry, d_child);
		if (usbfs_positive(tx_cache_get_dentry(de))) {
			spin_unlock(&dcache_lock);
			return 0;
		}
	}
	tx_list2_put_iterator(&iter);

	spin_unlock(&dcache_lock);
	return 1;
}

static int usbfs_unlink (struct _inode *dir, struct _dentry *dentry)
{
	struct _inode *inode = d_get_inode(dentry);
	_imutex_lock(inode);
	drop_nlink(inode);
	dput(parent(dentry));
	_imutex_unlock(inode);
	d_delete(dentry);
	return 0;
}

static int usbfs_rmdir(struct _inode *dir, struct _dentry *dentry)
{
	int error = -ENOTEMPTY;
	struct _inode * inode = d_get_inode(dentry);

	_imutex_lock(inode);
	dentry_unhash(parent(dentry));
	if (usbfs_empty(parent(dentry))) {
		drop_nlink(inode);
		drop_nlink(inode);
		dput(parent(dentry));
		inode->i_flags |= S_DEAD;
		drop_nlink(dir);
		error = 0;
	}
	_imutex_unlock(inode);
	if (!error)
		d_delete(dentry);
	dput(parent(dentry));
	return error;
}


/* default file operations */
static ssize_t default_read_file (struct file *file, char __user *buf,
				  size_t count, loff_t *ppos)
{
	return 0;
}

static ssize_t default_write_file (struct file *file, const char __user *buf,
				   size_t count, loff_t *ppos)
{
	return count;
}

static loff_t default_file_lseek (struct _file *file, loff_t offset, int orig)
{
	loff_t retval = -EINVAL;
	struct inode *inode = f_get_dentry(file)->d_inode;

	mutex_lock(&inode->i_mutex);
	switch(orig) {
	case 0:
		if (offset > 0) {
			file->f_pos = offset;
			retval = file->f_pos;
		} 
		break;
	case 1:
		if ((offset + file->f_pos) > 0) {
			file->f_pos += offset;
			retval = file->f_pos;
		} 
		break;
	default:
		break;
	}
	mutex_unlock(&inode->i_mutex);
	return retval;
}

static int default_open (struct _inode *inode, struct file *file)
{
	if (parent(inode)->i_private)
		file->private_data = parent(inode)->i_private;

	return 0;
}

static const struct file_operations default_file_operations = {
	.read =		default_read_file,
	.write =	default_write_file,
	.open =		default_open,
	.llseek =	default_file_lseek,
};

static struct super_operations usbfs_ops = {
	.statfs =	simple_statfs,
	.drop_inode =	generic_delete_inode,
	.remount_fs =	remount,
};

static int usbfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *inode;
	struct dentry *root;

	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = USBDEVICE_SUPER_MAGIC;
	sb->s_op = &usbfs_ops;
	sb->s_time_gran = 1;
	inode = usbfs_get_inode(sb, S_IFDIR | 0755, 0);

	if (!inode) {
		dbg("%s: could not get inode!",__FUNCTION__);
		return -ENOMEM;
	}

	root = d_alloc_root(tx_cache_get_inode(inode));
	if (!root) {
		dbg("%s: could not get root dentry!",__FUNCTION__);
		iput(inode);
		return -ENOMEM;
	}
	sb->s_root = root;
	return 0;
}

/*
 * fs_create_by_name - create a file, given a name
 * @name:	name of file
 * @mode:	type of file
 * @parent:	dentry of directory to create it in
 * @dentry:	resulting dentry of file
 *
 * This function handles both regular files and directories.
 */
static int fs_create_by_name (const char *name, mode_t mode,
			      struct _dentry *parent, struct _dentry **dentry)
{
	int error = 0;

	/* If the parent is not specified, we create it in the root.
	 * We need the root dentry to do this, which is in the super 
	 * block. A pointer to that is in the struct vfsmount that we
	 * have around.
	 */
	if (!parent ) {
		if (usbfs_mount && usbfs_mount->mnt_sb) {
			parent = tx_cache_get_dentry(usbfs_mount->mnt_sb->s_root);
		}
	}

	if (!parent) {
		dbg("Ah! can not find a parent!");
		return -EFAULT;
	}

	*dentry = NULL;
	mutex_lock(&parent->d_inode->i_mutex);
	*dentry = lookup_one_len(name, &parent, strlen(name));
	if (!IS_ERR(dentry)) {
		if ((mode & S_IFMT) == S_IFDIR)
			error = usbfs_mkdir (d_get_inode(parent), *dentry, mode);
		else 
			error = usbfs_create (d_get_inode(parent), *dentry, mode);
	} else
		error = PTR_ERR(dentry);
	mutex_unlock(&parent->d_inode->i_mutex);

	return error;
}

static struct dentry *fs_create_file (const char *name, mode_t mode,
				      struct _dentry *parent, void *data,
				      const struct file_operations *fops,
				      uid_t uid, gid_t gid)
{
	struct _dentry *dentry;
	int error;

	dbg("creating file '%s'",name);

	error = fs_create_by_name (name, mode, parent, &dentry);
	if (error) {
		dentry = NULL;
	} else {
		if (dentry->d_inode) {
			struct _inode *inode = d_get_inode(dentry);
			if (data)
				dentry->d_inode->i_private = data;
			if (fops)
				inode->i_fop = fops;
			inode->i_uid = uid;
			inode->i_gid = gid;
		}
	}

	return parent(dentry);
}

static void fs_remove_file (struct _dentry *dentry)
{
	struct _dentry *parent = tx_cache_get_dentry(dentry->d_parent);
	
	if (!parent || !parent->d_inode)
		return;

	mutex_lock_nested(&parent->d_inode->i_mutex, I_MUTEX_PARENT);
	if (usbfs_positive(dentry)) {
		if (dentry->d_inode) {
			struct _inode *inode = d_get_inode(dentry);
			if (S_ISDIR(inode->i_mode))
				usbfs_rmdir(d_get_inode(parent), dentry);
			else
				usbfs_unlink(d_get_inode(parent), dentry);
			dput(parent(dentry));
		}
	}
	mutex_unlock(&parent->d_inode->i_mutex);
}

/* --------------------------------------------------------------------- */

static int usb_get_sb(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data, struct vfsmount *mnt)
{
	return get_sb_single(fs_type, flags, data, usbfs_fill_super, mnt);
}

static struct file_system_type usb_fs_type = {
	.owner =	THIS_MODULE,
	.name =		"usbfs",
	.get_sb =	usb_get_sb,
	.kill_sb =	kill_litter_super,
};

/* --------------------------------------------------------------------- */

static int create_special_files (void)
{
	struct dentry *parent;
	int retval;

	/* the simple_pin_fs calls will call remount with no options
	 * without this flag that would overwrite the real mount options (if any)
	 */
	ignore_mount = 1;

	/* create the devices special file */
	retval = simple_pin_fs(&usb_fs_type, &usbfs_mount, &usbfs_mount_count);
	if (retval) {
		err ("Unable to get usbfs mount");
		goto exit;
	}

	ignore_mount = 0;

	parent = usbfs_mount->mnt_sb->s_root;
	devices_usbfs_dentry = fs_create_file ("devices",
					       listmode | S_IFREG, tx_cache_get_dentry(parent),
					       NULL, &usbfs_devices_fops,
					       listuid, listgid);
	if (devices_usbfs_dentry == NULL) {
		err ("Unable to create devices usbfs file");
		retval = -ENODEV;
		goto error_clean_mounts;
	}

	goto exit;
	
error_clean_mounts:
	simple_release_fs(&usbfs_mount, &usbfs_mount_count);
exit:
	return retval;
}

static void remove_special_files (void)
{
	if (devices_usbfs_dentry)
		fs_remove_file (tx_cache_get_dentry(devices_usbfs_dentry));
	devices_usbfs_dentry = NULL;
	simple_release_fs(&usbfs_mount, &usbfs_mount_count);
}

void usbfs_update_special (void)
{
	struct _inode *inode;

	if (devices_usbfs_dentry) {
		inode = dentry_get_inode(devices_usbfs_dentry);
		if (inode)
			inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	}
}

static void usbfs_add_bus(struct usb_bus *bus)
{
	struct dentry *parent;
	char name[8];
	int retval;

	/* create the special files if this is the first bus added */
	if (num_buses == 0) {
		retval = create_special_files();
		if (retval)
			return;
	}
	++num_buses;

	sprintf (name, "%03d", bus->busnum);

	parent = usbfs_mount->mnt_sb->s_root;
	bus->usbfs_dentry = fs_create_file (name, busmode | S_IFDIR, 
					    tx_cache_get_dentry(parent),
					    bus, NULL, busuid, busgid);
	if (bus->usbfs_dentry == NULL) {
		err ("error creating usbfs bus entry");
		return;
	}
}

static void usbfs_remove_bus(struct usb_bus *bus)
{
	if (bus->usbfs_dentry) {
		fs_remove_file (tx_cache_get_dentry(bus->usbfs_dentry));
		bus->usbfs_dentry = NULL;
	}

	--num_buses;
	if (num_buses <= 0) {
		remove_special_files();
		num_buses = 0;
	}
}

static void usbfs_add_device(struct usb_device *dev)
{
	char name[8];
	int i;
	int i_size;
	struct _dentry *usbfs_dentry;

	sprintf (name, "%03d", dev->devnum);
	dev->usbfs_dentry = fs_create_file (name, devmode | S_IFREG,
					    tx_cache_get_dentry(dev->bus->usbfs_dentry), dev,
					    &usbdev_file_operations,
					    devuid, devgid);
	if (dev->usbfs_dentry == NULL) {
		err ("error creating usbfs device entry");
		return;
	}

	/* Set the size of the device's file to be
	 * equal to the size of the device descriptors. */
	i_size = sizeof (struct usb_device_descriptor);
	for (i = 0; i < dev->descriptor.bNumConfigurations; ++i) {
		struct usb_config_descriptor *config =
			(struct usb_config_descriptor *)dev->rawdescriptors[i];
		i_size += le16_to_cpu(config->wTotalLength);
	}
	usbfs_dentry = tx_cache_get_dentry(dev->usbfs_dentry);
	if (usbfs_dentry->d_inode)
		d_get_inode(usbfs_dentry)->i_size = i_size;
}

static void usbfs_remove_device(struct usb_device *dev)
{
	struct dev_state *ds;
	struct siginfo sinfo;

	if (dev->usbfs_dentry) {
		fs_remove_file (tx_cache_get_dentry(dev->usbfs_dentry));
		dev->usbfs_dentry = NULL;
	}
	while (!list_empty(&dev->filelist)) {
		ds = list_entry(dev->filelist.next, struct dev_state, list);
		wake_up_all(&ds->wait);
		list_del_init(&ds->list);
		if (ds->discsignr) {
			sinfo.si_signo = ds->discsignr;
			sinfo.si_errno = EPIPE;
			sinfo.si_code = SI_ASYNCIO;
			sinfo.si_addr = ds->disccontext;
			kill_pid_info_as_uid(ds->discsignr, &sinfo, ds->disc_pid, ds->disc_uid, ds->disc_euid, ds->secid);
		}
	}
}

static int usbfs_notify(struct notifier_block *self, unsigned long action, void *dev)
{
	switch (action) {
	case USB_DEVICE_ADD:
		usbfs_add_device(dev);
		break;
	case USB_DEVICE_REMOVE:
		usbfs_remove_device(dev);
		break;
	case USB_BUS_ADD:
		usbfs_add_bus(dev);
		break;
	case USB_BUS_REMOVE:
		usbfs_remove_bus(dev);
	}

	usbfs_update_special();
	usbfs_conn_disc_event();
	return NOTIFY_OK;
}

static struct notifier_block usbfs_nb = {
	.notifier_call = 	usbfs_notify,
};

/* --------------------------------------------------------------------- */

static struct proc_dir_entry *usbdir = NULL;

int __init usbfs_init(void)
{
	int retval;

	retval = register_filesystem(&usb_fs_type);
	if (retval)
		return retval;

	usb_register_notify(&usbfs_nb);

	/* create mount point for usbfs */
	usbdir = proc_mkdir("usb", proc_bus);

	return 0;
}

void usbfs_cleanup(void)
{
	usb_unregister_notify(&usbfs_nb);
	unregister_filesystem(&usb_fs_type);
	if (usbdir)
		remove_proc_entry("usb", proc_bus);
}

