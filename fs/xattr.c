/*
  File: fs/xattr.c

  Extended attribute handling.

  Copyright (C) 2001 by Andreas Gruenbacher <a.gruenbacher@computer.org>
  Copyright (C) 2001 SGI - Silicon Graphics, Inc <linux-xfs@oss.sgi.com>
  Copyright (c) 2004 Red Hat, Inc., James Morris <jmorris@redhat.com>
 */
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/xattr.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/module.h>
#include <linux/fsnotify.h>
#include <linux/audit.h>
#include <asm/uaccess.h>

#include <linux/transaction.h>
#include <linux/tx_inodes.h>
#include <linux/tx_super.h>

/*
 * Check permissions for extended attribute access.  This is a bit complicated
 * because different namespaces have very different rules.
 */
static int
xattr_permission(struct _inode *inode, const char *name, int mask)
{
	/*
	 * We can never set or remove an extended attribute on a read-only
	 * filesystem  or on an immutable / append-only inode.
	 */
	if (mask & MAY_WRITE) {
		if (IS_RDONLY(inode))
			return -EROFS;
		if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
			return -EPERM;
	}

	/*
	 * No restriction for security.* and system.* from the VFS.  Decision
	 * on these is left to the underlying filesystem / security module.
	 */
	if (!strncmp(name, XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN) ||
	    !strncmp(name, XATTR_SYSTEM_PREFIX, XATTR_SYSTEM_PREFIX_LEN))
		return 0;

	/*
	 * The trusted.* namespace can only be accessed by a privileged user.
	 */
	if (!strncmp(name, XATTR_TRUSTED_PREFIX, XATTR_TRUSTED_PREFIX_LEN))
		return (capable(CAP_SYS_ADMIN) ? 0 : -EPERM);

	/* In user.* namespace, only regular files and directories can have
	 * extended attributes. For sticky directories, only the owner and
	 * privileged user can write attributes.
	 */
	if (!strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN)) {
		if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
			return -EPERM;
		if (S_ISDIR(inode->i_mode) && (inode->i_mode & S_ISVTX) &&
		    (mask & MAY_WRITE) && (current->fsuid != inode->i_uid) &&
		    !capable(CAP_FOWNER))
			return -EPERM;
	}

	return permission(inode, mask, NULL);
}

int
vfs_setxattr(struct _dentry *dentry, char *name, void *value,
		size_t size, int flags)
{
	struct _inode *inode = d_get_inode(dentry);
	int error;

	_imutex_lock(inode);
	error = security_inode_setxattr(dentry, name, value, size, flags);
	if (error)
		goto out;
	error = -EOPNOTSUPP;
	if (inode->i_op->setxattr) {
		error = inode->i_op->setxattr(dentry, name, value, size, flags);
		if (!error) {
			fsnotify_xattr(parent(dentry));
			security_inode_post_setxattr(dentry, name, value,
						     size, flags);
		}
	} else if (!strncmp(name, XATTR_SECURITY_PREFIX,
				XATTR_SECURITY_PREFIX_LEN)) {
		const char *suffix = name + XATTR_SECURITY_PREFIX_LEN;
		error = security_inode_setsecurity(parent(inode), suffix, value,
						   size, flags);
		if (!error)
			fsnotify_xattr(parent(dentry));
	}
out:
	_imutex_unlock(inode);
	return error;
}
EXPORT_SYMBOL_GPL(vfs_setxattr);

ssize_t
vfs_getxattr(struct _dentry *dentry, char *name, void *value, size_t size)
{
	struct _inode *inode = d_get_inode(dentry);
	int error;

	error = xattr_permission(inode, name, MAY_READ);
	if (error)
		return error;

	error = security_inode_getxattr(dentry, name);
	if (error)
		return error;

	if (inode->i_op->getxattr)
		error = inode->i_op->getxattr(dentry, name, value, size);
	else
		error = -EOPNOTSUPP;

	if (!strncmp(name, XATTR_SECURITY_PREFIX,
				XATTR_SECURITY_PREFIX_LEN)) {
		const char *suffix = name + XATTR_SECURITY_PREFIX_LEN;
		int ret = security_inode_getsecurity(parent(inode), suffix, value,
						     size, error);
		/*
		 * Only overwrite the return value if a security module
		 * is actually active.
		 */
		if (ret != -EOPNOTSUPP)
			error = ret;
	}

	return error;
}
EXPORT_SYMBOL_GPL(vfs_getxattr);

ssize_t
vfs_listxattr(struct _dentry *d, char *list, size_t size)
{
	ssize_t error;
	struct _inode *_inode;
	error = security_inode_listxattr(d);
	if (error)
		return error;
	error = -EOPNOTSUPP;
	_inode = d_get_inode(d);
	if (_inode->i_op && _inode->i_op->listxattr) {
		error = _inode->i_op->listxattr(d, list, size);
	} else {
		error = security_inode_listsecurity(parent(_inode), list, size);
		if (size && error > size)
			error = -ERANGE;
	}
	return error;
}
EXPORT_SYMBOL_GPL(vfs_listxattr);

int
vfs_removexattr(struct _dentry *dentry, char *name)
{
	struct _inode *inode = d_get_inode(dentry);
	int error;

	if (!inode->i_op->removexattr)
		return -EOPNOTSUPP;

	error = xattr_permission(inode, name, MAY_WRITE);
	if (error)
		return error;

	error = security_inode_removexattr(dentry, name);
	if (error)
		return error;

	if(live_transaction())
		OSA_MAGIC(OSA_BREAKSIM);
	_imutex_lock(inode);
	error = inode->i_op->removexattr(dentry, name);
	_imutex_unlock(inode);

	if (!error)
		fsnotify_xattr(parent(dentry));
	return error;
}
EXPORT_SYMBOL_GPL(vfs_removexattr);


/*
 * Extended attribute SET operations
 */
static long
setxattr(struct _dentry *d, char __user *name, void __user *value,
	 size_t size, int flags)
{
	int error;
	void *kvalue = NULL;
	char kname[XATTR_NAME_MAX + 1];

	if (flags & ~(XATTR_CREATE|XATTR_REPLACE))
		return -EINVAL;

	error = strncpy_from_user(kname, name, sizeof(kname));
	if (error == 0 || error == sizeof(kname))
		error = -ERANGE;
	if (error < 0)
		return error;

	if (size) {
		if (size > XATTR_SIZE_MAX)
			return -E2BIG;
		kvalue = kmalloc(size, GFP_KERNEL);
		if (!kvalue)
			return -ENOMEM;
		if (copy_from_user(kvalue, value, size)) {
			kfree(kvalue);
			return -EFAULT;
		}
	}

	error = vfs_setxattr(d, kname, kvalue, size, flags);
	kfree(kvalue);
	return error;
}

asmlinkage long
sys_setxattr(char __user *path, char __user *name, void __user *value,
	     size_t size, int flags)
{
	struct nameidata nd;
	int error;

	error = user_path_walk(path, &nd);
	if (error)
		return error;
	error = setxattr(nd.dentry, name, value, size, flags);
	path_release(&nd);
	return error;
}

asmlinkage long
sys_lsetxattr(char __user *path, char __user *name, void __user *value,
	      size_t size, int flags)
{
	struct nameidata nd;
	int error;

	error = user_path_walk_link(path, &nd);
	if (error)
		return error;
	error = setxattr(nd.dentry, name, value, size, flags);
	path_release(&nd);
	return error;
}

asmlinkage long
sys_fsetxattr(int fd, char __user *name, void __user *value,
	      size_t size, int flags)
{
	struct file *f;
	struct _dentry *dentry;
	int error = -EBADF;

	f = fget(fd);
	if (!f)
		return error;
	dentry = file_get_dentry(f);
	audit_inode(NULL, dentry->d_inode);
	error = setxattr(dentry, name, value, size, flags);
	fput(f);
	return error;
}

/*
 * Extended attribute GET operations
 */
static ssize_t
getxattr(struct _dentry *d, char __user *name, void __user *value, size_t size)
{
	ssize_t error;
	void *kvalue = NULL;
	char kname[XATTR_NAME_MAX + 1];

	error = strncpy_from_user(kname, name, sizeof(kname));
	if (error == 0 || error == sizeof(kname))
		error = -ERANGE;
	if (error < 0)
		return error;

	if (size) {
		if (size > XATTR_SIZE_MAX)
			size = XATTR_SIZE_MAX;
		kvalue = kzalloc(size, GFP_KERNEL);
		if (!kvalue)
			return -ENOMEM;
	}

	error = vfs_getxattr(d, kname, kvalue, size);
	if (error > 0) {
		if (size && copy_to_user(value, kvalue, error))
			error = -EFAULT;
	} else if (error == -ERANGE && size >= XATTR_SIZE_MAX) {
		/* The file system tried to returned a value bigger
		   than XATTR_SIZE_MAX bytes. Not possible. */
		error = -E2BIG;
	}
	kfree(kvalue);
	return error;
}

asmlinkage ssize_t
sys_getxattr(char __user *path, char __user *name, void __user *value,
	     size_t size)
{
	struct nameidata nd;
	ssize_t error;

	error = user_path_walk(path, &nd);
	if (error)
		return error;
	error = getxattr(nd.dentry, name, value, size);
	path_release(&nd);
	return error;
}

asmlinkage ssize_t
sys_lgetxattr(char __user *path, char __user *name, void __user *value,
	      size_t size)
{
	struct nameidata nd;
	ssize_t error;

	error = user_path_walk_link(path, &nd);
	if (error)
		return error;
	error = getxattr(nd.dentry, name, value, size);
	path_release(&nd);
	return error;
}

asmlinkage ssize_t
sys_fgetxattr(int fd, char __user *name, void __user *value, size_t size)
{
	struct file *f;
	ssize_t error = -EBADF;

	f = fget(fd);
	if (!f)
		return error;
	audit_inode(NULL, f->f_path.dentry->d_inode);
	error = getxattr(file_get_dentry(f), name, value, size);
	fput(f);
	return error;
}

/*
 * Extended attribute LIST operations
 */
static ssize_t
listxattr(struct _dentry *d, char __user *list, size_t size)
{
	ssize_t error;
	char *klist = NULL;

	if (size) {
		if (size > XATTR_LIST_MAX)
			size = XATTR_LIST_MAX;
		klist = kmalloc(size, GFP_KERNEL);
		if (!klist)
			return -ENOMEM;
	}

	error = vfs_listxattr(d, klist, size);
	if (error > 0) {
		if (size && copy_to_user(list, klist, error))
			error = -EFAULT;
	} else if (error == -ERANGE && size >= XATTR_LIST_MAX) {
		/* The file system tried to returned a list bigger
		   than XATTR_LIST_MAX bytes. Not possible. */
		error = -E2BIG;
	}
	kfree(klist);
	return error;
}

asmlinkage ssize_t
sys_listxattr(char __user *path, char __user *list, size_t size)
{
	struct nameidata nd;
	ssize_t error;

	error = user_path_walk(path, &nd);
	if (error)
		return error;
	error = listxattr(nd.dentry, list, size);
	path_release(&nd);
	return error;
}

asmlinkage ssize_t
sys_llistxattr(char __user *path, char __user *list, size_t size)
{
	struct nameidata nd;
	ssize_t error;

	error = user_path_walk_link(path, &nd);
	if (error)
		return error;
	error = listxattr(nd.dentry, list, size);
	path_release(&nd);
	return error;
}

asmlinkage ssize_t
sys_flistxattr(int fd, char __user *list, size_t size)
{
	struct file *f;
	ssize_t error = -EBADF;
	struct _dentry *dentry;

	f = fget(fd);
	if (!f)
		return error;
	dentry = file_get_dentry(f);
	audit_inode(NULL, dentry->d_inode);
	error = listxattr(dentry, list, size);
	fput(f);
	return error;
}

/*
 * Extended attribute REMOVE operations
 */
static long
removexattr(struct _dentry *d, char __user *name)
{
	int error;
	char kname[XATTR_NAME_MAX + 1];

	error = strncpy_from_user(kname, name, sizeof(kname));
	if (error == 0 || error == sizeof(kname))
		error = -ERANGE;
	if (error < 0)
		return error;

	return vfs_removexattr(d, kname);
}

asmlinkage long
sys_removexattr(char __user *path, char __user *name)
{
	struct nameidata nd;
	int error;

	error = user_path_walk(path, &nd);
	if (error)
		return error;
	error = removexattr(nd.dentry, name);
	path_release(&nd);
	return error;
}

asmlinkage long
sys_lremovexattr(char __user *path, char __user *name)
{
	struct nameidata nd;
	int error;

	error = user_path_walk_link(path, &nd);
	if (error)
		return error;
	error = removexattr(nd.dentry, name);
	path_release(&nd);
	return error;
}

asmlinkage long
sys_fremovexattr(int fd, char __user *name)
{
	struct file *f;
	struct _dentry *dentry;
	int error = -EBADF;

	f = fget(fd);
	if (!f)
		return error;
	dentry = file_get_dentry(f);
	audit_inode(NULL, dentry->d_inode);
	error = removexattr(dentry, name);
	fput(f);
	return error;
}


static const char *
strcmp_prefix(const char *a, const char *a_prefix)
{
	while (*a_prefix && *a == *a_prefix) {
		a++;
		a_prefix++;
	}
	return *a_prefix ? NULL : a;
}

/*
 * In order to implement different sets of xattr operations for each xattr
 * prefix with the generic xattr API, a filesystem should create a
 * null-terminated array of struct xattr_handler (one for each prefix) and
 * hang a pointer to it off of the s_xattr field of the superblock.
 *
 * The generic_fooxattr() functions will use this list to dispatch xattr
 * operations to the correct xattr_handler.
 */
#define for_each_xattr_handler(handlers, handler)		\
		for ((handler) = *(handlers)++;			\
			(handler) != NULL;			\
			(handler) = *(handlers)++)

/*
 * Find the xattr_handler with the matching prefix.
 */
static struct xattr_handler *
xattr_resolve_name(struct xattr_handler **handlers, const char **name)
{
	struct xattr_handler *handler;

	if (!*name)
		return NULL;

	for_each_xattr_handler(handlers, handler) {
		const char *n = strcmp_prefix(*name, handler->prefix);
		if (n) {
			*name = n;
			break;
		}
	}
	return handler;
}

/*
 * Find the handler for the prefix and dispatch its get() operation.
 */
ssize_t
generic_getxattr(struct _dentry *dentry, const char *name, void *buffer, size_t size)
{
	struct xattr_handler *handler;
	struct _inode *inode = d_get_inode(dentry);

	handler = xattr_resolve_name(inode->i_sb->s_xattr, &name);
	if (!handler)
		return -EOPNOTSUPP;
	return handler->get(inode, name, buffer, size);
}

/*
 * Combine the results of the list() operation from every xattr_handler in the
 * list.
 */
ssize_t
generic_listxattr(struct _dentry *dentry, char *buffer, size_t buffer_size)
{
	struct inode *inode = dentry->d_inode;
	struct xattr_handler *handler, **handlers = tx_cache_get_inode_ro(inode)->i_sb->s_xattr;
	unsigned int size = 0;

	if (!buffer) {
		for_each_xattr_handler(handlers, handler)
			size += handler->list(inode, NULL, 0, NULL, 0);
	} else {
		char *buf = buffer;

		for_each_xattr_handler(handlers, handler) {
			size = handler->list(inode, buf, buffer_size, NULL, 0);
			if (size > buffer_size)
				return -ERANGE;
			buf += size;
			buffer_size -= size;
		}
		size = buf - buffer;
	}
	return size;
}

/*
 * Find the handler for the prefix and dispatch its set() operation.
 */
int
generic_setxattr(struct _dentry *dentry, const char *name, const void *value, size_t size, int flags)
{
	struct xattr_handler *handler;
	struct _inode *inode = d_get_inode(dentry);

	if (size == 0)
		value = "";  /* empty EA, do not remove */
	handler = xattr_resolve_name(inode->i_sb->s_xattr, &name);
	if (!handler)
		return -EOPNOTSUPP;
	return handler->set(inode, name, value, size, flags);
}

/*
 * Find the handler for the prefix and dispatch its set() operation to remove
 * any associated extended attribute.
 */
int
generic_removexattr(struct _dentry *dentry, const char *name)
{
	struct xattr_handler *handler;
	struct _inode *inode = d_get_inode(dentry);

	handler = xattr_resolve_name(inode->i_sb->s_xattr, &name);
	if (!handler)
		return -EOPNOTSUPP;
	return handler->set(inode, name, NULL, 0, XATTR_REPLACE);
}

EXPORT_SYMBOL(generic_getxattr);
EXPORT_SYMBOL(generic_listxattr);
EXPORT_SYMBOL(generic_setxattr);
EXPORT_SYMBOL(generic_removexattr);
