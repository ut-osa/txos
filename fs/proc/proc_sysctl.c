/*
 * /proc/sys support
 */

#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/security.h>
#include "internal.h"

#include <linux/tx_inodes.h>
#include <linux/tx_super.h>
#include <linux/tx_dentry.h>
#include <linux/tx_file.h>

static struct dentry_operations proc_sys_dentry_operations;
static const struct file_operations proc_sys_file_operations;
static struct inode_operations proc_sys_inode_operations;

static void proc_sys_refresh_inode(struct _inode *inode, struct ctl_table *table)
{
	/* Refresh the cached information bits in the inode */
	if (table) {
		inode->i_uid = 0;
		inode->i_gid = 0;
		inode->i_mode = table->mode;
		if (table->proc_handler) {
			inode->i_mode |= S_IFREG;
			inode->i_nlink = 1;
		} else {
			inode->i_mode |= S_IFDIR;
			inode->i_nlink = 0;	/* It is too hard to figure out */
		}
	}
}

static struct inode *proc_sys_make_inode(struct _inode *dir, struct ctl_table *table)
{
	struct inode *inode;
	struct _inode *_inode;
	struct proc_inode *dir_ei, *ei;
	int depth;

	inode = new_inode(dir->i_sb);
	if (!inode)
		goto out;

	_inode = tx_cache_get_inode(inode);
	/* A directory is always one deeper than it's parent */
	dir_ei = PROC_I(dir);
	depth = dir_ei->fd + 1;

	ei = PROC_I(_inode);
	ei->fd = depth;
	_inode->i_mtime = _inode->i_atime = _inode->i_ctime = CURRENT_TIME;
	_inode->i_op = &proc_sys_inode_operations;
	_inode->i_fop = &proc_sys_file_operations;
	_inode->i_flags |= S_PRIVATE; /* tell selinux to ignore this inode */
	proc_sys_refresh_inode(_inode, table);
out:
	return inode;
}

static struct _dentry *proc_sys_ancestor(struct _dentry *dentry, int depth)
{
	for (;;) {
		struct proc_inode *ei;

		ei = PROC_I(d_get_inode(dentry));
		if (ei->fd == depth)
			break; /* found */

		dentry = tx_cache_get_dentry(dentry->d_parent);
	}
	return dentry;
}

static struct ctl_table *proc_sys_lookup_table_one(struct ctl_table *table,
							struct qstr *name)
{
	int len;
	for ( ; table->ctl_name || table->procname; table++) {

		if (!table->procname)
			continue;

		len = strlen(table->procname);
		if (len != name->len)
			continue;

		if (memcmp(table->procname, name->name, len) != 0)
			continue;

		/* I have a match */
		return table;
	}
	return NULL;
}

static struct ctl_table *proc_sys_lookup_table(struct _dentry *dentry,
						struct ctl_table *table)
{
	struct _dentry *ancestor;
	struct proc_inode *ei;
	int depth, i;

	ei = PROC_I(d_get_inode(dentry));
	depth = ei->fd;

	if (depth == 0)
		return table;

	for (i = 1; table && (i <= depth); i++) {
		ancestor = proc_sys_ancestor(dentry, i);
		table = proc_sys_lookup_table_one(table, &ancestor->d_name);
		if (table)
			table = table->child;
	}
	return table;

}
static struct ctl_table *proc_sys_lookup_entry(struct _dentry *dparent,
						struct qstr *name,
						struct ctl_table *table)
{
	table = proc_sys_lookup_table(dparent, table);
	if (table)
		table = proc_sys_lookup_table_one(table, name);
	return table;
}

static struct ctl_table *do_proc_sys_lookup(struct _dentry *parent,
						struct qstr *name,
						struct ctl_table_header **ptr)
{
	struct ctl_table_header *head;
	struct ctl_table *table = NULL;

	for (head = sysctl_head_next(NULL); head;
			head = sysctl_head_next(head)) {
		table = proc_sys_lookup_entry(parent, name, head->ctl_table);
		if (table)
			break;
	}
	*ptr = head;
	return table;
}

static struct _dentry *proc_sys_lookup(struct _inode *dir, struct _dentry *dentry,
				       struct nameidata *nd)
{
	struct ctl_table_header *head;
	struct inode *inode;
	struct _dentry *err;
	struct ctl_table *table;

	err = ERR_PTR(-ENOENT);
	table = do_proc_sys_lookup(tx_cache_get_dentry(dentry->d_parent), &dentry->d_name, &head);
	if (!table)
		goto out;

	err = ERR_PTR(-ENOMEM);
	inode = proc_sys_make_inode(dir, table);
	if (!inode)
		goto out;

	err = NULL;
	dentry->d_op = &proc_sys_dentry_operations;
	d_add(dentry, tx_cache_get_inode(inode));

out:
	sysctl_head_finish(head);
	return err;
}

static ssize_t proc_sys_read(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	struct _dentry *dentry = file_get_dentry(filp);
	struct ctl_table_header *head;
	struct ctl_table *table;
	ssize_t error, res;

	table = do_proc_sys_lookup(tx_cache_get_dentry(dentry->d_parent), &dentry->d_name, &head);
	/* Has the sysctl entry disappeared on us? */
	error = -ENOENT;
	if (!table)
		goto out;

	/* Has the sysctl entry been replaced by a directory? */
	error = -EISDIR;
	if (!table->proc_handler)
		goto out;

	/*
	 * At this point we know that the sysctl was not unregistered
	 * and won't be until we finish.
	 */
	error = -EPERM;
	if (sysctl_perm(table, MAY_READ))
		goto out;

	/* careful: calling conventions are nasty here */
	res = count;
	error = table->proc_handler(table, 0, filp, buf, &res, ppos);
	if (!error)
		error = res;
out:
	sysctl_head_finish(head);

	return error;
}

static ssize_t proc_sys_write(struct file *filp, const char __user *buf,
				size_t count, loff_t *ppos)
{
	struct _dentry *dentry = file_get_dentry(filp);
	struct ctl_table_header *head;
	struct ctl_table *table;
	ssize_t error, res;

	table = do_proc_sys_lookup(tx_cache_get_dentry(dentry->d_parent), &dentry->d_name, &head);
	/* Has the sysctl entry disappeared on us? */
	error = -ENOENT;
	if (!table)
		goto out;

	/* Has the sysctl entry been replaced by a directory? */
	error = -EISDIR;
	if (!table->proc_handler)
		goto out;

	/*
	 * At this point we know that the sysctl was not unregistered
	 * and won't be until we finish.
	 */
	error = -EPERM;
	if (sysctl_perm(table, MAY_WRITE))
		goto out;

	/* careful: calling conventions are nasty here */
	res = count;
	error = table->proc_handler(table, 1, filp, (char __user *)buf,
				    &res, ppos);
	if (!error)
		error = res;
out:
	sysctl_head_finish(head);

	return error;
}


static int proc_sys_fill_cache(struct file *filp, void *dirent,
				filldir_t filldir, struct ctl_table *table)
{
	struct ctl_table_header *head;
	struct ctl_table *child_table = NULL;
	struct _dentry *child, *dir = file_get_dentry(filp);
	struct inode *inode;
	struct _inode *_inode;
	struct qstr qname;
	ino_t ino = 0;
	unsigned type = DT_UNKNOWN;
	int ret;

	qname.name = table->procname;
	qname.len  = strlen(table->procname);
	qname.hash = full_name_hash(qname.name, qname.len);

	/* Suppress duplicates.
	 * Only fill a directory entry if it is the value that
	 * an ordinary lookup of that name returns.  Hide all
	 * others.
	 *
	 * If we ever cache this translation in the dcache
	 * I should do a dcache lookup first.  But for now
	 * it is just simpler not to.
	 */
	ret = 0;
	child_table = do_proc_sys_lookup(dir, &qname, &head);
	sysctl_head_finish(head);
	if (child_table != table)
		return 0;

	child = d_lookup(&dir, &qname);
	if (!child) {
		struct dentry *new;
		struct _dentry *_new;
		new = d_alloc(dir, &qname);
		if (new) {
			_new = tx_cache_get_dentry(new);
			inode = proc_sys_make_inode(d_get_inode(dir), table);
			if (!inode)
				child = ERR_PTR(-ENOMEM);
			else {
				_new->d_op = &proc_sys_dentry_operations;
				d_add(_new, tx_cache_get_inode(inode));
			}
			if (child)
				dput(new);
			else
				child = _new;
		}
	}
	if (!child || IS_ERR(child) || !child->d_inode)
		goto end_instantiate;
	inode = child->d_inode;
	if (inode) {
		_inode = tx_cache_get_inode(inode);
		ino  = _inode->i_ino;
		type = _inode->i_mode >> 12;
	}
	dput(parent(child));
end_instantiate:
	if (!ino)
		ino= find_inode_number(&dir, &qname);
	if (!ino)
		ino = 1;
	return filldir(dirent, qname.name, qname.len, tx_cache_get_file_ro(filp)->f_pos, ino, type);
}

static int proc_sys_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
	struct _file *_filp = tx_cache_get_file(filp);
	struct _dentry *dentry = f_get_dentry(_filp);
	struct _inode *inode = d_get_inode(dentry);
	struct ctl_table_header *head = NULL;
	struct ctl_table *table;
	unsigned long pos;
	int ret;

	ret = -ENOTDIR;
	if (!S_ISDIR(inode->i_mode))
		goto out;

	ret = 0;
	/* Avoid a switch here: arm builds fail with missing __cmpdi2 */
	if (_filp->f_pos == 0) {
		if (filldir(dirent, ".", 1, _filp->f_pos,
				inode->i_ino, DT_DIR) < 0)
			goto out;
		_filp->f_pos++;
	}
	if (_filp->f_pos == 1) {
		if (filldir(dirent, "..", 2, _filp->f_pos,
				parent_ino(dentry), DT_DIR) < 0)
			goto out;
		_filp->f_pos++;
	}
	pos = 2;

	/* - Find each instance of the directory
	 * - Read all entries in each instance
	 * - Before returning an entry to user space lookup the entry
	 *   by name and if I find a different entry don't return
	 *   this one because it means it is a buried dup.
	 * For sysctl this should only happen for directory entries.
	 */
	for (head = sysctl_head_next(NULL); head; head = sysctl_head_next(head)) {
		table = proc_sys_lookup_table(dentry, head->ctl_table);

		if (!table)
			continue;

		for (; table->ctl_name || table->procname; table++, pos++) {
			/* Can't do anything without a proc name */
			if (!table->procname)
				continue;

			if (pos < _filp->f_pos)
				continue;

			if (proc_sys_fill_cache(filp, dirent, filldir, table) < 0)
				goto out;
			_filp->f_pos = pos + 1;
		}
	}
	ret = 1;
out:
	sysctl_head_finish(head);
	return ret;
}

static int proc_sys_permission(const struct _inode *inode, int mask, struct nameidata *nd)
{
	/*
	 * sysctl entries that are not writeable,
	 * are _NOT_ writeable, capabilities or not.
	 */
	struct ctl_table_header *head;
	struct ctl_table *table;
	struct _dentry *dentry;
	int mode;
	int depth;
	int error;

	head = NULL;
	depth = PROC_I(inode)->fd;

	/* First check the cached permissions, in case we don't have
	 * enough information to lookup the sysctl table entry.
	 */
	error = -EACCES;
	mode = inode->i_mode;

	if (current->euid == 0)
		mode >>= 6;
	else if (in_group_p(0))
		mode >>= 3;

	if ((mode & mask & (MAY_READ|MAY_WRITE|MAY_EXEC)) == mask)
		error = 0;

	/* If we can't get a sysctl table entry the permission
	 * checks on the cached mode will have to be enough.
	 */
	if (!nd || !depth)
		goto out;

	dentry = nd->dentry;
	table = do_proc_sys_lookup(tx_cache_get_dentry(dentry->d_parent), &dentry->d_name, &head);

	/* If the entry does not exist deny permission */
	error = -EACCES;
	if (!table)
		goto out;

	/* Use the permissions on the sysctl table entry */
	error = sysctl_perm(table, mask);
out:
	sysctl_head_finish(head);
	return error;
}

static int proc_sys_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct _inode *inode = dentry_get_inode(dentry);
	int error;

	if (attr->ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID))
		return -EPERM;

	error = inode_change_ok(inode, attr);
	if (!error)
		error = inode_setattr(inode, attr);

	return error;
}

/* I'm lazy and don't distinguish between files and directories,
 * until access time.
 */
static const struct file_operations proc_sys_file_operations = {
	.read		= proc_sys_read,
	.write		= proc_sys_write,
	.readdir	= proc_sys_readdir,
};

static struct inode_operations proc_sys_inode_operations = {
	.lookup		= proc_sys_lookup,
	.permission	= proc_sys_permission,
	.setattr	= proc_sys_setattr,
#ifdef CONFIG_TX_KSTM
        .validate       = proc_validate_inode,
#endif
};

static int proc_sys_revalidate(struct _dentry *dentry, struct nameidata *nd)
{
	struct ctl_table_header *head;
	struct ctl_table *table;
	table = do_proc_sys_lookup(tx_cache_get_dentry(dentry->d_parent), &dentry->d_name, &head);
	proc_sys_refresh_inode(d_get_inode(dentry), table);
	sysctl_head_finish(head);
	return !!table;
}

static struct dentry_operations proc_sys_dentry_operations = {
	.d_revalidate	= proc_sys_revalidate,
};

static struct proc_dir_entry *proc_sys_root;

int proc_sys_init(void)
{
	proc_sys_root = proc_mkdir("sys", NULL);
	proc_sys_root->proc_iops = &proc_sys_inode_operations;
	proc_sys_root->proc_fops = &proc_sys_file_operations;
	proc_sys_root->nlink = 0;
	return 0;
}
