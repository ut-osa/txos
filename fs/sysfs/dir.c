/*
 * dir.c - Operations for sysfs directories.
 */

#undef DEBUG

#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/namei.h>
#include <asm/semaphore.h>
#include "sysfs.h"
#include <linux/tx_inodes.h>
#include <linux/tx_dentry.h>
#include <linux/tx_file.h>

DECLARE_RWSEM(sysfs_rename_sem);
spinlock_t sysfs_lock = SPIN_LOCK_UNLOCKED;

static void sysfs_d_iput(struct dentry * dentry, struct inode * inode)
{
	struct sysfs_dirent * sd = dentry->d_fsdata;

	if (sd) {
		/* sd->s_dentry is protected with sysfs_lock.  This
		 * allows sysfs_drop_dentry() to dereference it.
		 */
		spin_lock(&sysfs_lock);

		/* The dentry might have been deleted or another
		 * lookup could have happened updating sd->s_dentry to
		 * point the new dentry.  Ignore if it isn't pointing
		 * to this dentry.
		 */
		if (sd->s_dentry == dentry)
			sd->s_dentry = NULL;
		spin_unlock(&sysfs_lock);
		sysfs_put(sd);
	}
	iput(inode);
}

static struct dentry_operations sysfs_dentry_ops = {
	.d_iput		= sysfs_d_iput,
};

static unsigned int sysfs_inode_counter;
ino_t sysfs_get_inum(void)
{
	if (unlikely(sysfs_inode_counter < 3))
		sysfs_inode_counter = 3;
	return sysfs_inode_counter++;
}

/*
 * Allocates a new sysfs_dirent and links it to the parent sysfs_dirent
 */
static struct sysfs_dirent * __sysfs_new_dirent(void * element)
{
	struct sysfs_dirent * sd;

	sd = kmem_cache_zalloc(sysfs_dir_cachep, GFP_KERNEL);
	if (!sd)
		return NULL;

	sd->s_ino = sysfs_get_inum();
	atomic_set(&sd->s_count, 1);
	atomic_set(&sd->s_event, 1);
	INIT_LIST_HEAD(&sd->s_children);
	INIT_LIST_HEAD(&sd->s_sibling);
	sd->s_element = element;

	return sd;
}

static void __sysfs_list_dirent(struct sysfs_dirent *parent_sd,
			      struct sysfs_dirent *sd)
{
	if (sd)
		list_add(&sd->s_sibling, &parent_sd->s_children);
}

static struct sysfs_dirent * sysfs_new_dirent(struct sysfs_dirent *parent_sd,
						void * element)
{
	struct sysfs_dirent *sd;
	sd = __sysfs_new_dirent(element);
	__sysfs_list_dirent(parent_sd, sd);
	return sd;
}

/*
 *
 * Return -EEXIST if there is already a sysfs element with the same name for
 * the same parent.
 *
 * called with parent inode's i_mutex held
 */
int sysfs_dirent_exist(struct sysfs_dirent *parent_sd,
			  const unsigned char *new)
{
	struct sysfs_dirent * sd;

	list_for_each_entry(sd, &parent_sd->s_children, s_sibling) {
		if (sd->s_element) {
			const unsigned char *existing = sysfs_get_name(sd);
			if (strcmp(existing, new))
				continue;
			else
				return -EEXIST;
		}
	}

	return 0;
}


static struct sysfs_dirent *
__sysfs_make_dirent(struct _dentry *dentry, void *element, mode_t mode, int type)
{
	struct sysfs_dirent * sd;

	sd = __sysfs_new_dirent(element);
	if (!sd)
		goto out;

	sd->s_mode = mode;
	sd->s_type = type;
	sd->s_dentry = dentry ? parent(dentry) : NULL;
	if (dentry) {
		parent(dentry)->d_fsdata = sysfs_get(sd);
		dentry->d_op = &sysfs_dentry_ops;
	}

out:
	return sd;
}

int sysfs_make_dirent(struct sysfs_dirent * parent_sd, struct _dentry * dentry,
			void * element, umode_t mode, int type)
{
	struct sysfs_dirent *sd;

	sd = __sysfs_make_dirent(dentry, element, mode, type);
	__sysfs_list_dirent(parent_sd, sd);

	return sd ? 0 : -ENOMEM;
}

static int init_dir(struct _inode * inode)
{
	inode->i_op = &sysfs_dir_inode_operations;
	inode->i_fop = &sysfs_dir_operations;

	/* directory inodes start off with i_nlink == 2 (for "." entry) */
	inc_nlink(inode);
	return 0;
}

static int init_file(struct _inode * inode)
{
	inode->i_size = PAGE_SIZE;
	inode->i_fop = &sysfs_file_operations;
	return 0;
}

static int init_symlink(struct _inode * inode)
{
	inode->i_op = &sysfs_symlink_inode_operations;
	return 0;
}

static int create_dir(struct kobject * k, struct _dentry * p,
		      const char * n, struct _dentry ** d)
{
	int error;
	umode_t mode = S_IFDIR| S_IRWXU | S_IRUGO | S_IXUGO;

	imutex_lock(p->d_inode);
	*d = lookup_one_len(n, &p, strlen(n));
	if (!IS_ERR(*d)) {
 		if (sysfs_dirent_exist(parent(p)->d_fsdata, n))
  			error = -EEXIST;
  		else
			error = sysfs_make_dirent(parent(p)->d_fsdata, *d, k, mode,
								SYSFS_DIR);
		if (!error) {
			error = sysfs_create(*d, mode, init_dir);
			if (!error) {
				inc_nlink(d_get_inode(p));
				(*d)->d_op = &sysfs_dentry_ops;
				d_rehash(*d);
			}
		}
		if (error && (error != -EEXIST)) {
			struct sysfs_dirent *sd = parent(*d)->d_fsdata;
			if (sd) {
 				list_del_init(&sd->s_sibling);
				sysfs_put(sd);
			}
			d_drop(*d);
		}
		dput(parent(*d));
	} else
		error = PTR_ERR(*d);
	imutex_unlock(p->d_inode);
	return error;
}


int sysfs_create_subdir(struct kobject * k, const char * n, struct _dentry ** d)
{
	return create_dir(k,tx_cache_get_dentry(k->dentry),n,d);
}

/**
 *	sysfs_create_dir - create a directory for an object.
 *	@kobj:		object we're creating directory for. 
 *	@shadow_parent:	parent parent object.
 */

int sysfs_create_dir(struct kobject * kobj, struct dentry *shadow_parent)
{
	struct _dentry * dentry = NULL;
	struct dentry * parent;
	int error = 0;

	BUG_ON(!kobj);

	if (shadow_parent)
		parent = shadow_parent;
	else if (kobj->parent)
		parent = kobj->parent->dentry;
	else if (sysfs_mount && sysfs_mount->mnt_sb)
		parent = sysfs_mount->mnt_sb->s_root;
	else
		return -EFAULT;

	error = create_dir(kobj,tx_cache_get_dentry(parent),
			   kobject_name(kobj),&dentry);
	if (!error)
		kobj->dentry = parent(dentry);
	return error;
}

/* attaches attribute's sysfs_dirent to the dentry corresponding to the
 * attribute file
 */
static int sysfs_attach_attr(struct sysfs_dirent * sd, struct _dentry * dentry)
{
	struct attribute * attr = NULL;
	struct bin_attribute * bin_attr = NULL;
	int (* init) (struct _inode *) = NULL;
	int error = 0;

        if (sd->s_type & SYSFS_KOBJ_BIN_ATTR) {
                bin_attr = sd->s_element;
                attr = &bin_attr->attr;
        } else {
                attr = sd->s_element;
                init = init_file;
        }

	parent(dentry)->d_fsdata = sysfs_get(sd);
	/* protect sd->s_dentry against sysfs_d_iput */
	spin_lock(&sysfs_lock);
	sd->s_dentry = parent(dentry);
	spin_unlock(&sysfs_lock);
	error = sysfs_create(dentry, (attr->mode & S_IALLUGO) | S_IFREG, init);
	if (error) {
		sysfs_put(sd);
		return error;
	}

        if (bin_attr) {
		struct _inode *inode = d_get_inode(dentry);
		inode->i_size = bin_attr->size;
		inode->i_fop = &bin_fops;
	}
	dentry->d_op = &sysfs_dentry_ops;
	d_rehash(dentry);

	return 0;
}

static int sysfs_attach_link(struct sysfs_dirent * sd, struct _dentry * dentry)
{
	int err = 0;

	parent(dentry)->d_fsdata = sysfs_get(sd);
	/* protect sd->s_dentry against sysfs_d_iput */
	spin_lock(&sysfs_lock);
	sd->s_dentry = parent(dentry);
	spin_unlock(&sysfs_lock);
	err = sysfs_create(dentry, S_IFLNK|S_IRWXUGO, init_symlink);
	if (!err) {
		dentry->d_op = &sysfs_dentry_ops;
		d_rehash(dentry);
	} else
		sysfs_put(sd);

	return err;
}

static struct _dentry * sysfs_lookup(struct _inode *dir, struct _dentry *dentry,
				    struct nameidata *nd)
{
	struct sysfs_dirent * parent_sd = dentry->d_parent->d_fsdata;
	struct sysfs_dirent * sd;
	int err = 0;

	list_for_each_entry(sd, &parent_sd->s_children, s_sibling) {
		if (sd->s_type & SYSFS_NOT_PINNED) {
			const unsigned char * name = sysfs_get_name(sd);

			if (strcmp(name, dentry->d_name.name))
				continue;

			if (sd->s_type & SYSFS_KOBJ_LINK)
				err = sysfs_attach_link(sd, dentry);
			else
				err = sysfs_attach_attr(sd, dentry);
			break;
		}
	}

	return ERR_PTR(err);
}

const struct inode_operations sysfs_dir_inode_operations = {
	.lookup		= sysfs_lookup,
	.setattr	= sysfs_setattr,
};

static void remove_dir(struct _dentry * d)
{
	struct _dentry * parent = tx_cache_get_dentry(dget(d->d_parent));
	struct sysfs_dirent * sd;

	imutex_lock(parent->d_inode);
	d_delete(d);
	sd = parent(d)->d_fsdata;
 	list_del_init(&sd->s_sibling);
	sysfs_put(sd);
	if (d->d_inode)
		simple_rmdir(d_get_inode(parent),d);

	pr_debug(" o %s removing done (%d)\n",d->d_name.name,
		 tx_atomic_read(&parent(d)->d_count));

	imutex_unlock(parent->d_inode);
	dput(parent(parent));
}

void sysfs_remove_subdir(struct _dentry * d)
{
	remove_dir(d);
}


static void __sysfs_remove_dir(struct _dentry *dentry)
{
	struct sysfs_dirent * parent_sd;
	struct sysfs_dirent * sd, * tmp;

	dget(parent(dentry));
	if (!dentry)
		return;

	pr_debug("sysfs %s: removing dir\n",dentry->d_name.name);
	imutex_lock(dentry->d_inode);
	parent_sd = parent(dentry)->d_fsdata;
	list_for_each_entry_safe(sd, tmp, &parent_sd->s_children, s_sibling) {
		if (!sd->s_element || !(sd->s_type & SYSFS_NOT_PINNED))
			continue;
		list_del_init(&sd->s_sibling);
		sysfs_drop_dentry(sd, parent(dentry));
		sysfs_put(sd);
	}
	imutex_unlock(dentry->d_inode);

	remove_dir(dentry);
	/**
	 * Drop reference from dget() on entrance.
	 */
	dput(parent(dentry));
}

/**
 *	sysfs_remove_dir - remove an object's directory.
 *	@kobj:	object.
 *
 *	The only thing special about this is that we remove any files in
 *	the directory before we remove the directory, and we've inlined
 *	what used to be sysfs_rmdir() below, instead of calling separately.
 */

void sysfs_remove_dir(struct kobject * kobj)
{
	__sysfs_remove_dir(tx_cache_get_dentry(kobj->dentry));
	kobj->dentry = NULL;
}

int sysfs_rename_dir(struct kobject * kobj, struct _dentry **new_parentp,
		     const char *new_name)
{
	int error = 0;
	struct _dentry * new_dentry;
	struct _dentry *new_parent = *new_parentp;

	if (!new_parent)
		return -EFAULT;

	down_write(&sysfs_rename_sem);
	imutex_lock(new_parent->d_inode);

	new_dentry = lookup_one_len(new_name, new_parentp, strlen(new_name));
	new_parent = *new_parentp;
	if (!IS_ERR(new_dentry)) {
		/* By allowing two different directories with the
		 * same d_parent we allow this routine to move
		 * between different shadows of the same directory
		 */
		struct _dentry *kobj_dentry = tx_cache_get_dentry(kobj->dentry);
		struct inode *inode = tx_cache_get_dentry(kobj_dentry->d_parent)->d_inode;
		if (inode != new_parent->d_inode)
			return -EINVAL;
		else if (inode != new_parent->d_inode)
			error = -EINVAL;
		else if (new_dentry == kobj_dentry)
			error = -EINVAL;
		else if (!new_dentry->d_inode) {
			error = kobject_set_name(kobj, "%s", new_name);
			if (!error) {
				struct sysfs_dirent *sd, *parent_sd;

				d_add(new_dentry, NULL);
				d_move(kobj_dentry, new_dentry);

				sd = kobj->dentry->d_fsdata;
				parent_sd = parent(new_parent)->d_fsdata;

				list_del_init(&sd->s_sibling);
				list_add(&sd->s_sibling, &parent_sd->s_children);
			}
			else
				d_drop(new_dentry);
		} else
			error = -EEXIST;
		dput(parent(new_dentry));
	}
	imutex_unlock(new_parent->d_inode);
	up_write(&sysfs_rename_sem);

	return error;
}

int sysfs_move_dir(struct kobject *kobj, struct kobject *new_parent)
{
	struct _dentry *old_parent_dentry, *new_parent_dentry, *new_dentry;
	struct sysfs_dirent *new_parent_sd, *sd;
	int error;

	old_parent_dentry = tx_cache_get_dentry(kobj->parent ?
						kobj->parent->dentry : 
						sysfs_mount->mnt_sb->s_root);
	new_parent_dentry = tx_cache_get_dentry(new_parent ?
						new_parent->dentry : 
						sysfs_mount->mnt_sb->s_root);

	if (old_parent_dentry->d_inode == new_parent_dentry->d_inode)
		return 0;	/* nothing to move */
again:
	imutex_lock(old_parent_dentry->d_inode);
	if (imutex_trylock(new_parent_dentry->d_inode)) {
		imutex_unlock(old_parent_dentry->d_inode);
		goto again;
	}

	new_parent_sd = parent(new_parent_dentry)->d_fsdata;
	sd = kobj->dentry->d_fsdata;

	new_dentry = lookup_one_len(kobj->name, &new_parent_dentry,
				    strlen(kobj->name));
	if (IS_ERR(new_dentry)) {
		error = PTR_ERR(new_dentry);
		goto out;
	} else
		error = 0;
	d_add(new_dentry, NULL);
	d_move(tx_cache_get_dentry(kobj->dentry), new_dentry);
	dput(parent(new_dentry));

	/* Remove from old parent's list and insert into new parent's list. */
	list_del_init(&sd->s_sibling);
	list_add(&sd->s_sibling, &new_parent_sd->s_children);

out:
	imutex_unlock(new_parent_dentry->d_inode);
	imutex_unlock(old_parent_dentry->d_inode);

	return error;
}

static int sysfs_dir_open(struct _inode *inode, struct file *file)
{
	struct _dentry * dentry = file_get_dentry(file);
	struct sysfs_dirent * parent_sd = parent(dentry)->d_fsdata;

	imutex_lock(dentry->d_inode);
	file->private_data = sysfs_new_dirent(parent_sd, NULL);
	imutex_unlock(dentry->d_inode);

	return file->private_data ? 0 : -ENOMEM;

}

static int sysfs_dir_close(struct _inode *inode, struct file *file)
{
	struct _dentry * dentry = file_get_dentry(file);
	struct sysfs_dirent * cursor = file->private_data;

	imutex_lock(dentry->d_inode);
	list_del_init(&cursor->s_sibling);
	imutex_unlock(dentry->d_inode);

	release_sysfs_dirent(cursor);

	return 0;
}

/* Relationship between s_mode and the DT_xxx types */
static inline unsigned char dt_type(struct sysfs_dirent *sd)
{
	return (sd->s_mode >> 12) & 15;
}

static int sysfs_readdir(struct file * filp, void * dirent, filldir_t filldir)
{
	struct _file *_filp = tx_cache_get_file(filp);
	struct _dentry *dentry = f_get_dentry(_filp);
	struct sysfs_dirent * parent_sd = parent(dentry)->d_fsdata;
	struct sysfs_dirent *cursor = filp->private_data;
	struct list_head *p, *q = &cursor->s_sibling;
	ino_t ino;
	int i = _filp->f_pos;

	switch (i) {
		case 0:
			ino = parent_sd->s_ino;
			if (filldir(dirent, ".", 1, i, ino, DT_DIR) < 0)
				break;
			_filp->f_pos++;
			i++;
			/* fallthrough */
		case 1:
			ino = parent_ino(dentry);
			if (filldir(dirent, "..", 2, i, ino, DT_DIR) < 0)
				break;
			_filp->f_pos++;
			i++;
			/* fallthrough */
		default:
			if (_filp->f_pos == 2)
				list_move(q, &parent_sd->s_children);

			for (p=q->next; p!= &parent_sd->s_children; p=p->next) {
				struct sysfs_dirent *next;
				const char * name;
				int len;

				next = list_entry(p, struct sysfs_dirent,
						   s_sibling);
				if (!next->s_element)
					continue;

				name = sysfs_get_name(next);
				len = strlen(name);
				ino = next->s_ino;

				if (filldir(dirent, name, len, _filp->f_pos, ino,
						 dt_type(next)) < 0)
					return 0;

				list_move(q, p);
				p = q;
				_filp->f_pos++;
			}
	}
	return 0;
}

static loff_t sysfs_dir_lseek(struct _file * file, loff_t offset, int origin)
{
	struct _dentry * dentry = f_get_dentry(file);

	imutex_lock(dentry->d_inode);
	switch (origin) {
		case 1:
			offset += file->f_pos;
		case 0:
			if (offset >= 0)
				break;
		default:
			imutex_unlock(dentry->d_inode);
			return -EINVAL;
	}
	if (offset != file->f_pos) {
		file->f_pos = offset;
		if (file->f_pos >= 2) {
			struct sysfs_dirent *sd = parent(dentry)->d_fsdata;
			struct sysfs_dirent *cursor = parent(file)->private_data;
			struct list_head *p;
			loff_t n = file->f_pos - 2;

			list_del(&cursor->s_sibling);
			p = sd->s_children.next;
			while (n && p != &sd->s_children) {
				struct sysfs_dirent *next;
				next = list_entry(p, struct sysfs_dirent,
						   s_sibling);
				if (next->s_element)
					n--;
				p = p->next;
			}
			list_add_tail(&cursor->s_sibling, p);
		}
	}
	imutex_unlock(dentry->d_inode);
	return offset;
}


/**
 *	sysfs_make_shadowed_dir - Setup so a directory can be shadowed
 *	@kobj:	object we're creating shadow of.
 */

int sysfs_make_shadowed_dir(struct kobject *kobj,
	void * (*follow_link)(struct _dentry *, struct nameidata *))
{
	struct _inode *inode;
	struct inode_operations *i_op;

	inode = dentry_get_inode(kobj->dentry);
	if (inode->i_op != &sysfs_dir_inode_operations)
		return -EINVAL;

	i_op = kmalloc(sizeof(*i_op), GFP_KERNEL);
	if (!i_op)
		return -ENOMEM;

	memcpy(i_op, &sysfs_dir_inode_operations, sizeof(*i_op));
	i_op->follow_link = follow_link;

	/* Locking of inode->i_op?
	 * Since setting i_op is a single word write and they
	 * are atomic we should be ok here.
	 */
	inode->i_op = i_op;
	return 0;
}

/**
 *	sysfs_create_shadow_dir - create a shadow directory for an object.
 *	@kobj:	object we're creating directory for.
 *
 *	sysfs_make_shadowed_dir must already have been called on this
 *	directory.
 */

struct dentry *sysfs_create_shadow_dir(struct kobject *kobj)
{
	struct sysfs_dirent *sd;
	struct dentry *shadow;
	struct _dentry *parent, *dir, *_shadow;
	struct _inode *inode;

	dir = tx_cache_get_dentry(kobj->dentry);
	inode = d_get_inode(dir);
	parent = tx_cache_get_dentry(dir->d_parent);
	shadow = ERR_PTR(-EINVAL);
	if (!sysfs_is_shadowed_inode(inode))
		goto out;

	shadow = d_alloc(parent, &dir->d_name);
	if (!shadow)
		goto nomem;

	_shadow = tx_cache_get_dentry(shadow);
	sd = __sysfs_make_dirent(_shadow, kobj, inode->i_mode, SYSFS_DIR);
	if (!sd)
		goto nomem;

	d_instantiate(_shadow, tx_cache_get_inode(igrab(parent(inode))));
	inc_nlink(inode);
	inc_nlink(d_get_inode(parent));
	_shadow->d_op = &sysfs_dentry_ops;

	dget(shadow);		/* Extra count - pin the dentry in core */

out:
	return shadow;
nomem:
	dput(shadow);
	shadow = ERR_PTR(-ENOMEM);
	goto out;
}

/**
 *	sysfs_remove_shadow_dir - remove an object's directory.
 *	@shadow: dentry of shadow directory
 *
 *	The only thing special about this is that we remove any files in
 *	the directory before we remove the directory, and we've inlined
 *	what used to be sysfs_rmdir() below, instead of calling separately.
 */

void sysfs_remove_shadow_dir(struct _dentry *shadow)
{
	__sysfs_remove_dir(shadow);
}

const struct file_operations sysfs_dir_operations = {
	.open		= sysfs_dir_open,
	.release	= sysfs_dir_close,
	.llseek		= sysfs_dir_lseek,
	.read		= generic_read_dir,
	.readdir	= sysfs_readdir,
};
