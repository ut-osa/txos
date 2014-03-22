/*
 *	fs/libfs.c
 *	Library for filesystems writers.
 */

#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/mount.h>
#include <linux/vfs.h>
#include <linux/mutex.h>

#include <asm/uaccess.h>

#include <linux/transaction.h>
#include <linux/tx_dentry.h>
#include <linux/tx_file.h>
#include <linux/tx_super.h>

int simple_getattr(struct vfsmount *mnt, const struct _dentry *dentry,
		   struct kstat *stat)
{
	struct _inode *inode = d_get_inode(dentry);
	generic_fillattr(inode, stat);
	stat->blocks = inode->i_mapping->nrpages << (PAGE_CACHE_SHIFT - 9);
	return 0;
}

int simple_statfs(const struct dentry *dentry, struct kstatfs *buf)
{
	buf->f_type = dentry->d_sb->s_magic;
	buf->f_bsize = PAGE_CACHE_SIZE;
	buf->f_namelen = NAME_MAX;
	return 0;
}

/*
 * Retaining negative dentries for an in-memory filesystem just wastes
 * memory and lookup time: arrange for them to be deleted immediately.
 */
static int simple_delete_dentry(struct _dentry *dentry)
{
	return 1;
}

/*
 * Lookup the data. This is trivial - if the dentry didn't already
 * exist, we know it is negative.  Set d_op to delete negative dentries.
 */
struct _dentry *simple_lookup(struct _inode *dir, struct _dentry *dentry, struct nameidata *nd)
{
	static struct dentry_operations simple_dentry_operations = {
		.d_delete = simple_delete_dentry,
	};

	if (dentry->d_name.len > NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);
	dentry->d_op = &simple_dentry_operations;
	d_add(dentry, NULL);
	return NULL;
}

int simple_sync_file(struct file * file, struct _dentry *dentry, int datasync)
{
	return 0;
}
 
int dcache_dir_open(struct _inode *inode, struct file *file)
{
	static struct qstr cursor_name = {.len = 1, .name = "."};

	file->private_data = d_alloc(file_get_dentry(file), &cursor_name);

	return file->private_data ? 0 : -ENOMEM;
}

int dcache_dir_close(struct _inode *inode, struct file *file)
{
	dput(file->private_data);
	return 0;
}

loff_t dcache_dir_lseek(struct _file *file, loff_t offset, int origin)
{
	struct _dentry *dentry = f_get_dentry(file);
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
			struct dentry *cursor = parent(file)->private_data;
			struct tx_list2_iterator iter;
			loff_t n = file->f_pos - 2;

			spin_lock(&dcache_lock);
			record_tx_lock(&dcache_lock, SPIN_LOCK);
			tx_list2_del(&cursor->d_child);
			tx_list2_get_iterator(&iter, &parent(dentry)->d_subdirs);
#ifdef CONFIG_DISABLE_LIST2
			while (tx_list2_iter_next(&iter) && iter.cur != &parent(dentry)->d_subdirs){
#else
			while (tx_list2_iter_next(&iter) && iter.cur != &parent(dentry)->d_subdirs.head){
#endif
				struct dentry *next = tx_list2_iter_entry(&iter, struct dentry, d_child);
				struct _dentry *_next = tx_cache_get_dentry(next);
				if (!d_unhashed(_next) && _next->d_inode)
					n--;
			}
			tx_list2_put_iterator(&iter);
			tx_list2_add_tail(&cursor->d_child, iter.head);
			spin_unlock(&dcache_lock);
			record_tx_unlock(&dcache_lock, SPIN_LOCK);
		}
	}
	imutex_unlock(dentry->d_inode);
	return offset;
}

/* Relationship between i_mode and the DT_xxx types */
static inline unsigned char dt_type(struct _inode *inode)
{
	return (inode->i_mode >> 12) & 15;
}

/*
 * Directory is locked and all positive dentries in it are safe, since
 * for ramfs-type trees they can't go away without unlink() or rmdir(),
 * both impossible due to the lock on directory.
 */
#ifndef CONFIG_DISABLE_LIST2
int dcache_readdir(struct file * filp, void * dirent, filldir_t filldir)
{
	struct _file *_filp = tx_cache_get_file(filp);
	struct _dentry *dentry = f_get_dentry(_filp);
	struct dentry *cursor = filp->private_data;
	struct _inode *_inode = d_get_inode(dentry);
	struct tx_list2_iterator iter;
	struct tx_list2_entry_ref *q = &cursor->d_child;
	//struct tx_list_head *p, *q = &cursor->d_child;
	ino_t ino;
	int i = _filp->f_pos;

	switch (i) {
		case 0:
			ino = _inode->i_ino;
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
			spin_lock(&dcache_lock);
			record_tx_lock(&dcache_lock, SPIN_LOCK);
			if (_filp->f_pos == 2)
				tx_list2_move(q, &parent(dentry)->d_subdirs);

			if(unlikely(tx_list2_get_iterator_pos(&iter, q)))
				goto bad_out;
			while (tx_list2_iter_next(&iter)){
				struct dentry *next = tx_list2_iter_entry(&iter, struct dentry, d_child);
				struct _dentry *_next = tx_cache_get_dentry(next);
				struct _inode *_next_inode;
				BUG_ON(next == cursor);
				
				if (d_unhashed(_next) || !_next->d_inode)
					continue;

				_next_inode = d_get_inode(_next);

				tx_list2_put_iterator(&iter);
				spin_unlock(&dcache_lock);
				record_tx_unlock(&dcache_lock, SPIN_LOCK);
				if (filldir(dirent, _next->d_name.name, 
					    _next->d_name.len, _filp->f_pos, 
					    _next_inode->i_ino, 
					    dt_type(_next_inode)) < 0){
					return 0;
				}
				spin_lock(&dcache_lock);
				record_tx_lock(&dcache_lock, SPIN_LOCK);
				if(unlikely(tx_list2_get_iterator_pos(&iter, &next->d_child)))
					goto bad_out;

				/* next is still alive */
				tx_list2_move_iter_locked(q, &iter);
				_filp->f_pos++;
			}
			tx_list2_put_iterator(&iter);
			spin_unlock(&dcache_lock);
			record_tx_unlock(&dcache_lock, SPIN_LOCK);
	}
	return 0;

bad_out:
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);
	printk(KERN_ERR "WARNING: Unable to complete readdir.  Bailing\n");
	return 0;

}
#else
int dcache_readdir(struct file * filp, void * dirent, filldir_t filldir)
{
	struct _file *_filp = tx_cache_get_file(filp);
	struct _dentry *dentry = f_get_dentry(_filp);
	struct dentry *cursor = filp->private_data;
	struct _inode *_inode = d_get_inode(dentry);
	struct list_head *p, *q = &cursor->d_child;
	ino_t ino;
	int i = _filp->f_pos;

	switch (i) {
		case 0:
			ino = _inode->i_ino;
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
			spin_lock(&dcache_lock);
			record_tx_lock(&dcache_lock, SPIN_LOCK);
			if (_filp->f_pos == 2)
				tx_list2_move(q, &parent(dentry)->d_subdirs);

			for(p=q->next; p != &parent(dentry)->d_subdirs; p=p->next){
				struct dentry *next = list_entry(p, struct dentry, d_child);
				struct _dentry *_next = tx_cache_get_dentry(next);
				struct _inode *_next_inode;
				BUG_ON(next == cursor);
				
				if (d_unhashed(_next) || !_next->d_inode)
					continue;

				_next_inode = d_get_inode(_next);

				spin_unlock(&dcache_lock);
				record_tx_unlock(&dcache_lock, SPIN_LOCK);
				if (filldir(dirent, _next->d_name.name, 
					    _next->d_name.len, _filp->f_pos, 
					    _next_inode->i_ino, 
					    dt_type(_next_inode)) < 0){
					return 0;
				}
				spin_lock(&dcache_lock);
				record_tx_lock(&dcache_lock, SPIN_LOCK);
				/* next is still alive */
				list_move(q,p);
				p=q;
				_filp->f_pos++;
			}
			spin_unlock(&dcache_lock);
			record_tx_unlock(&dcache_lock, SPIN_LOCK);
	}
	return 0;
}
#endif


ssize_t generic_read_dir(struct file *filp, char __user *buf, size_t siz, loff_t *ppos)
{
	return -EISDIR;
}

const struct file_operations simple_dir_operations = {
	.open		= dcache_dir_open,
	.release	= dcache_dir_close,
	.llseek		= dcache_dir_lseek,
	.read		= generic_read_dir,
	.readdir	= dcache_readdir,
	.fsync		= simple_sync_file,
};

const struct inode_operations simple_dir_inode_operations = {
	.lookup		= simple_lookup,
};

static const struct super_operations simple_super_operations = {
	.statfs		= simple_statfs,
};

/*
 * Common helper for pseudo-filesystems (sockfs, pipefs, bdev - stuff that
 * will never be mountable)
 */
int get_sb_pseudo(struct file_system_type *fs_type, char *name,
	const struct super_operations *ops, unsigned long magic,
	struct vfsmount *mnt)
{
	struct super_block *s = sget(fs_type, NULL, set_anon_super, NULL);
	struct _super_block *_s = tx_cache_get_super(s);
	struct dentry *dentry;
	struct _dentry *_dentry;
	struct inode *root;
	struct _inode *_root;
	struct qstr d_name = {.name = name, .len = strlen(name)};

	if (IS_ERR(s))
		return PTR_ERR(s);

	_s->s_flags = MS_NOUSER;
	s->s_maxbytes = ~0ULL;
	s->s_blocksize = 1024;
	s->s_blocksize_bits = 10;
	s->s_magic = magic;
	s->s_op = ops ? ops : &simple_super_operations;
	s->s_time_gran = 1;
	root = new_inode(s);
	if (!root)
		goto Enomem;

	/* Should be safe here*/
	KSTM_BUG_ON(active_transaction());
	_root = root->i_contents;
       
	/*
	 * since this is the first inode, make it number 1. New inodes created
	 * after this must take care not to collide with it (by passing
	 * max_reserved of 1 to iunique).
	 */
	_root->i_ino = 1;
	_root->i_mode = S_IFDIR | S_IRUSR | S_IWUSR;
	_root->i_uid = _root->i_gid = 0;
	_root->i_atime = _root->i_mtime = _root->i_ctime = CURRENT_TIME;
	dentry = d_alloc(NULL, &d_name);
	if (!dentry) {
		iput(root);
		goto Enomem;
	}
	_dentry = tx_cache_get_dentry(dentry);
	dentry->d_sb = s;
	_dentry->d_parent = dentry;
	d_instantiate(_dentry, _root);
	s->s_root = dentry;
	_s->s_flags |= MS_ACTIVE;
	return simple_set_mnt(mnt, s);

Enomem:
	up_write(&s->s_umount);
	deactivate_super(s);
	return -ENOMEM;
}

int simple_link(struct _dentry *old_dentry, struct _inode *dir, struct _dentry *dentry)
{
	struct _inode *inode = d_get_inode(old_dentry);

	inode->i_ctime = dir->i_ctime = dir->i_mtime = CURRENT_TIME;
	inc_nlink(inode);
	tx_atomic_inc(&parent(inode)->i_count);
	dget(parent(dentry));
	d_instantiate(dentry, inode);
	return 0;
}

static inline int simple_positive(struct _dentry *dentry)
{
	return dentry->d_inode && !d_unhashed(dentry);
}

int simple_empty(struct dentry *dentry)
{
	int ret = 0;
	struct tx_list2_iterator iter;

	spin_lock(&dcache_lock);
	record_tx_lock(&dcache_lock, SPIN_LOCK);
	tx_list2_get_iterator(&iter, &dentry->d_subdirs);
	while (tx_list2_iter_next(&iter)){
		struct dentry *child = tx_list2_iter_entry(&iter, struct dentry, d_child);
		if (simple_positive(tx_cache_get_dentry_ro(child)))
			goto out;
	}
	ret = 1;
out:
	tx_list2_put_iterator(&iter);
	spin_unlock(&dcache_lock);
	record_tx_unlock(&dcache_lock, SPIN_LOCK);
	return ret;
}

int simple_unlink(struct _inode *dir, struct _dentry *dentry)
{
	struct _inode *inode = d_get_inode(dentry);

	inode->i_ctime = dir->i_ctime = dir->i_mtime = CURRENT_TIME;
	drop_nlink(inode);
	dput(parent(dentry));
	return 0;
}

int simple_rmdir(struct _inode *dir, struct _dentry *dentry)
{
	if (!simple_empty(parent(dentry)))
		return -ENOTEMPTY;

	drop_nlink(d_get_inode(dentry));
	simple_unlink(dir, dentry);
	drop_nlink(dir);
	return 0;
}

int simple_rename(struct _inode *old_dir, struct _dentry *old_dentry,
		struct _inode *new_dir, struct _dentry *new_dentry)
{
	struct _inode *inode = d_get_inode(old_dentry);
	int they_are_dirs = S_ISDIR(inode->i_mode);

	if (!simple_empty(parent(new_dentry)))
		return -ENOTEMPTY;

	if (new_dentry->d_inode) {
		simple_unlink(new_dir, new_dentry);
		if (they_are_dirs)
			drop_nlink(old_dir);
	} else if (they_are_dirs) {
		drop_nlink(old_dir);
		inc_nlink(new_dir);
	}

	old_dir->i_ctime = old_dir->i_mtime = new_dir->i_ctime =
		new_dir->i_mtime = inode->i_ctime = CURRENT_TIME;

	return 0;
}

int simple_readpage(struct file *file, struct page *page)
{
	clear_highpage(page);
	flush_dcache_page(page);
	SetPageUptodate(page);
	unlock_page(page);
	return 0;
}

int simple_prepare_write(struct file *file, struct page *page,
			unsigned from, unsigned to)
{
	if (!PageUptodate(page)) {
		if (to - from != PAGE_CACHE_SIZE) {
			void *kaddr = kmap_atomic(page, KM_USER0);
			memset(kaddr, 0, from);
			memset(kaddr + to, 0, PAGE_CACHE_SIZE - to);
			flush_dcache_page(page);
			kunmap_atomic(kaddr, KM_USER0);
		}
	}
	return 0;
}

int simple_commit_write(struct file *file, struct page *page,
			unsigned from, unsigned to)
{
	struct _inode *inode = tx_cache_get_inode(page->mapping->host);
	loff_t pos = ((loff_t)page->index << PAGE_CACHE_SHIFT) + to;

	if (!PageUptodate(page))
		SetPageUptodate(page);
	/*
	 * No need to use i_size_read() here, the i_size
	 * cannot change under us because we hold the i_mutex.
	 */
	if (pos > inode->i_size)
		i_size_write(inode, pos);
	set_page_dirty(page);
	return 0;
}

/*
 * the inodes created here are not hashed. If you use iunique to generate
 * unique inode values later for this filesystem, then you must take care
 * to pass it an appropriate max_reserved value to avoid collisions.
 */
int simple_fill_super(struct super_block *s, int magic, struct tree_descr *files)
{
	struct inode *inode;
	struct _inode *_inode;
	struct dentry *root;
	struct _dentry *_root;
	struct dentry *dentry;
	struct _dentry *_dentry;
	int i;

	s->s_blocksize = PAGE_CACHE_SIZE;
	s->s_blocksize_bits = PAGE_CACHE_SHIFT;
	s->s_magic = magic;
	s->s_op = &simple_super_operations;
	s->s_time_gran = 1;

	inode = new_inode(s);
	if (!inode)
		return -ENOMEM;
	
	// Shouldn't be tx here
	KSTM_BUG_ON(live_transaction());
	_inode = tx_cache_get_inode(inode);
	/*
	 * because the root inode is 1, the files array must not contain an
	 * entry at index 1
	 */
	_inode->i_ino = 1;
	_inode->i_mode = S_IFDIR | 0755;
	_inode->i_uid = _inode->i_gid = 0;
	inode->i_blocks = 0;
	_inode->i_atime = _inode->i_mtime = _inode->i_ctime = CURRENT_TIME;
	_inode->i_op = &simple_dir_inode_operations;
	_inode->i_fop = &simple_dir_operations;
	_inode->i_nlink = 2;
	root = d_alloc_root(_inode);
	if (!root) {
		iput(inode);
		return -ENOMEM;
	}
	_root = tx_cache_get_dentry(root);
	for (i = 0; !files->name || files->name[0]; i++, files++) {
		if (!files->name)
			continue;

		/* warn if it tries to conflict with the root inode */
		if (unlikely(i == 1))
			printk(KERN_WARNING "%s: %s passed in a files array"
				"with an index of 1!\n", __func__,
				s->s_type->name);

		dentry = d_alloc_name(_root, files->name);
		if (!dentry)
			goto out;
		_dentry = tx_cache_get_dentry(dentry);
		inode = new_inode(s);
		if (!inode)
			goto out;
		_inode = tx_cache_get_inode(inode);
		_inode->i_mode = S_IFREG | files->mode;
		_inode->i_uid = _inode->i_gid = 0;
		inode->i_blocks = 0;
		_inode->i_atime = _inode->i_mtime = _inode->i_ctime = CURRENT_TIME;
		_inode->i_fop = files->ops;
		_inode->i_ino = i;
		d_add(_dentry, _inode);
	}
	s->s_root = root;
	return 0;
out:
	d_genocide(_root);
	dput(root);
	return -ENOMEM;
}

static DEFINE_SPINLOCK(pin_fs_lock);

int simple_pin_fs(struct file_system_type *type, struct vfsmount **mount, int *count)
{
	struct vfsmount *mnt = NULL;
	spin_lock(&pin_fs_lock);
	if (unlikely(!*mount)) {
		spin_unlock(&pin_fs_lock);
		mnt = vfs_kern_mount(type, 0, type->name, NULL);
		if (IS_ERR(mnt))
			return PTR_ERR(mnt);
		spin_lock(&pin_fs_lock);
		if (!*mount)
			*mount = mnt;
	}
	mntget(*mount);
	++*count;
	spin_unlock(&pin_fs_lock);
	mntput(mnt);
	return 0;
}

void simple_release_fs(struct vfsmount **mount, int *count)
{
	struct vfsmount *mnt;
	spin_lock(&pin_fs_lock);
	mnt = *mount;
	if (!--*count)
		*mount = NULL;
	spin_unlock(&pin_fs_lock);
	mntput(mnt);
}

ssize_t simple_read_from_buffer(void __user *to, size_t count, loff_t *ppos,
				const void *from, size_t available)
{
	loff_t pos = *ppos;
	if (pos < 0)
		return -EINVAL;
	if (pos >= available)
		return 0;
	if (count > available - pos)
		count = available - pos;
	if (copy_to_user(to, from + pos, count))
		return -EFAULT;
	*ppos = pos + count;
	return count;
}

/*
 * Transaction based IO.
 * The file expects a single write which triggers the transaction, and then
 * possibly a read which collects the result - which is stored in a
 * file-local buffer.
 */
char *simple_transaction_get(struct file *file, const char __user *buf, size_t size)
{
	struct simple_transaction_argresp *ar;
	static DEFINE_SPINLOCK(simple_transaction_lock);

	if (size > SIMPLE_TRANSACTION_LIMIT - 1)
		return ERR_PTR(-EFBIG);

	ar = (struct simple_transaction_argresp *)get_zeroed_page(GFP_KERNEL);
	if (!ar)
		return ERR_PTR(-ENOMEM);

	spin_lock(&simple_transaction_lock);

	/* only one write allowed per open */
	if (file->private_data) {
		spin_unlock(&simple_transaction_lock);
		free_page((unsigned long)ar);
		return ERR_PTR(-EBUSY);
	}

	file->private_data = ar;

	spin_unlock(&simple_transaction_lock);

	if (copy_from_user(ar->data, buf, size))
		return ERR_PTR(-EFAULT);

	return ar->data;
}

ssize_t simple_transaction_read(struct file *file, char __user *buf, size_t size, loff_t *pos)
{
	struct simple_transaction_argresp *ar = file->private_data;

	if (!ar)
		return 0;
	return simple_read_from_buffer(buf, size, pos, ar->data, ar->size);
}

int simple_transaction_release(struct inode *inode, struct file *file)
{
	free_page((unsigned long)file->private_data);
	return 0;
}

/* Simple attribute files */

struct simple_attr {
	u64 (*get)(void *);
	void (*set)(void *, u64);
	char get_buf[24];	/* enough to store a u64 and "\n\0" */
	char set_buf[24];
	void *data;
	const char *fmt;	/* format for read operation */
	struct mutex mutex;	/* protects access to these buffers */
};

/* simple_attr_open is called by an actual attribute open file operation
 * to set the attribute specific access operations. */
int simple_attr_open(struct inode *inode, struct file *file,
		     u64 (*get)(void *), void (*set)(void *, u64),
		     const char *fmt)
{
	struct simple_attr *attr;

	attr = kmalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	attr->get = get;
	attr->set = set;
	attr->data = inode->i_private;
	attr->fmt = fmt;
	mutex_init(&attr->mutex);

	file->private_data = attr;

	return nonseekable_open(tx_cache_get_inode(inode), file);
}

int simple_attr_close(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	return 0;
}

/* read from the buffer that is filled with the get function */
ssize_t simple_attr_read(struct file *file, char __user *buf,
			 size_t len, loff_t *ppos)
{
	struct simple_attr *attr;
	size_t size;
	ssize_t ret;

	attr = file->private_data;

	if (!attr->get)
		return -EACCES;

	mutex_lock(&attr->mutex);
	if (*ppos) /* continued read */
		size = strlen(attr->get_buf);
	else	  /* first read */
		size = scnprintf(attr->get_buf, sizeof(attr->get_buf),
				 attr->fmt,
				 (unsigned long long)attr->get(attr->data));

	ret = simple_read_from_buffer(buf, len, ppos, attr->get_buf, size);
	mutex_unlock(&attr->mutex);
	return ret;
}

/* interpret the buffer as a number to call the set function with */
ssize_t simple_attr_write(struct file *file, const char __user *buf,
			  size_t len, loff_t *ppos)
{
	struct simple_attr *attr;
	u64 val;
	size_t size;
	ssize_t ret;

	attr = file->private_data;

	if (!attr->set)
		return -EACCES;

	mutex_lock(&attr->mutex);
	ret = -EFAULT;
	size = min(sizeof(attr->set_buf) - 1, len);
	if (copy_from_user(attr->set_buf, buf, size))
		goto out;

	ret = len; /* claim we got the whole input */
	attr->set_buf[size] = '\0';
	val = simple_strtol(attr->set_buf, NULL, 0);
	attr->set(attr->data, val);
out:
	mutex_unlock(&attr->mutex);
	return ret;
}

EXPORT_SYMBOL(dcache_dir_close);
EXPORT_SYMBOL(dcache_dir_lseek);
EXPORT_SYMBOL(dcache_dir_open);
EXPORT_SYMBOL(dcache_readdir);
EXPORT_SYMBOL(generic_read_dir);
EXPORT_SYMBOL(get_sb_pseudo);
EXPORT_SYMBOL(simple_commit_write);
EXPORT_SYMBOL(simple_dir_inode_operations);
EXPORT_SYMBOL(simple_dir_operations);
EXPORT_SYMBOL(simple_empty);
EXPORT_SYMBOL(d_alloc_name);
EXPORT_SYMBOL(simple_fill_super);
EXPORT_SYMBOL(simple_getattr);
EXPORT_SYMBOL(simple_link);
EXPORT_SYMBOL(simple_lookup);
EXPORT_SYMBOL(simple_pin_fs);
EXPORT_SYMBOL(simple_prepare_write);
EXPORT_SYMBOL(simple_readpage);
EXPORT_SYMBOL(simple_release_fs);
EXPORT_SYMBOL(simple_rename);
EXPORT_SYMBOL(simple_rmdir);
EXPORT_SYMBOL(simple_statfs);
EXPORT_SYMBOL(simple_sync_file);
EXPORT_SYMBOL(simple_unlink);
EXPORT_SYMBOL(simple_read_from_buffer);
EXPORT_SYMBOL(simple_transaction_get);
EXPORT_SYMBOL(simple_transaction_read);
EXPORT_SYMBOL(simple_transaction_release);
EXPORT_SYMBOL_GPL(simple_attr_open);
EXPORT_SYMBOL_GPL(simple_attr_close);
EXPORT_SYMBOL_GPL(simple_attr_read);
EXPORT_SYMBOL_GPL(simple_attr_write);
