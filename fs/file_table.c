/*
 *  linux/fs/file_table.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 1997 David S. Miller (davem@caip.rutgers.edu)
 */

#include <linux/string.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/eventpoll.h>
#include <linux/rcupdate.h>
#include <linux/mount.h>
#include <linux/capability.h>
#include <linux/cdev.h>
#include <linux/fsnotify.h>
#include <linux/sysctl.h>
#include <linux/percpu_counter.h>

#include <linux/tx_inodes.h>
#include <linux/tx_dentry.h>

#include <asm/atomic.h>

/* sysctl tunables... */
struct files_stat_struct files_stat = {
	.max_files = NR_FILE
};

/* public. Not pretty! */
__cacheline_aligned_in_smp DEFINE_SPINLOCK(files_lock);

static struct percpu_counter nr_files __cacheline_aligned_in_smp;

static inline void file_free_rcu(struct rcu_head *head)
{
	struct file *f =  container_of(head, struct file, fu_rcuhead);
	struct _file *_f = f->f_contents;
	kmem_cache_free(_filp_cachep, _f);
	kmem_cache_free(filp_cachep, f);
}

static inline void file_free(struct file *f)
{
	percpu_counter_dec(&nr_files);
	if(unlikely(live_transaction())){
		/* DEP 2/26/09: If we free (early release) a file in
		 * the tx, don't really free it until commit or abort
		 * so that atomic op rollback doesn't corrupt the
		 * slab.
		 */
		f->fu_rcuhead.func = file_free_rcu;
		spin_lock(&current->transaction->lock);
		f->fu_rcuhead.next = current->transaction->deferred_frees;
		current->transaction->deferred_frees = &f->fu_rcuhead;
		spin_unlock(&current->transaction->lock);
	} else
		call_rcu(&f->fu_rcuhead, file_free_rcu);
}

/*
 * Return the total number of open files in the system
 */
static int get_nr_files(void)
{
	return percpu_counter_read_positive(&nr_files);
}

/*
 * Return the maximum number of open files in the system
 */
int get_max_files(void)
{
	return files_stat.max_files;
}
EXPORT_SYMBOL_GPL(get_max_files);

/*
 * Handle nr_files sysctl
 */
#if defined(CONFIG_SYSCTL) && defined(CONFIG_PROC_FS)
int proc_nr_files(ctl_table *table, int write, struct file *filp,
                     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	files_stat.nr_files = get_nr_files();
	return proc_dointvec(table, write, filp, buffer, lenp, ppos);
}
#else
int proc_nr_files(ctl_table *table, int write, struct file *filp,
                     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}
#endif

/* Find an unused file structure and return a pointer to it.
 * Returns NULL, if there are no more free file structures or
 * we run out of memory.
 */
struct file *get_empty_filp(void)
{
	struct task_struct *tsk;
	static int old_max;
	struct file * f;
	struct _file * _f;

	/*
	 * Privileged users can go above max_files
	 */
	if (get_nr_files() >= files_stat.max_files && !capable(CAP_SYS_ADMIN)) {
		/*
		 * percpu_counters are inaccurate.  Do an expensive check before
		 * we go and fail.
		 */
		if (percpu_counter_sum(&nr_files) >= files_stat.max_files)
			goto over;
	}

	f = kmem_cache_alloc(filp_cachep, GFP_KERNEL);
	if (f == NULL)
		goto fail;

	_f = kmem_cache_alloc(_filp_cachep, GFP_KERNEL);
	if (f == NULL){
		kmem_cache_free(filp_cachep, f);
		goto fail;
	}
	percpu_counter_inc(&nr_files);
	memset(f, 0, sizeof(*f));
	memset(_f, 0, sizeof(*_f));
	f->f_contents = _f;
	_f->parent = f;
	if (security_file_alloc(f))
		goto fail_sec;

	tsk = current;
	INIT_LIST_HEAD(&f->fu_list);
	atomic_set(&f->f_count, 1);
	rwlock_init(&f->f_owner.lock);
	_f->f_uid = tsk->fsuid;
	_f->f_gid = tsk->fsgid;
	eventpoll_init_file(f);
	/* f->f_version: 0 */
#ifdef CONFIG_TX_KSTM
	init_tx_object(&f->xobj, TYPE_FILE);
	f->tx_alloc = live_transaction();
	// Make sure we get the file in rw mode
	if(f->tx_alloc)
		tx_cache_get_file(f);
#endif
	return f;

over:
	/* Ran out of filps - report that */
	if (get_nr_files() > old_max) {
		printk(KERN_INFO "VFS: file-max limit %d reached\n",
					get_max_files());
		old_max = get_nr_files();
	}
	goto fail;

fail_sec:
	file_free(f);
fail:
	return NULL;
}

EXPORT_SYMBOL(get_empty_filp);

void fastcall fput(struct file *file)
{
	if (tx_atomic_dec_and_test(&file->f_count)
	    || (file->tx_alloc && live_transaction() && atomic_read(&file->f_count) == 1)){
		int status = atomic_read(&current->transaction->status);
		if(status == TX_ABORTING){
			eventpoll_release(file);
			security_file_free(file);
			fops_put(file->f_op);
			put_pid(file->f_owner.pid);
			file_kill(file);
			file_free(file);
			return;
		}
		
		KSTM_BUG_ON(inactive_transaction() && file->tx_alloc);
		__fput(file);
	}
}

EXPORT_SYMBOL(fput);

/* __fput is called from task context when aio completion releases the last
 * last use of a struct file *.  Do not use otherwise.
 */
void fastcall __fput(struct file *file)
{
	struct _file *_file = tx_cache_get_file(file);
	struct dentry *dentry = _file->f_path.dentry;
	struct vfsmount *mnt = _file->f_path.mnt;
	struct _dentry *_dentry = f_get_dentry(_file);
	struct _inode *_inode = d_get_inode(_dentry);
	struct inode *inode = parent(_inode);

	might_sleep();

	fsnotify_close(file);
	/*
	 * The function eventpoll_release() should be the first called
	 * in the file cleanup chain.
	 */
	eventpoll_release(file);
	locks_remove_flock(file);

	if (file->f_op && file->f_op->release)
		file->f_op->release(_inode, file);
	security_file_free(file);
	if (unlikely(S_ISCHR(_inode->i_mode) && inode->i_cdev != NULL))
		cdev_put(inode->i_cdev);
	fops_put(file->f_op);
	if (_file->f_mode & FMODE_WRITE)
		put_write_access(inode);
	put_pid(file->f_owner.pid);
	file_kill(file);
	if(live_transaction())
		early_release(&file->xobj, 1);
	_file->f_path.dentry = NULL;
	_file->f_path.mnt = NULL;
	file_free(file);
	
	KSTM_BUG_ON(atomic_read(&dentry->d_count) == 0);

	dput(dentry);
	mntput(mnt);
}

struct file fastcall *fget(unsigned int fd)
{
	struct file *file;
	struct files_struct *files = current->files;

	rcu_read_lock();
	file = fcheck_files(files, fd);
	if (file) {
		if (!tx_atomic_inc_not_zero(&file->f_count)) {
			/* File object ref couldn't be taken */
			rcu_read_unlock();
			return NULL;
		}
	}
	rcu_read_unlock();

	return file;
}

EXPORT_SYMBOL(fget);

/*
 * Lightweight file lookup - no refcnt increment if fd table isn't shared. 
 * You can use this only if it is guranteed that the current task already 
 * holds a refcnt to that file. That check has to be done at fget() only
 * and a flag is returned to be passed to the corresponding fput_light().
 * There must not be a cloning between an fget_light/fput_light pair.
 */
struct file fastcall *fget_light(unsigned int fd, int *fput_needed)
{
	struct file *file;
	struct files_struct *files = current->files;

	*fput_needed = 0;
	if (likely((atomic_read(&files->count) == 1))) {
		file = fcheck_files(files, fd);
	} else {
		rcu_read_lock();
		file = fcheck_files(files, fd);
		if (file) {
			if (tx_atomic_inc_not_zero(&file->f_count))
				*fput_needed = 1;
			else
				/* Didn't get the reference, someone's freed */
				file = NULL;
		}
		rcu_read_unlock();
	}

	return file;
}


void put_filp(struct file *file)
{
	if (tx_atomic_dec_and_test(&file->f_count)) {
		security_file_free(file);
		file_kill(file);
		file_free(file);
	}
}

void file_move(struct file *file, struct list_head *list)
{
	if (!list)
		return;

	file_list_lock();
	list_move(&file->fu_list, list);
	file_list_unlock();
}

void file_kill(struct file *file)
{
	if (!list_empty(&file->fu_list)) {
		file_list_lock();
		list_del_init(&file->fu_list);
		file_list_unlock();
	}
}

int fs_may_remount_ro(struct super_block *sb)
{
	struct list_head *p;

	/* Check that no files are currently opened for writing. */
	file_list_lock();
	list_for_each(p, &sb->s_files) {
		struct file *file = list_entry(p, struct file, fu_list);
		struct _inode *_inode = d_get_inode(file_get_dentry(file));

		/* File with pending delete? */
		if (_inode->i_nlink == 0)
			goto too_bad;

		/* Writeable file? */
		if (S_ISREG(_inode->i_mode) && (tx_cache_get_file_ro(file)->f_mode & FMODE_WRITE))
			goto too_bad;
	}
	file_list_unlock();
	return 1; /* Tis' cool bro. */
too_bad:
	file_list_unlock();
	return 0;
}

void __init files_init(unsigned long mempages)
{ 
	int n; 
	/* One file with associated inode and dcache is very roughly 1K. 
	 * Per default don't use more than 10% of our memory for files. 
	 */ 

	n = (mempages * (PAGE_SIZE / 1024)) / 10;
	files_stat.max_files = n; 
	if (files_stat.max_files < NR_FILE)
		files_stat.max_files = NR_FILE;
	files_defer_init();
	percpu_counter_init(&nr_files, 0);
} 
