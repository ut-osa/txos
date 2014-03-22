/*
 *  linux/fs/file.c
 *
 *  Copyright (C) 1998-1999, Stephen Tweedie and Bill Hawes
 *
 *  Manage the dynamic fd arrays in the process files_struct.
 */

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/time.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/file.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/workqueue.h>

struct fdtable_defer {
	spinlock_t lock;
	struct work_struct wq;
	struct fdtable *next;
};

/*
 * We use this list to defer free fdtables that have vmalloced
 * sets/arrays. By keeping a per-cpu list, we avoid having to embed
 * the work_struct in fdtable itself which avoids a 64 byte (i386) increase in
 * this per-task structure.
 */
static DEFINE_PER_CPU(struct fdtable_defer, fdtable_defer_list);

static inline void * alloc_fdmem(unsigned int size)
{
	if (size <= PAGE_SIZE)
		return kmalloc(size, GFP_KERNEL);
	else
		return vmalloc(size);
}

static inline void free_fdarr(struct fdtable *fdt)
{
	if (fdt->max_fds <= (PAGE_SIZE / sizeof(struct file *)))
		kfree(fdt->fd);
	else
		vfree(fdt->fd);
}

static inline void free_fdset(struct fdtable *fdt)
{
	if (fdt->max_fds <= (PAGE_SIZE * BITS_PER_BYTE / 2))
		kfree(fdt->open_fds);
	else
		vfree(fdt->open_fds);
}

static void free_fdtable_work(struct work_struct *work)
{
	struct fdtable_defer *f =
		container_of(work, struct fdtable_defer, wq);
	struct fdtable *fdt;

	spin_lock_bh(&f->lock);
	fdt = f->next;
	f->next = NULL;
	spin_unlock_bh(&f->lock);
	while(fdt) {
		struct fdtable *next = fdt->next;
		vfree(fdt->fd);
		free_fdset(fdt);
		kfree(fdt);
		fdt = next;
	}
}

void free_fdtable_rcu(struct rcu_head *rcu)
{
	struct fdtable *fdt = container_of(rcu, struct fdtable, rcu);
	struct fdtable_defer *fddef;

	BUG_ON(!fdt);

	if (fdt->max_fds <= NR_OPEN_DEFAULT) {
		/*
		 * This fdtable is embedded in the files structure and that
		 * structure itself is getting destroyed.
		 */
		kmem_cache_free(files_cachep,
				container_of(fdt, struct files_struct, fdtab));
		return;
	}
	if (fdt->max_fds <= (PAGE_SIZE / sizeof(struct file *))) {
		kfree(fdt->fd);
		kfree(fdt->open_fds);
		kfree(fdt);
	} else {
		fddef = &get_cpu_var(fdtable_defer_list);
		spin_lock(&fddef->lock);
		fdt->next = fddef->next;
		fddef->next = fdt;
		/* vmallocs are handled from the workqueue context */
		schedule_work(&fddef->wq);
		spin_unlock(&fddef->lock);
		put_cpu_var(fdtable_defer_list);
	}
}

/*
 * Expand the fdset in the files_struct.  Called with the files spinlock
 * held for write.
 */
static void copy_fdtable(struct fdtable *nfdt, struct fdtable *ofdt)
{
	unsigned int cpy, set;

	BUG_ON(nfdt->max_fds < ofdt->max_fds);
	if (ofdt->max_fds == 0)
		return;

	cpy = ofdt->max_fds * sizeof(struct file *);
	set = (nfdt->max_fds - ofdt->max_fds) * sizeof(struct file *);
	memcpy(nfdt->fd, ofdt->fd, cpy);
	memset((char *)(nfdt->fd) + cpy, 0, set);

	cpy = ofdt->max_fds / BITS_PER_BYTE;
	set = (nfdt->max_fds - ofdt->max_fds) / BITS_PER_BYTE;
	memcpy(nfdt->open_fds, ofdt->open_fds, cpy);
	memset((char *)(nfdt->open_fds) + cpy, 0, set);
	memcpy(nfdt->close_on_exec, ofdt->close_on_exec, cpy);
	memset((char *)(nfdt->close_on_exec) + cpy, 0, set);
}

static struct fdtable * alloc_fdtable(unsigned int nr)
{
	struct fdtable *fdt;
	char *data;

	/*
	 * Figure out how many fds we actually want to support in this fdtable.
	 * Allocation steps are keyed to the size of the fdarray, since it
	 * grows far faster than any of the other dynamic data. We try to fit
	 * the fdarray into comfortable page-tuned chunks: starting at 1024B
	 * and growing in powers of two from there on.
	 */
	nr /= (1024 / sizeof(struct file *));
	nr = roundup_pow_of_two(nr + 1);
	nr *= (1024 / sizeof(struct file *));
	if (nr > NR_OPEN)
		nr = NR_OPEN;

	fdt = kmalloc(sizeof(struct fdtable), GFP_KERNEL);
	if (!fdt)
		goto out;
	fdt->max_fds = nr;
	data = alloc_fdmem(nr * sizeof(struct file *));
	if (!data)
		goto out_fdt;
	fdt->fd = (struct file **)data;
	data = alloc_fdmem(max_t(unsigned int,
				 2 * nr / BITS_PER_BYTE, L1_CACHE_BYTES));
	if (!data)
		goto out_arr;
	fdt->open_fds = (fd_set *)data;
	data += nr / BITS_PER_BYTE;
	fdt->close_on_exec = (fd_set *)data;
	INIT_RCU_HEAD(&fdt->rcu);
	fdt->next = NULL;

	return fdt;

out_arr:
	free_fdarr(fdt);
out_fdt:
	kfree(fdt);
out:
	return NULL;
}

/*
 * Expand the file descriptor table.
 * This function will allocate a new fdtable and both fd array and fdset, of
 * the given size.
 * Return <0 error code on error; 1 on successful completion.
 * The files->file_lock should be held on entry, and will be held on exit.
 */
static int expand_fdtable(struct files_struct *files, int nr)
	__releases(files->file_lock)
	__acquires(files->file_lock)
{
	struct fdtable *new_fdt, *cur_fdt;

	spin_unlock(&files->file_lock);
	new_fdt = alloc_fdtable(nr);
	spin_lock(&files->file_lock);
	if (!new_fdt)
		return -ENOMEM;
	/*
	 * Check again since another task may have expanded the fd table while
	 * we dropped the lock
	 */
	cur_fdt = files_fdtable(files);
	if (nr >= cur_fdt->max_fds) {
		/* Continue as planned */
		copy_fdtable(new_fdt, cur_fdt);
		rcu_assign_pointer(files->fdt, new_fdt);
		if (cur_fdt->max_fds > NR_OPEN_DEFAULT)
			free_fdtable(cur_fdt);
	} else {
		/* Somebody else expanded, so undo our attempt */
		free_fdarr(new_fdt);
		free_fdset(new_fdt);
		kfree(new_fdt);
	}
	return 1;
}

/*
 * Expand files.
 * This function will expand the file structures, if the requested size exceeds
 * the current capacity and there is room for expansion.
 * Return <0 error code on error; 0 when nothing done; 1 when files were
 * expanded and execution may have blocked.
 * The files->file_lock should be held on entry, and will be held on exit.
 */
int expand_files(struct files_struct *files, int nr)
{
	struct fdtable *fdt;

	fdt = files_fdtable(files);
	/* Do we need to expand? */
	if (nr < fdt->max_fds)
		return 0;
	/* Can we expand? */
	if (nr >= NR_OPEN)
		return -EMFILE;

	/* All good, so we try */
	return expand_fdtable(files, nr);
}

static void __devinit fdtable_defer_list_init(int cpu)
{
	struct fdtable_defer *fddef = &per_cpu(fdtable_defer_list, cpu);
	spin_lock_init(&fddef->lock);
	INIT_WORK(&fddef->wq, free_fdtable_work);
	fddef->next = NULL;
}

void __init files_defer_init(void)
{
	int i;
	for_each_possible_cpu(i)
		fdtable_defer_list_init(i);
}

void checkpoint_files(void){
	BUG_ON(current->files == NULL);

	/* DEP 3/6/09: XXX: Chris can hack around this. LDAP is our only
	 * multi-threaded workload at the moment.  We should go back
	 * and do this right later. */
#ifdef CONFIG_TX_KSTM_WARNINGS
	if(atomic_read(&current->files->count) > 1){
		printk(KERN_ERR "WARNING: Multi-threaded task trying to checkpoint files.  Get ready for some -EBADFs\n");
	}
#endif
	if(current->files_checkpoint == NULL){
		current->files_checkpoint = kmem_cache_alloc(files_cachep, GFP_KERNEL);
		BUG_ON(!current->files_checkpoint);
		spin_lock(&current->files->file_lock);
		memcpy(current->files_checkpoint, current->files, sizeof(struct files_struct));
		spin_lock_init(&current->files_checkpoint->file_lock);
		if(current->files->fdt == &current->files->fdtab)
			current->files_checkpoint->fdt = &current->files_checkpoint->fdtab;
		else {
			// Allocate and copy
			struct fdtable *new = alloc_fdtable(current->files->fdt->max_fds / 2);
			copy_fdtable(new, current->files->fdt);
			current->files_checkpoint->fdt = new;
		}
		
		spin_unlock(&current->files->file_lock);

	} else {
		struct fdtable *fdt = current->files_checkpoint->fdt;
		spin_lock(&current->files->file_lock);
		memcpy(current->files_checkpoint, current->files,
		       sizeof(struct files_struct));
		spin_lock_init(&current->files_checkpoint->file_lock);
		// Put back the fdt pointer
		current->files_checkpoint->fdt = fdt;
		
		if(current->files->fdt->max_fds != current->files_checkpoint->fdt->max_fds){
			printk(KERN_ERR "Expanding checkpoint from %d to %d\n",
			       current->files_checkpoint->fdt->max_fds, 
			       current->files->fdt->max_fds);
			spin_lock(&current->files_checkpoint->file_lock);
			expand_fdtable(current->files_checkpoint, 
				       current->files->fdt->max_fds / 2);
			spin_unlock(&current->files_checkpoint->file_lock);
		}
		copy_fdtable(current->files_checkpoint->fdt, current->files->fdt);

		spin_unlock(&current->files->file_lock);
	}
	current->files_checkpoint_current = 1;

	if(current->files_checkpoint->fdt->max_fds != current->files->fdt->max_fds){
		printk(KERN_ERR "fds %d %d\n", current->files_checkpoint->fdt->max_fds,
		       current->files->fdt->max_fds);
		OSA_MAGIC(OSA_BREAKSIM);
	}

	KSTM_BUG_ON(current->files_checkpoint->fdt->max_fds != current->files->fdt->max_fds);

}


void release_files_checkpoint(struct task_struct *tsk){
	struct fdtable *fdt;
	if(!tsk->files_checkpoint)
		return;

	fdt = tsk->files_checkpoint->fdt;
	if(fdt != &tsk->files_checkpoint->fdtab)
		kmem_cache_free(files_cachep, tsk->files_checkpoint);
	free_fdtable(fdt);
		
	tsk->files_checkpoint = NULL;
}

void rollback_files_checkpoint(struct task_struct *tsk){
	if((!tsk->files_checkpoint) || !(tsk->files_checkpoint_current))
		return;

	/* I think this is actually sufficient */
	copy_fdtable(tsk->files->fdt, tsk->files_checkpoint->fdt);
	tsk->files->next_fd = tsk->files_checkpoint->next_fd;

}

// early release on exit
