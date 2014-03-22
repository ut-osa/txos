#include <linux/transaction.h>
#include <linux/fs.h>
#include <linux/tx_inodes.h>
#include <linux/osamagic.h>
#include <linux/syscalls.h>
#include <linux/proc_fs.h>
#include <linux/mount.h>
#include <linux/blkdev.h>
#include <linux/shmem_fs.h>
#include <linux/mqueue.h>
#include <asm/uaccess.h>
#include <linux/ext2_fs_i.h>
#include <linux/ext2_fs_sb.h>
#include <linux/file.h>
#include <net/sock.h>
#include <linux/fsnotify.h>
#include <linux/tx_file.h>
#include <linux/debugtx.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/key.h>
#include <linux/cn_proc.h>
#include <linux/tx_signal.h>
#include <linux/tx_jbd.h>
#include <linux/tx_pages.h>
#include <asm/transaction.h>
#include <asm/i387.h>
#include <linux/random.h>

extern struct transaction exit_placeholder;

struct proc_dir_entry *kstm_ctl_procfile;
struct proc_dir_entry *kstm_commit_procfile;
static int kstm_on = 0;
#define PROC_BUF_SIZE 64
static char proc_buffer[PROC_BUF_SIZE];
/* Track the number of active transactions for optimal perf */
atomic_t tx_count;

/* The undo log cache */
struct kmem_cache *undo_log_cachep;
/* per-object deferred operations */
struct kmem_cache *deferred_object_operation_struct_cachep;

/* The conflict resolution policy:
* 0 - dynamic priority first, ties broken by timestamp [DEFAULT]
* 1 - timestamp first, then arbitrary
* 2 - static priority first, ties broken by timestamp
*/
struct proc_dir_entry *tx_res_policy_ctl_procfile;
#define TX_POLICY_DYNAMIC_PRIO 0
#define TX_POLICY_TIMESTAMP 1
#define TX_POLICY_STATIC_PRIO 2
static int tx_res_policy = TX_POLICY_DYNAMIC_PRIO;
static char proc_policy_buffer[PROC_BUF_SIZE];

int kstm_ctl_procfile_read(char *buffer,
			   char **buffer_location,
			   off_t offset, int buffer_length, int *eof, void *data){

	int ret = sprintf(buffer, "%d\n", kstm_on);
	return ret;
}

int kstm_ctl_procfile_write(struct file *file,
			    const char __user *buffer,
			    unsigned long count, void *data){
	
	/* get buffer size */
	int procfs_buffer_size = count;
	if (procfs_buffer_size > PROC_BUF_SIZE ) {
		procfs_buffer_size = PROC_BUF_SIZE;
	}
	
	/* write data to the buffer */
	if ( copy_from_user(proc_buffer, buffer, procfs_buffer_size) ) {
		return -EFAULT;
	}
	
	sscanf(proc_buffer, "%d", &kstm_on);
	return procfs_buffer_size;
}

static int commits = 0;
static int aborts = 0;

int kstm_commit_procfile_read(char *buffer,
			      char **buffer_location,
			      off_t offset, int buffer_length, int *eof, void *data){
	
	int ret = sprintf(buffer, "commits: %d\naborts: %d\n", 
			  commits, aborts);
	return ret;
}

int kstm_commit_procfile_write(struct file *file,
			       const char __user *buffer,
			       unsigned long count, void *data){
	commits = 0;
	aborts = 0;
	return count;
}

/* Conflict policy procfile handlers */
int tx_res_policy_ctl_procfile_read(char *buffer,
				    char **buffer_location,
				    off_t offset, int buffer_length, 
				    int *eof, void *data){

	int ret = sprintf(buffer, "%d\n", tx_res_policy);
	return ret;
}

int tx_res_policy_ctl_procfile_write(struct file *file,
			    const char __user *buffer,
			    unsigned long count, void *data){
	
  int new_policy=0;
  /* get buffer size */
  int procfs_buffer_size = count;
  if (procfs_buffer_size > PROC_BUF_SIZE ) {
    procfs_buffer_size = PROC_BUF_SIZE;
  }
  
  /* write data to the buffer */
  if ( copy_from_user(proc_policy_buffer, buffer, procfs_buffer_size) ) {
    return -EFAULT;
  }
  
  sscanf(proc_policy_buffer, "%d", &new_policy);
  /* bound valid values */
  if (new_policy >= 0 && new_policy <= 2) 
    tx_res_policy = new_policy;
  
  return procfs_buffer_size;
}

struct kmem_cache *cp_cachep;

int tx_chkpt_task_fields(struct task_struct *tsk) {
	if (atomic_read(&tsk->transaction->status) != TX_INACTIVE && 
	    tsk->cp == NULL) {
		/*DEBUG 
		  printk(KERN_ERR "checkpoint! task values:\n");
		  printk(KERN_ERR "uid=%d fsuid=%d gid=%d fsgid=%d fsptr=%x robustptr=%x sigptr=%x\n",
		  current->uid, current->fsuid, current->gid,
		  current->fsgid, current->fs, current->robust_list,
		  current->signal);
		*/
		tsk->cp = kmem_cache_alloc(cp_cachep, GFP_KERNEL);
		BUG_ON(tsk->cp == NULL);
		if (memcpy(tsk->cp, &tsk->uid, sizeof(struct xstruct)) < 0)
			return -1;
		/*
		printk(KERN_ERR "cp values: uid=%d fsuid=%d gid=%d fsgid=%d fsptr=%x robustptr=%x sigptr=%x\n",
		       current->cp->uid, current->cp->fsuid, current->cp->gid,
		       current->cp->fsgid, current->cp->fs,
		       current->cp->robust_list, current->cp->signal);
		*/
	}
	return 0;
}

#ifdef CONFIG_TX_KSTM_PROF

unsigned long long commitCycles = 0;
unsigned long long shadowCopyCycles = 0;

struct proc_dir_entry *kstm_prof_procfile;

int kstm_prof_procfile_read(char *buffer,
			    char **buffer_location,
			    off_t offset, int buffer_length, int *eof, void *data){
	int ret;
	if(offset > 0){
		ret = 0;
	} else {
		/* Just print access until we get it working.
		 * No floating point math in the kernel :(
		 */
		ret = sprintf(buffer, "Commit: %llu\nShadow: %llu\n", commitCycles, shadowCopyCycles);
		buffer += ret;
	}
	return ret;

}


int kstm_prof_procfile_write(struct file *file,
			const char __user *buffer,
			unsigned long count, void *data){
	commitCycles = 0;
	shadowCopyCycles = 0;
	return count;
}

#endif // CONFIG_TX_KSTM_PROF


#ifdef CONFIG_TX_KSTM_STATS

unsigned long long syscall_counts[NR_syscalls];
unsigned long long syscall_aborts[NR_syscalls];
unsigned long long syscall_cycles[NR_syscalls];
unsigned long long syscall_cycles_squared[NR_syscalls];
unsigned long long syscall_r[NR_syscalls];
unsigned long long syscall_w[NR_syscalls];
unsigned long long syscall_bytes[NR_syscalls];

unsigned long long hash_distribution[TX_HASH_BUCKETS];
unsigned long long hit_distribution[TX_HASH_BUCKETS];
unsigned long long miss_distribution[TX_HASH_BUCKETS];
unsigned long long upgrade_distribution[TX_HASH_BUCKETS];
unsigned long long pointless_distribution[TX_HASH_BUCKETS];

static spinlock_t kstm_stat_spin;

struct proc_dir_entry *kstm_procfile;

int kstm_procfile_read(char *buffer,
		       char **buffer_location,
		       off_t offset, int buffer_length, int *eof, void *data){
	int ret, r, i;
	spin_lock(&kstm_stat_spin);
	if(offset > 0){
		ret = 0;
	} else {
		/* Just print access until we get it working.
		 * No floating point math in the kernel :(
		 */
		ret = sprintf(buffer, "%u: %llu (%llu), %llu, %llu, (%llu, %llu), %llu\n", __NR_access, 
			      syscall_counts[__NR_access], 
			      syscall_aborts[__NR_access], 
			      syscall_cycles[__NR_access],
			      syscall_cycles_squared[__NR_access],
			      syscall_r[__NR_access],
			      syscall_w[__NR_access],
			      syscall_bytes[__NR_access]
			);
		buffer += ret;
		
		for(i = 0; i < TX_HASH_BUCKETS; i++){
			r = sprintf(buffer, "%d: %llu, h %llu, m %llu, u %llu, p %llu\n", i, 
				    hash_distribution[i], hit_distribution[i],
				    miss_distribution[i], upgrade_distribution[i],
				    pointless_distribution[i]);
				
				;
			ret += r;
			buffer += r;
		}

	}
	spin_unlock(&kstm_stat_spin);
	return ret;

}

static inline void reset_tx_stats(void){
	memset(syscall_counts, 0, NR_syscalls * sizeof(unsigned long long));
	memset(syscall_aborts, 0, NR_syscalls * sizeof(unsigned long long));
	memset(syscall_cycles, 0, NR_syscalls * sizeof(unsigned long long));
	memset(syscall_cycles_squared, 0, NR_syscalls * sizeof(unsigned long long));
	memset(syscall_r, 0, NR_syscalls * sizeof(unsigned long long));
	memset(syscall_w, 0, NR_syscalls * sizeof(unsigned long long));
	memset(syscall_bytes, 0, NR_syscalls * sizeof(unsigned long long));

	memset(hash_distribution, 0, TX_HASH_BUCKETS * sizeof(unsigned long long));
	memset(hit_distribution, 0, TX_HASH_BUCKETS * sizeof(unsigned long long));
	memset(miss_distribution, 0, TX_HASH_BUCKETS * sizeof(unsigned long long));
	memset(upgrade_distribution, 0, TX_HASH_BUCKETS * sizeof(unsigned long long));
	memset(pointless_distribution, 0, TX_HASH_BUCKETS * sizeof(unsigned long long));

}

int kstm_procfile_write(struct file *file,
			const char __user *buffer,
			unsigned long count, void *data){
	spin_lock(&kstm_stat_spin);
	reset_tx_stats();
	spin_unlock(&kstm_stat_spin);
	return count;

}

void init_tx_stats(){

   reset_tx_stats();

   kstm_procfile = create_proc_entry("kstm", 0644, 0);
   kstm_procfile->read_proc = kstm_procfile_read;
   kstm_procfile->write_proc = kstm_procfile_write;

   spin_lock_init(&kstm_stat_spin);
}

void stats_begin_tx(unsigned long syscall){
	spin_lock(&kstm_stat_spin);
	syscall_counts[syscall]++;
	spin_unlock(&kstm_stat_spin);
	current->syscall_start_time = native_read_tsc();
	current->syscall_cum_time = 0;
}

void stats_abort_tx(unsigned long eax){
	spin_lock(&kstm_stat_spin);
	syscall_aborts[eax]++;
	spin_unlock(&kstm_stat_spin);
}

inline void kstm_stats_sched(struct task_struct *prev, struct task_struct *next){
	if(prev->eax)
		prev->syscall_cum_time += native_read_tsc() - prev->syscall_start_time;

	if(next->eax)
		next->syscall_start_time = native_read_tsc();
}

static inline void stats_end_tx(unsigned long eax){
	unsigned long long delta = native_read_tsc() - current->syscall_start_time;
	delta += current->syscall_cum_time;
	spin_lock(&kstm_stat_spin);
	syscall_cycles[eax] += delta;
	syscall_cycles_squared[eax] += (delta * delta);
	spin_unlock(&kstm_stat_spin);
}

static inline void update_kstm_rw_stats(unsigned long eax, unsigned long long reads, unsigned long long writes, unsigned long bytes){
	spin_lock(&kstm_stat_spin);
	syscall_r[eax] += reads;
	syscall_w[eax] += writes;
	syscall_bytes[eax] += bytes;
	spin_unlock(&kstm_stat_spin);
}

#endif // CONFIG_TX_KSTM_STATS

#ifdef CONFIG_TX_KSTM

struct kmem_cache *cachep_tx_thread_list;
struct kmem_cache *atomic_cachep;
struct kmem_cache *alloc_cachep;
struct kmem_cache *fsnotify_cachep;
struct kmem_cache *tx_page_cachep;
struct kmem_cache *cachep_tx_list;
struct kmem_cache *cachep_tx_hlist;


// Just use an atomic counter for now - this may have negative
// performance consequences
atomic_t timestamp_counter;

// Contention manager function - timestamp Returns true if a wins the
// conflict over b.  Should sleep indicates that b lost due to a
// timestamp difference. This information allows us to prevent sleeper
// deadlock.
int contentionManager(struct transaction *a, struct transaction *b, int *should_sleep){
	// Also need to check the state
	int statusa = atomic_read(&a->status);
	int statusb = atomic_read(&b->status);
	int timestamp_winner = ((int)(a->timestamp) - (int)(b->timestamp) < 0);
	int prio_winner = 0;
	struct task_struct *next_task;

	switch (tx_res_policy) {
	case (TX_POLICY_TIMESTAMP):
		prio_winner = timestamp_winner;
		break;
	case (TX_POLICY_STATIC_PRIO):
	{
		/* Calculate the max prio of tasks in the tx */
		int prio_a = MAX_PRIO;
		int prio_b = MAX_PRIO;
		int prio_diff;
		spin_lock(&a->lock);
		list_for_each_entry(next_task, &a->tasks, transaction_entry)
			if(next_task->static_prio < prio_a)
				prio_a = next_task->static_prio;
		spin_unlock(&a->lock);

		spin_lock(&b->lock);
		list_for_each_entry(next_task, &b->tasks, transaction_entry)
			if(next_task->static_prio < prio_b)
				prio_b = next_task->static_prio;
		spin_unlock(&b->lock);
		
		prio_diff = prio_b - prio_a;
		if (prio_diff > 0)
			prio_winner = 1; //a wins
		else if (prio_diff < 0)
			prio_winner = 0; //b wins
		else prio_winner = timestamp_winner;
	}
	break;
	default: //TX_POLICY_DYNAMIC_PRIO - default
	{
		/* Calculate the max prio of tasks in the tx */
		int prio_a = MAX_PRIO;
		int prio_b = MAX_PRIO;
		int prio_diff;
		spin_lock(&a->lock);
		list_for_each_entry(next_task, &a->tasks, transaction_entry)
			if(next_task->prio < prio_a)
				prio_a = next_task->prio;
		spin_unlock(&a->lock);

		spin_lock(&b->lock);
		list_for_each_entry(next_task, &b->tasks, transaction_entry)
			if(next_task->prio < prio_b)
				prio_b = next_task->prio;
		spin_unlock(&b->lock);

		prio_diff = prio_b - prio_a;
		if (prio_diff > 0)
			prio_winner = 1; //a wins
		else if (prio_diff < 0)
			prio_winner = 0; //b wins
		else prio_winner = timestamp_winner;
	}
	break;
	}
	
	if(should_sleep)
		*should_sleep = 0;

	// Aborted tx's have to lose
	if(statusa == TX_ABORTED || statusa == TX_ABORTING)
		return 0;
	if(statusb == TX_ABORTED || statusb == TX_ABORTING)
		return 1;
	
	// Committing tx's have to win
	if(statusa == TX_COMMITTING)
		return 1;
	if(statusb == TX_COMMITTING)
		return 0;

	// Finally, if we have 2 real, honest-to-god active tx's,
	// arbitrate based on timestamp
	if(should_sleep)
		*should_sleep = 1;
	return prio_winner;
}

#ifdef CONFIG_TX_KSTM

void init_tx_global(){
   /* create a slab on which transaction_structs can be allocated */
   cachep_tx_vfsmount =
	   kmem_cache_create("tx_vfsmount_struct", 
			     sizeof(struct vfsmount),
			     0, SLAB_HWCACHE_ALIGN | SLAB_DESTROY_BY_RCU,
			     NULL, NULL);

#ifndef CONFIG_DISABLE_LIST2

   tx_list2_cachep =
	   kmem_cache_create("tx_list2_entry_struct", 
			     sizeof(struct tx_list2_entry),
			     0, SLAB_HWCACHE_ALIGN | SLAB_DESTROY_BY_RCU,
			     NULL, NULL);

#endif

   cachep_tx_thread_list =
	   kmem_cache_create("tx_thread_list_node_struct", 
			     sizeof(struct txobj_thread_list_node),
			     0, SLAB_HWCACHE_ALIGN | SLAB_DESTROY_BY_RCU,
			     NULL, NULL);

   /* Undo log rec cache */
   undo_log_cachep = 
	   kmem_cache_create("tx_undo_log_struct",
			     sizeof(struct undo_log_rec),
			     0, SLAB_HWCACHE_ALIGN | SLAB_DESTROY_BY_RCU,
			     NULL, NULL);

   /* Range lock record cache */
   range_lock_cachep = 
	   kmem_cache_create("range_lock_struct",
			     sizeof(struct range_lock),
			     0, SLAB_HWCACHE_ALIGN | SLAB_DESTROY_BY_RCU,
			     NULL, NULL);

   /* task checkpoint cache */
   cp_cachep = 
	   kmem_cache_create("tx_checkpoint_struct",
			     sizeof(struct xstruct),
			     0, SLAB_HWCACHE_ALIGN | SLAB_DESTROY_BY_RCU,
			     NULL, NULL);

   /* ATomic op Undo log rec cache */
   atomic_cachep = 
	   kmem_cache_create("atomic_op_buf",
			     sizeof(struct atomic_op_record_buf),
			     0, SLAB_HWCACHE_ALIGN | SLAB_DESTROY_BY_RCU,
			     NULL, NULL);


   alloc_cachep = 
	   kmem_cache_create("alloc_buf",
			     sizeof(struct alloc_record_buf),
			     0, SLAB_HWCACHE_ALIGN | SLAB_DESTROY_BY_RCU,
			     NULL, NULL);

   fsnotify_cachep = 
	   kmem_cache_create("fsnotify_buf",
			     sizeof(struct fsnotify_event_buf),
			     0, SLAB_HWCACHE_ALIGN | SLAB_DESTROY_BY_RCU,
			     NULL, NULL);

   tx_page_cachep = 
	   kmem_cache_create("tx_page_buf",
			     sizeof(struct page_record_buf),
			     0, SLAB_HWCACHE_ALIGN | SLAB_DESTROY_BY_RCU,
			     NULL, NULL);

   cachep_tx_list = 
	   kmem_cache_create("tx_list_buf",
			     sizeof(struct tx_list_head),
			     0, SLAB_HWCACHE_ALIGN | SLAB_DESTROY_BY_RCU,
			     NULL, NULL);
   cachep_tx_hlist = 
	   kmem_cache_create("tx_hlist_buf",
			     sizeof(struct tx_hlist_head),
			     0, SLAB_HWCACHE_ALIGN | SLAB_DESTROY_BY_RCU,
			     NULL, NULL);

   deferred_object_operation_struct_cachep = 
	   kmem_cache_create("deferred_object_operation",
			     sizeof(struct deferred_object_operation),
			     0, SLAB_HWCACHE_ALIGN | SLAB_DESTROY_BY_RCU,
			     NULL, NULL);

   atomic_set(&tx_count, 0);
}

void init_tx_proc(){
   kstm_ctl_procfile = create_proc_entry("kstm_ctl", 0644, 0);
   kstm_ctl_procfile->read_proc = kstm_ctl_procfile_read;
   kstm_ctl_procfile->write_proc = kstm_ctl_procfile_write;
   kstm_commit_procfile = create_proc_entry("kstm_commit", 0644, 0);
   kstm_commit_procfile->read_proc = kstm_commit_procfile_read;
   kstm_commit_procfile->write_proc = kstm_commit_procfile_write;
   //policy control
   tx_res_policy_ctl_procfile = create_proc_entry("tx_res_policy_ctl", 0644, 0);
   tx_res_policy_ctl_procfile->read_proc = tx_res_policy_ctl_procfile_read;
   tx_res_policy_ctl_procfile->write_proc = tx_res_policy_ctl_procfile_write;
#ifdef CONFIG_TX_KSTM_PROF
   // profiling
   kstm_prof_procfile = create_proc_entry("kstm_prof", 0644, 0);
   kstm_prof_procfile->read_proc = kstm_prof_procfile_read;
   kstm_prof_procfile->write_proc = kstm_prof_procfile_write;
#endif
}


// Some forward declarations
void remove_xnode_reference(struct transaction * t, struct transactional_object *xobj);
void remove_reader(struct transaction *t, struct transactional_object * xobj);

// This function can be called by an "adversary" to abort.
// Do not call to self-abort.  Call abort_self().
int abortTransaction(struct transaction *t){
	// If aborting someone else, just set their status word and ride
	// roughshod over their transactional objects
#ifdef CONFIG_TX_KSTM_DEBUG_STALL_ON_CONFLICT
	OSA_MAGIC(OSA_BREAKSIM);
#endif
	KSTM_BUG_ON(current->transaction == t);
	
	if (atomic_cmpxchg(&t->status, TX_ACTIVE, TX_ABORTED) == TX_ACTIVE) {
		log_enemy_abort();
	}
	return 0;
}

// Delete all readers for an object, abort them if abort is set.
// Called with xobj->lock held.
int remove_all_readers(struct transactional_object * xobj){
	struct txobj_thread_list_node *tx_node, *n;
	int readers = 0;
	list_for_each_entry_safe(tx_node, n, &xobj->readers, object_list){
		BUG_ON(atomic_read(&tx_node->tx->status) == TX_COMMITTING);

		;
		if(atomic_cmpxchg(&tx_node->tx->status, TX_ACTIVE, TX_ABORTED) == TX_ACTIVE) {
			log_enemy_abort();
		}
		list_del_init(&tx_node->object_list);
		readers++;
	}
	return readers;
}

// This is a complicated function: It must determine if any reader
// beats a new writer.  If so, the writer loses, no change to any
// readers.  If all readers lose to writer, all readers abort.
// Called with xobj->lock held
struct transaction * has_conflicting_reader(struct transaction *t,
					    struct transactional_object * xobj,
					    int test_only,
					    int *should_sleep){
	struct txobj_thread_list_node *tx_node, *n;

	list_for_each_entry(tx_node, &xobj->readers, object_list){

		// Don't compare to oneself
		if(tx_node->tx == t)
			continue;

		if(contentionManager(tx_node->tx, current->transaction, should_sleep))
			return tx_node->tx;
	}

	/* Quit early if we are just checking */
	if(test_only)
		return NULL;
	
	// At this point, we must knock off each reader that isn't us

	list_for_each_entry_safe(tx_node, n, &xobj->readers, object_list){

		if(tx_node->tx == t)
			continue;

		abortTransaction(tx_node->tx);
		list_del_init(&tx_node->object_list);
	}

	return NULL;
}

// Assumes all checks completed
struct txobj_thread_list_node * tx_add_reader(struct transactional_object *xobj){

	/* Can't alloc here - holding a spinlock */
	struct txobj_thread_list_node *new_list_node =  alloc_tx_thread_list_node();

	if(!new_list_node)
		return NULL;

	new_list_node->tx = current->transaction;
	new_list_node->tx_obj = xobj;
	INIT_LIST_HEAD(&new_list_node->object_list);
	INIT_SKIPLIST_HEAD(&new_list_node->workset_list);

	list_add(&new_list_node->object_list, &xobj->readers);

	return new_list_node;
}

//you must hold the lock to the struct transactional_object before calling this
//returns 0 if you added, 1 if you found it (clean this up)
// Called with xobj->lock held
struct txobj_thread_list_node * tx_check_add_reader(struct transactional_object * xobj){

	struct txobj_thread_list_node *tx_node;
	struct list_head *reader_list = &xobj->readers;

	// Make sure we aren't already there
	list_for_each_entry(tx_node, reader_list, object_list){

		if(current->transaction == tx_node->tx)
			return tx_node;
	}

	return tx_add_reader(xobj);
}

// Called with xobj->lock held
static inline struct transaction * contend_for_xobj(struct transactional_object *xobj, enum access_mode mode, 
						    int test_only, int *should_sleep,
						    struct txobj_thread_list_node **new_node){

	struct transaction *winner = NULL;

	// If we are already the reigning writer, skip
	// the rest of this
	if(xobj->writer == current->transaction)
		return NULL;

	/* CONFLICT DETECTION */

	// Checks for conflicts with existing readers (when trying to
	// write).  Check readers first because this minimizes aborts
	if(mode == ACCESS_RW){
		if((winner = has_conflicting_reader(current->transaction, xobj, test_only, should_sleep))){
			// We lose
			if(atomic_read(&current->transaction->status) != TX_INACTIVE) {
				log_self_abort();
				atomic_set(&current->transaction->status, TX_ABORTED);
			}
			return winner;
		}
	}

	// Check for conflicts with existing writer (that isn't me)
	if(xobj->writer != NULL){
		int abortSecond = contentionManager(xobj->writer, current->transaction, should_sleep);
		if(abortSecond){
			if(atomic_read(&current->transaction->status) != TX_INACTIVE){
				log_self_abort();
				atomic_set(&current->transaction->status, TX_ABORTED);
			}
			winner = xobj->writer;
			return winner;
		}
		else if(!test_only){
			
			if (atomic_cmpxchg(&xobj->writer->status, TX_ACTIVE, TX_ABORTED) == TX_ACTIVE) {
				log_enemy_abort();
			}
			xobj->writer = NULL;
		}
	}


	/* END CONFLICT DETECTION */

	/* NOW WE UPDATE THE TX MANAGEMENT DATA (if we are a real tx).
	 * If we are a non-tx syscall, just return early.*/
	if(atomic_read(&current->transaction->status) == TX_INACTIVE)
		return NULL;

	if (mode == ACCESS_RW){
		struct txobj_thread_list_node *tx_node = tx_check_add_reader(xobj);
		xobj->writer = current->transaction;
		if(new_node)
			*new_node = tx_node;
	}
	else if(mode == ACCESS_R){
		struct txobj_thread_list_node *tx_node = tx_check_add_reader(xobj);
		if(new_node)
			*new_node = tx_node;
	}
	else{
		printk(KERN_ERR "bad mode!\n");
	}

	return NULL;

}

/* If we can't wait (i.e. holding spinlocks/in interrupt), kick out
 * all asymmetrically conflicting transactions.  If we can, contend
 * fairly.  Return a pointer to the transaction to wait on if we
 * lose.  Must be holding object lock when called.
 */
struct transaction * check_asymmetric_conflict(struct transactional_object *xobj, enum access_mode mode, int can_sleep, int test_only){
	struct transaction *winner = NULL;
	int should_sleep = 0;
	int readers = 0;

	KSTM_BUG_ON(atomic_read(&current->transaction->status) != TX_INACTIVE);

	LOCK_XOBJ(xobj);

	/* If we can sleep, do the same contention as a tx */
	if(can_sleep){
		winner = contend_for_xobj(xobj, mode, test_only, &should_sleep, NULL);
		/* We expect to always lose based on
		 * policy, not transient state */
		KSTM_BUG_ON(winner && !should_sleep);

		UNLOCK_XOBJ(xobj);

		return winner;
		
		/* Comment this out unless we are debugging 
		   } else {
		   printk(KERN_ERR "Not Contending on asymmetric conflict, can_sleep = %d, count = %d\n", can_sleep, current_thread_info()->preempt_count2);
		   OSA_MAGIC(OSA_BREAKSIM);
		*/
	}

	/* If we can't sleep, be a bully to the tx's */
	if(xobj->writer != NULL){
		// Don't know how to handle this case
		BUG_ON(atomic_read(&xobj->writer->status) == TX_COMMITTING);

		
		if(atomic_cmpxchg(&xobj->writer->status, TX_ACTIVE, TX_ABORTED) == TX_ACTIVE) {
			log_enemy_abort();
		}
		xobj->writer = NULL;
	}
	// If the non-tx is in RW mode, kill the readers
	if(mode == ACCESS_RW)
		readers = remove_all_readers(xobj);
	
	// We need to copy the object so the readers keep a consistent cut
	if(readers && xobj->type == TYPE_INODE){
		replace_inode_notx(xobj);
	} else if(readers && xobj->type == TYPE_DENTRY){
		replace_dentry_notx(xobj);
	}


	UNLOCK_XOBJ(xobj);
	return winner;
}

// Update the access mode on a transactional object if we can.  Abort if we can't.
// Called with xobj->lock held
struct transaction * upgrade_xobj_mode(struct transactional_object *xobj, enum access_mode mode, int *should_sleep){
	struct transaction *winner;
	
#ifdef CONFIG_TX_KSTM_ABORT_OBJ_ON_UPGRADE
	int rand = 0;	
	current->upgrade_count++;
        
	printk(KERN_INFO "INFO: CONFIG_TX_KSTM_ABORT_OBJ_ON_UPGRADE :\n \
  								  upgrade_count=%d, \
                          transaction_count = %d\n", \
                          current->upgrade_count, current->transaction->count);

#ifdef CONFIG_TX_KSTM_ABORT_OBJ_ON_RANDOM
	
		rand = get_random_int() & 1;
		printk(KERN_INFO "INFO: CONFIG_TX_KSTM_ABORT_OBJ_ON_RANDOM :\n \
                          rand = %d\n", \
                          rand);

#endif /*CONFIG_TX_KSTM_ABORT_OBJ_ON_RANDOM*/

	if(((current->transaction->count+1) == current->upgrade_count) && !rand) {
		current->upgrade_count = 0;
		should_sleep = 0;
		printk(KERN_INFO "INFO:  !!Aborting\n");
		return current->transaction;
	}
		printk(KERN_INFO "INFO:  ***********\n");
#endif  /* CONFIG_TX_KSTM_ABORT_OBJ_ON_UPGRADE */

   // RW is the only other mode we know right now
	KSTM_BUG_ON(mode != ACCESS_RW);
	KSTM_BUG_ON(xobj->writer == current->transaction);

	// We should not be the writer if our mode is not RW
	KSTM_BUG_ON(xobj->writer == current->transaction);
	
	winner = contend_for_xobj(xobj, mode, 0, should_sleep, NULL);

	return winner;
}

static inline txobj_thread_list_node_t * __workset_has_object_locked(struct transactional_object *xobj){
	txobj_thread_list_node_t * node;
	list_for_each_entry(node, &xobj->readers, object_list){
		KSTM_BUG_ON(node->tx_obj != xobj);
		if(node->tx == current->transaction){
			return node;
		}
	}
	return NULL;

}

txobj_thread_list_node_t * workset_has_object_locked(struct transactional_object *xobj){
	return __workset_has_object_locked(xobj);
}
	
// Generalized workset lookup logic
txobj_thread_list_node_t * workset_has_object(struct transactional_object *xobj){
	txobj_thread_list_node_t * node;
	LOCK_XOBJ(xobj);
	node = __workset_has_object_locked(xobj);
	UNLOCK_XOBJ(xobj);
	return node;
}

void init_tx_object(struct transactional_object *new_tx_obj, enum tx_object_type type){
	// Init new tx obj
	new_tx_obj->type = type;
	INIT_LIST_HEAD(&new_tx_obj->readers);
	new_tx_obj->writer = NULL;
	spin_lock_init(&new_tx_obj->lock);
}

// Try to acquire a global xobj.  Returns thread list node reference if
// successful, NULL otherwise.
struct txobj_thread_list_node * tx_check_add_obj(struct transactional_object * xobj, enum tx_object_type type, enum access_mode mode,
						 int *should_sleep, struct transaction **winner){


	struct txobj_thread_list_node *new_node = NULL;

#ifdef CONFIG_TX_KSTM_ABORT_OBJ_ON_ADD
	int rand = 0;	

	current->create_count++;
        
	printk(KERN_INFO "INFO: CONFIG_TX_KSTM_ABORT_OBJ_ON_ADD :\n \
  								  create_count=%d, \
                          transaction_count = %d\n", \
                          current->create_count, current->transaction->count);

#ifdef CONFIG_TX_KSTM_ABORT_OBJ_ON_RANDOM
	
		rand = get_random_int() & 1;
		printk(KERN_INFO "INFO: CONFIG_TX_KSTM_ABORT_OBJ_ON_RANDOM :\n \
                          rand = %d\n", \
                          rand);


#endif /*CONFIG_TX_KSTM_ABORT_OBJ_ON_RANDOM*/

	if(((current->transaction->count+1) == current->create_count) && !rand) {
		current->create_count = 0;
		printk(KERN_INFO "INFO:  !!Aborting\n");
		return NULL;

	}
		printk(KERN_INFO "INFO:  ***********\n");
#endif  /* CONFIG_TX_KSTM_ABORT_OBJ_ON_ADD */

	KSTM_BUG_ON(!winner);

	// Only bother contending if we aren't the writer
	if(xobj->writer != current->transaction)
		*winner = contend_for_xobj(xobj, mode, 0, should_sleep, &new_node);

	return new_node;
}

static struct transaction * copy_tx(struct transaction *tx, struct task_struct *tsk){
	struct transaction *new_tx = alloc_transaction_struct();
	INIT_LIST_HEAD(&new_tx->tasks);
	INIT_LIST_HEAD(&new_tx->orphaned_atomic_ops);
	INIT_LIST_HEAD(&new_tx->orphaned_fsnotify);
	INIT_LIST_HEAD(&new_tx->orphaned_allocs);
	INIT_LIST_HEAD(&new_tx->orphaned_page_allocs);
	INIT_LIST_HEAD(&new_tx->orphaned_page_frees);
	spin_lock_init(&new_tx->lock);
	list_move(&tsk->transaction_entry, &new_tx->tasks);
	atomic_set(&new_tx->task_count, 0);
	atomic_set(&new_tx->ref_count, 1);
	atomic_set(&new_tx->status, atomic_read(&tx->status));
	new_tx->autoretry = tx->autoretry;
	new_tx->timestamp = tx->timestamp;
	new_tx->count = tx->count;
	new_tx->abortWithErr = tx->abortWithErr;

	INIT_SKIPLIST_HEAD_CHEAP(&current->transaction->object_list);
	INIT_SKIPLIST_HEAD_CHEAP(&current->transaction->list_list);
#ifdef CONFIG_TX_KSTM_DORDER
	INIT_LIST_HEAD(&current->transaction->data_writer_list);
#endif

	init_waitqueue_head(&new_tx->losers);
	init_waitqueue_head(&new_tx->siblings);

	return new_tx;
}

/* Consolidate some of the rollback logic to avoid code duplication in
 * commit (abort path) and abort_self */
static inline void rollback_tx_atomic(struct atomic_op_record_buf *buf){
	while(buf->count > 0){
		struct atomic_op_record *rec =
			&buf->recs[--buf->count];
		/* DEP: Only adds are buffered for now */
		/*
		switch(rec->type){
		case ATOMIC_OP_ADD:
		*/
		if(rec->val != 0)
			tx_atomic_sub(rec->val, rec->addr);
			/*
			break;
		default:
			BUG();
		}
			*/
	}
}


#ifdef CONFIG_TX_KSTM_TX_SIGNALS_VERBOSE
#define txsiglog(x) printk(KERN_ERR x)
#else
#define txsiglog(x) 
#endif
/* forward decl */
void replay_signal(struct k_sigreplay * kr);
void undefer_signals(struct task_struct * p);

/* 
 * reset_signals
 * reset signal replay/logging/defer state.
 */
void reset_signals(void) {
#ifdef CONFIG_TX_KSTM_TX_SIGNALS
	txsiglog("resetting signal state\n");
	sigemptyset(&current->sigactions_logged);
	current->sigmasks_logged = 0;
	current->replay_sigcount = 0;
	current->deferred_sigcount = 0;
	current->defer_recvtxsig = 0;
#endif
}

/*
 * set_signal_recv_deferrable
 * indicate whether a transactional receiver of
 * a signal should defer until commit, or consume 
 * the signal and stash a copy for replay on abort.
 */
void set_signal_recv_deferrable(int deferrable) {
#ifdef CONFIG_TX_KSTM_TX_SIGNALS
	current->defer_recvtxsig = deferrable;
#endif
}

/*
 * restore_signals
 * Handle reinstatement of signal state on an abort:
 * 1. If we have changed signal handlers, restore their previous state.
 * 2. If we have changed the block and RT block masks, restore them.
 * 3. If we have consumed any signals transactionally, replay them.
 * 4. If we have deferred the sending of any signals, discard them.
 */
void restore_signals(void) {
#ifdef CONFIG_TX_KSTM_TX_SIGNALS
	/* put signal handlers and block
	 * masks back the way they were. 
	 */
	int i;
	sigset_t * src;
	sigset_t * dst;
	struct k_sigaction * ksrc;
	struct k_sigaction * kdst;
	txsiglog("restore_signals\n");
	for(i=0;i<_NSIG;i++) {
		txsiglog("restoring sigaction\n");
		if(sigtestsetmask(&current->sigactions_logged, sigmask(i+1))) {
			ksrc = &current->old_sigactions[i];
			kdst = &current->sighand->action[i];
			*kdst = *ksrc;
		}
	}
	sigemptyset(&current->sigactions_logged);
	if(current->sigmasks_logged) {
		txsiglog("restoring blocked, real_blocked masks\n");
		src = &current->old_blocked;
		dst = &current->blocked;
		*dst = *src;
		src = &current->old_real_blocked;
		dst = &current->real_blocked;
		*dst = *src;
	}

	/* if we consumed any signals during the transaction, we have
	 * to move them back into the pending list by resending
	 * them--otherwise they will appear to have disappeared
	 * without a trace. Only replay them if we are in non-defer
	 * receive mode.
	 */
	if(!current->defer_recvtxsig) {
		for(i=0; i<current->replay_sigcount; i++) {
			txsiglog("replaying txnlly consumed signal...\n");
			replay_signal(&current->replay_sigs[i]);
		}
		current->replay_sigcount = 0;
	}

	/* if we sent any signals during the transaction, 
	 * they were put on to a defer list. Since we abort here
	 * we need only empty that list by resetting it's count.
	 */
	current->deferred_sigcount = 0;
#endif
}

/* 
 * commit_signals() 
 * Signal, sigaction and sigprocmask clean up.  It's sufficient to
 * clear the logged flags.  Also, if we've consumed any
 * signals transactionally, we no longer need to stash them
 * for replay: truncate the replay list. Caveat: if we've
 * deferred any received signals, we need to move them back to
 * the pending list first.
 */ 
void commit_signals(void) {
#ifdef CONFIG_TX_KSTM_TX_SIGNALS
	int i;
	txsiglog("commit_signals()\n");
	if(current->defer_recvtxsig) 
		for(i=0; i<current->replay_sigcount; i++) 
			replay_signal(&current->replay_sigs[i]);
	
	sigemptyset(&current->sigactions_logged);
	current->sigmasks_logged = 0;
	current->replay_sigcount = 0;
	
        /* If we attempted to send any signals, they were deferred.
	 * We need to go ahead and deliver those signals now. 
	 */
	undefer_signals(current);
	if(current->defer_recvtxsig) {
		txsiglog("completing a defersig tx!\n");
		current->defer_recvtxsig = 0;
	}
#endif
}

/* 
 * Locking discipline (since the vfs discipline is incomplete)
 * 
 *  Lock all bucket locks first
 *  Followed by all blocking locks (inode mutex), ordered by virt. addr.
 *  Followed by dcache_lock (if needed)
 *  Followed by all non-blocking spins (dentry, inodes), ordered by virt. addr
 *
 *  Because list2s are locked after holding the containing object's
 *  lock, and (I believe) we only hold one at a time, we lock all
 *  lists after all objects.  This should be a correct locking discipline.
 *
 */

// Commit or abort this transaction's kernel state.  Returns 0 if success,
// nonzero otherwise
static int endTransactionKernel(struct transaction *t){
	int i;
	int status;
	int commit = 1; // Should we commit our state at the end?
	txobj_thread_list_node_t *item, *n;
	SKIPLIST_HEAD(obj_list);
#ifdef CONFIG_TX_KSTM_DORDER
	LIST_HEAD(data_writer_list);
#endif
	struct task_struct *next_task, *nt;
	struct rcu_head *rcu;

	/* Use this field to coordinate wakeup */
	current->commit = -1;

	if(atomic_dec_and_test(&t->task_count)){

		t->committing_task = current;

		// Adopt orphaned lists
		list_splice_init(&t->orphaned_fsnotify, &current->fs_notify);
		list_splice_init(&t->orphaned_allocs, &current->allocs);
		list_splice_init(&t->orphaned_atomic_ops, &current->atomic_ops);

		
		/* Move the addrset lists onto our local workset list.
		 * Note that we do the list_list first, so that it
		 * ends up at the end.
		 */
		skiplist_splice_init(&t->list_list, &obj_list);
		skiplist_splice_init(&t->object_list, &obj_list);
#ifdef CONFIG_TX_KSTM_DORDER
		list_splice_init(&t->data_writer_list, &data_writer_list);
#endif

		/* Iterate once, getting the blocking locks on objects */
		skiplist_for_each_entry(item, &obj_list, workset_list){
			if(item->lock)
				(item->lock)(item, 1);
		}

		/* Get the transaction lock -- used for mutex on contention */
		spin_lock(&t->lock);


		/* Iterate again, getting the non-blocking locks */
		skiplist_for_each_entry(item, &obj_list, workset_list){
			if(item->lock)
				(item->lock)(item, 0);
			LOCK_XOBJ(item->tx_obj);
		}

		
		// Check our status word to make sure that we aren't aborted one
		// more time.  After this point, we can't be aborted anymore
		status = atomic_read(&t->status);
		if(status == TX_ABORTED || status == TX_ABORTING){
			/* We can get to aborting in multi-proc tx*/
			commit = 0;
			aborts++;

			atomic_set(&current->transaction->status, TX_ABORTING);
		} else if(status == TX_ACTIVE){
			commits++;

#ifdef CONFIG_TX_USER_HTM		
			if(0 != XEND_USER()){
				atomic_set(&current->transaction->status, TX_ABORTING);
			} else {
				atomic_set(&current->transaction->status, TX_COMMITTING);
			}
#else
			atomic_set(&current->transaction->status, TX_COMMITTING);
#endif
		} else {
			printk(KERN_ERR "Invalid status %d\n", status);
			BUG();
		}

		/* Release transaction lock */
		spin_unlock(&t->lock);


#ifdef CONFIG_TX_KSTM_ASSERTIONS	
		/* Do the validation */
		if(commit){
			skiplist_for_each_entry(item, &obj_list, workset_list){
				// We need to do this early because of lists
				// May not have a validate method
				// May want to do this after all items are locked to minimize aborts
				if(item->validate)
					(item->validate)(item);
			}
		}
#endif

		/* Commit or abort the state */
		skiplist_for_each_entry(item, &obj_list, workset_list){
			/* Remove from global lists */
			/* XXX: Replace with something sensible */
			remove_xnode_reference(t, item->tx_obj);
			if(commit){
				if(item->commit)
					(item->commit)(item);
			} else { 
				if(item->abort)
					(item->abort)(item);
			}
		
			/* Drop the non-blocking locks asap */		
			UNLOCK_XOBJ(item->tx_obj);
			if(item->unlock)
				(item->unlock)(item, 0);
		}
		
		/* Start any journalling */
		if(commit)
			BUG_ON(start_jbd_tx(&current->transaction->jbd, commit));

#ifdef CONFIG_TX_KSTM_DORDER
		/* Commit data writes in order, but that is only important when
		 * we are actually committing */
		if(commit) {
			list_for_each_entry(item, &data_writer_list, data_writer_list) {
				BUG_ON(item->unlock != unlock_inode_data_rw);
				item->unlock(item, 1);
				item->release(item, 0);
				skiplist_del(&item->workset_list);
				free_tx_thread_list_node(item);
			}
		}
#endif

		/* Release the blocking locks */
		skiplist_for_each_entry(item, &obj_list, workset_list){
			if(item->unlock)
				(item->unlock)(item, 1);
		}

		/* Stop any journalling */
		if(commit)
			BUG_ON(stop_jbd_tx(&current->transaction->jbd, commit));

		/* Must rollback the bitops early */
		if(!commit){
			struct atomic_op_record_buf *buf, *n;
			list_for_each_entry(next_task, &t->tasks, transaction_entry){
				list_for_each_entry_safe(buf, n, &next_task->atomic_ops, list){
					rollback_tx_atomic(buf);
					list_del(&buf->list);
					free_atomic_buf(buf);
				}
			}
		} else {
			struct atomic_op_record_buf *buf, *n;
			list_for_each_entry(next_task, &t->tasks, transaction_entry){
				list_for_each_entry_safe(buf, n, &next_task->atomic_ops, list){
					list_del(&buf->list);
					free_atomic_buf(buf);
				}
				/* Do all resultant fsnotify's */
				deliver_fs_notify_events(&next_task->fs_notify);
			}
		}

		//Free up the tx resources
		skiplist_for_each_entry_safe(item, n, &obj_list, workset_list){
			if(item->release)
				(item->release)(item, 0);
			skiplist_del(&item->workset_list);
			free_tx_thread_list_node(item);
		}

		// Handle orphaned allocations
		if(commit){
			struct page_record_buf *buf, *n;
			list_for_each_entry_safe(buf, n, &t->orphaned_page_allocs, list){
				list_del(&buf->list);
				free_txpg_buf(buf);
			}
			list_for_each_entry_safe(buf, n, &t->orphaned_page_frees, list){
				for(i = 0; i < buf->count; i++){
					BUG_ON(page_count(buf->pages[i]) != 1);
					page_cache_release(buf->pages[i]);
				}
				list_del(&buf->list);
				free_txpg_buf(buf);
			}
		} else {
			struct page_record_buf *buf, *n;
			list_for_each_entry_safe(buf, n, &t->orphaned_page_allocs, list){
				for(i = 0; i < buf->count; i++){
					BUG_ON(page_count(buf->pages[i]) != 1);
					page_cache_release(buf->pages[i]);
				}
				list_del(&buf->list);
				free_txpg_buf(buf);
			}
			list_for_each_entry_safe(buf, n, &t->orphaned_page_frees, list){
				list_del(&buf->list);
				free_txpg_buf(buf);
			}
		}

		// Handle anonymous pages, shouldn't need a lock
		list_for_each_entry_safe(next_task, nt, &t->tasks, transaction_entry){

			// Set each thread's commit entry
			next_task->commit = commit;

			if(!commit){
				struct fsnotify_event_buf *buf, *n;
				list_for_each_entry_safe(buf, n, &next_task->fs_notify, list){
					list_del(&buf->list);
					free_fsnotify_buf(buf);
				}
			}

			if(!list_empty(&next_task->tx_vmas)){
				struct vm_area_struct *vma, *n;
									
				if(commit){
					/* XXX To-do: Merge vmas - for now just fragment */
					list_for_each_entry_safe(vma, n, &next_task->tx_vmas, tx_cache){
						list_del_init(&vma->tx_cache);
						init_vma_tx(vma);
					}
				} else {
					list_for_each_entry_safe(vma, n, &next_task->tx_vmas, tx_cache){
						list_del_init(&vma->tx_cache);
						init_vma_tx(vma); // KS to myself: is this necessaary?
						do_munmap(vma->vm_mm, vma->vm_start, vma->vm_end - vma->vm_start);
					}
				}
			}
			if(!list_empty(&next_task->tx_unmapped_vmas)){
				if(commit){
					struct vm_area_struct *vma, *n;
					list_for_each_entry_safe(vma, n, &next_task->tx_unmapped_vmas, tx_cache){
						list_del_init(&vma->tx_cache);

						// the following is from remove_vma() in mmap.c
						if(vma->vm_file)
							fput(vma->vm_file);
						mpol_free(vma_policy(vma));

						kmem_cache_free(vm_area_cachep, vma);
					}
				}
				else{
					struct vm_area_struct *vma, *n;
					list_for_each_entry_safe(vma, n, &next_task->tx_unmapped_vmas, tx_cache){
						init_vma_tx(vma);
						list_del_init(&vma->tx_cache);
					}
				}
			}
		
			// After we have committed everything else, free up any transactionally freed pages
			if(commit) {
				/*update the bitmaps*/
				/* XXX: I don't know that we really want to do this anymore */
				//commit_all_bitops(NULL);


				struct page_record_buf *buf, *n;
				list_for_each_entry_safe(buf, n, &next_task->tx_page_allocs, list){
					list_del(&buf->list);
					free_txpg_buf(buf);
				}
				list_for_each_entry_safe(buf, n, &next_task->tx_page_frees, list){
					for(i = 0; i < buf->count; i++){
						BUG_ON(page_count(buf->pages[i]) != 1);
						page_cache_release(buf->pages[i]);
					}
					list_del(&buf->list);
					free_txpg_buf(buf);
				}


				/* invalidate checkpointed f-deez */
				next_task->files_checkpoint_current = 0;
			
				//deallocate fd's from ftd etc
				{
					struct alloc_record_buf *buf, *n;
					list_for_each_entry_safe(buf, n, &next_task->allocs, list){
						list_del(&buf->list);
						free_alloc_buf(buf);
					}
				}

			} else {
				
				/* rollback the bitmaps - XXX: this will currently
				 * generate defered disk writes, a more efficient
				 * design is forthcoming 
				 */
				/* XXX: I don't know that we really want to do this anymore */
				//handle = ext3_journal_current_handle();
				//rollback_all_bitops(handle);
				

				struct page_record_buf *buf, *n;
				list_for_each_entry_safe(buf, n, &next_task->tx_page_allocs, list){
					for(i = 0; i < buf->count; i++){
						BUG_ON(page_count(buf->pages[i]) != 1);
						page_cache_release(buf->pages[i]);
					}
					list_del(&buf->list);
					free_txpg_buf(buf);
				}
				list_for_each_entry_safe(buf, n, &next_task->tx_page_frees, list){
					list_del(&buf->list);
					free_txpg_buf(buf);
				}

				/* Free up transactional allocs too */
				{
					struct alloc_record_buf *buf, *n;
					list_for_each_entry_safe(buf, n, &next_task->allocs, list){
						while(buf->count > 0){
							struct alloc_record *rec = &buf->recs[--buf->count];
							if(rec->buf == NULL)
								continue;
				
							if(rec->cache)
								kmem_cache_free(rec->cache, rec->buf);
							else 
								kfree(rec->buf);
						}
						list_del(&buf->list);
						free_alloc_buf(buf);
					}
				}

				/* And roll back the transactional f-deez */
				rollback_files_checkpoint(next_task);
			}
			

			/* Just always copy the transaction for now.  We may need more sophisticated semantics later*/
			if(unlikely(next_task->xforked))
				next_task->transaction = copy_tx(next_task->transaction, next_task);

		}

		/* And free any deferred frees */
		while((rcu = t->deferred_frees)){
			t->deferred_frees = rcu->next;
			call_rcu(rcu, rcu->func);
		}


		// Make sure we really freed everything
		KSTM_BUG_ON(!skiplist_empty(&t->object_list));
		KSTM_BUG_ON(!skiplist_empty(&t->list_list));

		/* Signal any waiting tasks in the tx */
		wake_up_all(&t->siblings);

	} else {
		/* Wait for the committing thread to do its thing */
		wait_event_interruptible(t->siblings, current->commit > -1);
		
		commit = current->commit;
	}

	// Make sure the references to the transaction struct get gc-ed properly
	if(unlikely(current->xforked)){
		spin_lock(&t->lock);
		list_del(&current->transaction_entry);
		spin_unlock(&t->lock);
		if(atomic_dec_and_test(&t->ref_count)){
			KSTM_BUG_ON(atomic_read(&t->status) != TX_INACTIVE);
			KSTM_BUG_ON(waitqueue_active(&t->losers));
			KSTM_BUG_ON(waitqueue_active(&t->siblings));

			free_transaction_struct(t);
		}
	}

	//commit or abort task_struct fields
	if (current->cp != NULL) {
		if (commit) {
			tx_commit_signal(current);
			tx_commit_fs(current);
			//gid info commit
			if (current->cp->fsgid != current->fsgid)
				key_fsgid_changed(current);
			
			if (current->cp->gid != current->gid ||
			    current->cp->egid != current->egid ||
			    current->cp->sgid != current->sgid ||
			    current->cp->fsgid != current->fsgid)
				proc_id_connector(current, PROC_EVENT_GID);
			//uid info commit
			if (current->cp->fsuid != current->fsuid)
				key_fsuid_changed(current);
			
			if (current->cp->uid != current->uid ||
			    current->cp->euid != current->euid ||
			    current->cp->suid != current->suid ||
			    current->cp->fsuid != current->fsuid)
				proc_id_connector(current, PROC_EVENT_UID);
			
		} else {
			//abort! abort!
			//printk(KERN_ERR "Rolling back task_struct state!\n");
			tx_rollback_signal(current);
			tx_rollback_fs(current);
			memcpy(&current->uid, current->cp,
			       sizeof(struct xstruct));
		}
		kmem_cache_free(cp_cachep, current->cp);
		current->cp = NULL;
	}

	if(commit) 
		commit_signals();
	else 
		restore_signals();

	
	// Exit
	if(unlikely(current->xforked && !commit)){
		current->transactional = 0;
		atomic_set(&current->transaction->status, TX_INACTIVE);
		do_exit(current->exit_code);
	} else {
		if(current->pending_exit){
			if(commit){
				current->transactional = 0;
				atomic_set(&current->transaction->status, TX_INACTIVE);
				do_exit(current->exit_code);
			} else 
				current->pending_exit = 0;
		}
		current->xforked = 0;
	} 

	atomic_inc(&current->transaction->task_count);

	return 1 - commit;
}
	
// Called with xobj->lock held
void remove_reader(struct transaction *t, struct transactional_object * xobj){
	struct txobj_thread_list_node *tx_node, *n;
	int count = 0;

	list_for_each_entry_safe(tx_node, n, &xobj->readers, object_list){

		if(tx_node->tx == t){	
			list_del_init(&tx_node->object_list);
			count++;
		}
	}

#ifdef CONFIG_TX_KSTM_ASSERTIONS
	if(count > 1){
		printk(KERN_ERR "Surprisingly, we have more than one reader (%d)!\n", count );
		OSA_MAGIC( OSA_BREAKSIM );
	}
#endif
}

// Must hold object locks and xobj->lock
void remove_xnode_reference(struct transaction * t, struct transactional_object *xobj){

	KSTM_BUG_ON(xobj->writer == (void *) 0x6b6b6b6b);

	if(xobj->writer == t){
		xobj->writer = NULL;
	}
	remove_reader(t, xobj);
}

void debug_dump_workset(struct transaction *t){
	struct txobj_thread_list_node *xnode;

	printk(KERN_INFO "Committing Tx - workset:\n");
	skiplist_for_each_entry(xnode, &t->object_list, workset_list){

		if(xnode->type == TYPE_INODE){
			struct inode * inode;
			inode = (struct inode *)xnode->orig_obj;
			
			printk(KERN_INFO "\ninode %lu, mode %d\n", 
			       inode->i_contents->i_ino, xnode->rw);
		}
	}

	/* If we use this for anything, we should expand to include list2's */
	printk(KERN_INFO "End Tx workset.\n");
}

#endif //CONFIG_KSTM

////////////////////////////////////////////////////
/* User-level commit/abort functions */

#ifdef CONFIG_TX_USER_PTM

int commitTransactionUser(struct transaction *t){
	// Free the checkpointed mm
	commit_checkpoint(current);

  return 0;
}

int abortTransactionUser(struct transaction *t){
	// Restore the COW checkpoint struct task_struct *next_task;
	if(current->transactional && !current->usertm)
		rollback_checkpoint(current);
	
	// This function really just dumps the checkpoint
	if(!current->transaction->autoretry)
		commit_checkpoint(current);
	
  return 0;
}


#elif defined CONFIG_TX_USER_HTM

// Do the commit/abort during kernel commit/abort
int commitTransactionUser(struct transaction *t){
  return 0;
}

int abortTransactionUser(struct transaction *t){
	XABORT_USER();
	return 0;
}

#elif defined CONFIG_TX_USER_NOTM

// Do nothing
int commitTransactionUser(struct transaction *t){
  return 0;
}

int abortTransactionUser(struct transaction *t){
	return 0;
}


#else 
#error Unknown User-mode tx support option.  This should not happen.
#endif

/* End User-level commit/abort functions */
///////////////////////////////////////////////////

// Generalized commit function - calls implementation-specific
// functions.  Some of these steps may be nop's depending on the TM
// mechanism.
int endTransaction(struct transaction *t){

	// Assume user state is pre-committed at this point (either
	// this is a single system call and there isn't any, or we are
	// an xend system call and this is the precondition).
	int rv = 0;
#ifdef CONFIG_TX_KSTM_PROF
	unsigned long long cycles, a;
	rdtscll(cycles);
#endif
	rv = endTransactionKernel(t);
	//If the transaction failed, return the code for commitTransaction's failure
	if(rv) {
		// Do roll back the htm if this fails
#ifndef CONFIG_TX_USER_HTM
		if(!current->usertm)
#endif
		{
			abortTransactionUser(t);
		}
	} else {
		if(!current->usertm)
			commitTransactionUser(t);
	}
#ifdef CONFIG_TX_KSTM_PROF
	rdtscll(a);
	commitCycles += (a - cycles);
#endif	
	return rv;
}

#endif // CONFIG_TX

#ifdef CONFIG_TX_SYSCALLS

void common_tx_reset(void){

	INIT_SKIPLIST_HEAD_CHEAP(&current->transaction->object_list);
	INIT_SKIPLIST_HEAD_CHEAP(&current->transaction->list_list);

	INIT_LIST_HEAD(&current->tx_page_allocs);
	INIT_LIST_HEAD(&current->tx_page_frees);
	INIT_LIST_HEAD(&current->transaction->orphaned_page_allocs);
	INIT_LIST_HEAD(&current->transaction->orphaned_page_frees);
		
	current->transaction->deferred_frees = NULL;

	current->nr_locks = 0;

	reset_signals();
	
	atomic_set(&current->transaction->status, TX_ACTIVE);

	INIT_LIST_HEAD(&current->tx_vmas);
	INIT_LIST_HEAD(&current->tx_unmapped_vmas);
	INIT_LIST_HEAD(&current->transaction->orphaned_atomic_ops);
	INIT_LIST_HEAD(&current->transaction->orphaned_fsnotify);
	INIT_LIST_HEAD(&current->transaction->orphaned_allocs);

	INIT_LIST_HEAD(&current->allocs);
	INIT_LIST_HEAD(&current->fs_notify);
	INIT_LIST_HEAD(&current->atomic_ops);
}

static inline void terminate_transaction(void){
	// Mark the task as non transactional
	current->transactional = 0;
	current->usertm = 0;
	current->transaction->count = 0;
	atomic_set(&current->transaction->status, TX_INACTIVE);
	atomic_dec(&tx_count);
	current->files_checkpoint_current = 0;
	
	wake_up_all(&current->transaction->losers);
}

void early_release(struct transactional_object *xobj, int commit){
	txobj_thread_list_node_t * item;
	int found = 0;

	LOCK_XOBJ(xobj);
	/* No safe needed, as we exit after the first deletion */
	list_for_each_entry(item, &xobj->readers, object_list){
		KSTM_BUG_ON(item->tx_obj != xobj);
		if(item->tx == current->transaction){
			found = 1;
			break;
		}

	}
	UNLOCK_XOBJ(xobj);
		
	if(!found)
		return;


	if(item->lock){
		(item->lock)(item, 1);
		(item->lock)(item, 0);
	}
	LOCK_XOBJ(xobj);

	
#ifdef CONFIG_TX_KSTM_ASSERTIONS	
	if(item->validate)
		(item->validate)(item);
#endif
	if(commit){
		if(item->commit)
			(item->commit)(item);
	} else { 
		if(item->abort)
			(item->abort)(item);
	}
		
	remove_xnode_reference(current->transaction, item->tx_obj);
			
	/* Drop the non-blocking locks asap */		
	UNLOCK_XOBJ(item->tx_obj);
	if(item->unlock){
		(item->unlock)(item, 0);
		(item->unlock)(item, 1);
	}
			
	if(item->release)
		(item->release)(item, 1);

	WORKSET_LOCK(current->transaction);
	skiplist_del(&item->workset_list);
	WORKSET_UNLOCK(current->transaction);
	free_tx_thread_list_node(item);

	return;
}

/* Jump the stack pointers back to the beginning of the tx */
void abort_self(struct transaction *winner, int cleanup_only){

	/* 
	 * clear out our tx state
	 */
	int i;
	//handle_t *handle;
	struct transaction *t = current->transaction;

	aborts++;

#ifdef CONFIG_TX_KSTM_DEBUG_STALL_ON_CONFLICT
	OSA_MAGIC(OSA_BREAKSIM);
#endif

	/* DEBUG
	if(current->transactional && current->usertm){
		OSA_MAGIC(OSA_BREAKSIM);
		printk(KERN_ERR "Aborting myself (%d)\n", current->pid);
	}
	*/

	/* Set ourselves to aborting */
	atomic_set(&current->transaction->status, TX_ABORTING);

	/* Release all tx locks first.  Hope reverse ordering is safe  */
	while(current->nr_locks > 0){
		struct lock_record *rec = &current->locks[current->nr_locks - 1];
		if (rec->lock != NULL) {
			switch(rec->type){
			case READ_LOCK:
				read_unlock((rwlock_t *)rec->lock);
				break;
			case WRITE_LOCK:
				write_unlock((rwlock_t *)rec->lock);
				break;
			case SPIN_LOCK:
				spin_unlock((spinlock_t *)rec->lock);
				break;
			case MUTEX:
				mutex_unlock((struct mutex *) rec->lock);
				break;
			case READ_SEM:
				up_read((struct rw_semaphore *) rec->lock);
				break;
			case WRITE_SEM:
				up_write((struct rw_semaphore *) rec->lock);
				break;
			default:
				BUG();
			}
		}
		current->nr_locks--;
	}

	/* Use this field to coordinate wakeup */
	current->commit = -1;

	if(atomic_dec_and_test(&t->task_count)){
		struct task_struct *next_task, *nt;
		struct atomic_op_record_buf *buf, *n;
		struct rcu_head *rcu;

		list_splice_init(&t->orphaned_fsnotify, &current->fs_notify);
		list_splice_init(&t->orphaned_allocs, &current->allocs);
		list_splice_init(&t->orphaned_atomic_ops, &current->atomic_ops);


		/* Must rollback the bitops early */
		list_for_each_entry(next_task, &t->tasks, transaction_entry){
			list_for_each_entry_safe(buf, n, &next_task->atomic_ops, list){
				rollback_tx_atomic(buf);
				list_del(&buf->list);
				free_atomic_buf(buf);
			}
		}

		// Release all thread local transactional objects
		{
			struct txobj_thread_list_node *n, *xnode;
			
			skiplist_splice_init(&t->list_list, &t->object_list);
			skiplist_for_each_entry_safe(xnode, n, &t->object_list, workset_list){
					
				OSA_UNPROTECT_ADDR(xnode->orig_obj);
					
				if(xnode->abort)
					(xnode->abort)(xnode);
					
				// Lock the object
				// XXX: Coalesce into 1 fn call
				if(xnode->lock){
					(xnode->lock)(xnode, 1);
					(xnode->lock)(xnode, 0);
				}
				LOCK_XOBJ(xnode->tx_obj);
					
				remove_xnode_reference(t, xnode->tx_obj);
					
				//Release object lock
				UNLOCK_XOBJ(xnode->tx_obj);
				if(xnode->unlock){
					(xnode->unlock)(xnode, 0);
					(xnode->unlock)(xnode, 1);
				}
					
				//del xnode from the list
				skiplist_del(&xnode->workset_list);
				
				// Release the shadow copy
				if(xnode->release)
					(xnode->release)(xnode, 0);
				free_tx_thread_list_node(xnode);
			}
		}

		{
			struct page_record_buf *buf, *n;
			list_for_each_entry_safe(buf, n, &t->orphaned_page_allocs, list){
				for(i = 0; i < buf->count; i++){
					BUG_ON(page_count(buf->pages[i]) != 1);
					page_cache_release(buf->pages[i]);
				}
				list_del(&buf->list);
				free_txpg_buf(buf);
			}
			list_for_each_entry_safe(buf, n, &t->orphaned_page_frees, list){
				list_del(&buf->list);
				free_txpg_buf(buf);
			}
		}			

		list_for_each_entry_safe(next_task, nt, &t->tasks, transaction_entry){
			
			// Set each thread's commit entry
			next_task->commit = 0;

			// After we have aborted everything else, free up any transactionally alloc'd pages
			{
				struct page_record_buf *buf, *n;
				list_for_each_entry_safe(buf, n, &next_task->tx_page_allocs, list){
					for(i = 0; i < buf->count; i++){
						BUG_ON(page_count(buf->pages[i]) != 1);
						page_cache_release(buf->pages[i]);
					}
					list_del(&buf->list);
					free_txpg_buf(buf);
				}
				list_for_each_entry_safe(buf, n, &next_task->tx_page_frees, list){
					list_del(&buf->list);
					free_txpg_buf(buf);
				}
			}			


			/* Free up transactional allocs too */
			{
				struct alloc_record_buf *buf, *n;
				list_for_each_entry_safe(buf, n, &next_task->allocs, list){
					while(buf->count > 0){
						struct alloc_record *rec = &buf->recs[--buf->count];
						
						if(rec->buf == NULL)
							continue;
						
						if(rec->cache)
							kmem_cache_free(rec->cache, rec->buf);
						else 
							kfree(rec->buf);
					}
					list_del(&buf->list);
					free_alloc_buf(buf);
				}
			}
		
			/* Free tx fsnotifies */
			{
				struct fsnotify_event_buf *buf, *n;
				list_for_each_entry_safe(buf, n, &next_task->fs_notify, list){
					list_del(&buf->list);
					free_fsnotify_buf(buf);
				}
			}
			
			/* And transactional f-deez */
			rollback_files_checkpoint(next_task);
			
			if(unlikely(next_task->xforked))
				next_task->transaction = copy_tx(next_task->transaction, next_task);

			
		}

		/* And free any deferred frees */
		while((rcu = t->deferred_frees)){
			t->deferred_frees = rcu->next;
			call_rcu(rcu, rcu->func);
		}

		// Make sure we really freed everything
		KSTM_BUG_ON(!skiplist_empty(&t->object_list));
		KSTM_BUG_ON(!skiplist_empty(&t->list_list));

		/* Signal any waiting tasks in the tx */
		wake_up_all(&t->siblings);

	} else {
		/* Attempt to die early */
		if(current->xforked){
			current->transactional = 0;
			current->transaction = &exit_placeholder;
			do_exit(current->exit_code);
		}

		/* Wait for the committing thread to do its thing */
		wait_event_interruptible(t->siblings, current->commit > -1);
	}	

	//roll back task_struct state
	if (current->cp != NULL) {
		//abort! abort!
		//printk(KERN_ERR "Rolling back task_struct state!\n");
		tx_rollback_signal(current);
		tx_rollback_fs(current);
		memcpy(&current->uid, current->cp,
		       sizeof(struct xstruct));
		kmem_cache_free(cp_cachep, current->cp);
		current->cp = NULL;
		/*
		printk(KERN_ERR "after rollback: uid=%d fsuid=%d gid=%d fsgid=%d fsptr=%x robustptr=%x sigptr=%x\n",
		       current->uid, current->fsuid, 
		       current->gid, current->fsgid, 
		       current->fs, current->robust_list,
		       current->signal);
		*/
		
	}

	restore_signals();


	if(unlikely(current->xforked)){
		current->transactional = 0;
		atomic_set(&current->transaction->status, TX_INACTIVE);
		do_exit(current->exit_code);
	} else {
		if(current->pending_exit)
			current->pending_exit = 0;
	}
	atomic_inc(&current->transaction->task_count);		
	
	if(!current->usertm){
		/* If we are in a user tx, rollback the address space so that
		 * we have a good home to return to.  Must be done before the
		 * reset.
		 */
		abortTransactionUser(current->transaction);
		common_tx_reset();
	}

	stats_abort_tx(current->eax);
	current->transaction->count++;
	
	/* Get to the bottom of a dcache_lock lockup */
	KSTM_BUG_ON(dcache_lock.owner == current);

	/* Allow exit to use this function without the crazy stack jumping*/
	if(cleanup_only){
		atomic_set(&current->transaction->status, TX_INACTIVE);
		current->transactional = 0;
		/* And let the losers run again */
		wake_up_all(&current->transaction->losers);
		return;
	}

	/* Give someone else a shot.  If we have a specific
	 * transaction to wait on, go to the wait queue.  If
	 * not, just yield the cpu.
	 */
	if(winner) 
		wait_on_tx(winner);
	else 
		schedule();

	/* Now warp up the stack */
	*current->regsp = current->regs_checkpoint;
	/* Make sure xbegin terminates properly */
	if(current->usertm){
		*current->eaxp = __NR_xbogus;
		current->xbogus_return_code = -ETXABORT;
	} else{
		if(current->transaction->autoretry)
			atomic_set(&current->transaction->status, TX_ACTIVE);
		else
			current->transaction->abortWithErr = 1;
		*current->eaxp = current->eax;

		// Including floating point/mmx if used
		if(current->thread_info_status & TS_USEDFPU){
			OSA_MAGIC(OSA_BREAKSIM);
			current->thread = current->thread_checkpoint;
#ifndef CONFIG_X86_64
			restore_fpu(current);
#else
			restore_fpu_checking(&(current->thread.i387.fxsave));
#endif
		}
	}

	/* Learning the hard way: Every time we dick with registers to
	 * do an abort, we must use iret.  Otherwise the user process
	 * actually expects to get live register values back from the
	 * kernel via calling conventions.
	 */
	set_thread_flag(TIF_IRET);

	//printk(KERN_ERR "Return ebp == %x, return esp = %x\n", current->return_ebp, current->return_esp);

	/* Then update the eip and ebp values */
	jump_out_of_stack(); // doesn't return
}

void checkWhitelist(unsigned long *syscall){
	switch(*syscall){
		/* __NR_restart_syscall - does this do anything? */
	case __NR_exit:
	case __NR_fork:
	case __NR_read:
	case __NR_write:
	case __NR_open:
	case __NR_close:
		/* __NR_waitpid */
	case __NR_creat:
	case __NR_link:
	case __NR_unlink:
		/* __NR_execve */
	case __NR_chdir: /* all paths transactionalized */
	case __NR_time: /* all paths transactionalized */
	case __NR_mknod: /* mknod doesn't do anything special except set the rdev field */
	case __NR_chmod:
	case __NR_lchown:
#ifdef CONFIG_X86_32
	case __NR_oldstat: /* all paths transactionalized */
#endif
	case __NR_lseek: 
	case __NR_getpid:  /* all paths transactionalized */
		/* __NR_mount - not touching that */
		/* __NR_umount - not touching that */
		 /* all get/set *id paths transactionalized */
	case __NR_setgid: /* (16-bit) */
	case __NR_getgid:
	case __NR_getegid:
	case __NR_getresgid:
	case __NR_setresgid:
	case __NR_setregid:
	case __NR_setfsgid:
	case __NR_setuid:
	case __NR_getuid:
	case __NR_geteuid:
	case __NR_getresuid:
	case __NR_setresuid:
	case __NR_setreuid:
	case __NR_setfsuid:
#ifdef CONFIG_X86_32
	case __NR_setgid32:    /* (32-bit) */
	case __NR_getgid32:
	case __NR_getegid32:
	case __NR_getresgid32:
	case __NR_setresgid32:
	case __NR_setregid32:
	case __NR_setfsgid32:
	case __NR_setuid32:
	case __NR_getuid32:
	case __NR_geteuid32:
	case __NR_getresuid32:
	case __NR_setresuid32:
	case __NR_setreuid32:
	case __NR_setfsuid32:
		/* __NR_stime */
		/* __NR_ptrace */
		/* __NR_alarm */
	case __NR_oldfstat:  /* all paths transactionalized */
#endif
		/* __NR_pause */
	case  __NR_utime: /* all paths transactionalized */
	case __NR_access :
		/* __NR_nice */
		/* __NR_sync */
		/* __NR_kill */
	case __NR_rename:
	case __NR_mkdir:
	case __NR_rmdir:
	case __NR_dup:
	case __NR_pipe:
		/* __NR_times */
		/* __NR_brk - might want this */
		/* __NR_signal */
		/* __NR_acct */
		/* __NR_umount2 */
		/* __NR_lock - might want this? */
		/* ioctl:
		 * supports FIOCLEX, FIONCLEX, FIONBIO, possibly FIOASYNC,
		 *          FIOQSIZE, and *drumroll* TCGETS!
		 */
	case __NR_ioctl:
		/* fcntl: only some paths transactionalized */
		/* transactionalized: GETFD SETFD GETFL SETFL GETLK GETOWN
		 *                    GETSIG GETLEASE DUPFD
		 * unsupported      : SETLK SETLKW SETOWN SETSIG
		 *                    SETLEASE NOTIFY
		 */
	case __NR_fcntl:
		/* __NR_setpgid */
#ifdef CONFIG_X86_32
	case __NR_oldolduname:
#endif
	case __NR_umask:  /* all paths transactionalized */
	case __NR_chroot: /* all paths transactionalized */
		/* __NR_ustat - should be easy if we need it, but needs checking */
	case __NR_dup2:
	case __NR_getppid:
	case __NR_getpgrp:
		/* __NR_setsid*/
		/* __NR_sigaction, sgetmask, ssetmask */
		/* __NR_sigsuspend, sigpending */
		/* __NR_sethostname, getrusage */
		// case __NR_getrlimit: // dP: Temporarily taking this out until further investigation
	case __NR_setrlimit:
		/* get/set time of day */
		/* get/set groups16 */
		/* __NR_select, __NR__newselect */
	case __NR_symlink:
#ifdef CONFIG_X86_32
	case __NR_oldlstat:
#endif
	case __NR_readlink:
		/* __NR_uselib */
		/* __NR_swapon */
		/* __NR_reboot - never */
#ifdef CONFIG_X86_32
	case __NR_readdir:
#endif
		/* __NR_mmap, munmap */
	case __NR_truncate: /* Limited support, BUG's */
	case __NR_ftruncate:
	case __NR_fchmod:
	case __NR_fchown:
		/* get/set priority */
		/* statfs: completely transactionalized */
	case __NR_statfs:
	case __NR_fstatfs:
#ifdef CONFIG_X86_32
	case __NR_statfs64:
	case __NR_fstatfs64:
#endif
		/* ioperm */
		/* socketcall, syslog */
		/* get/set titimer */
	case __NR_stat:  /* all paths transactionalized */
	case __NR_lstat: /* all paths transactionalized */
	case __NR_fstat: /* all paths transactionalized */
#ifdef CONFIG_X86_32
	case __NR_olduname:
#endif
		/* iopl, vhangup, vm86old */
		/* wait */
		/* swapoff */
		/* sysinfo - probably ok */
		/* __NR_ipc */
		/*  msync - could be trivial */
	case __NR_fsync:
		/* sigreturn */
	case __NR_clone:
		/* setdomain, modify_ldt */
	case __NR_uname:
		/* adjtimex */
		/* mprotect */
		/* sigprocmask */
		/* init/delete module */
		/* quotaactl */
	case __NR_getpgid:
	case __NR_fchdir: /* all paths transactionalized */
		/* bdflush */
		/* sysfs */
		/* personality */
#ifdef CONFIG_X86_32
	case __NR__llseek: /* all paths transactionalized */
#endif
	case __NR_getdents:
		/* flock */
	case __NR_readv:
	case __NR_writev:
		/* getsid */
	case __NR_fdatasync:
		/* sysctl */
		/* mlock/munlock, mlockall, munlockall */
		/* NR_sched* */
	case __NR_nanosleep:
		/* mremap */
		/* prctl */
		/* rt_sig* */
	case __NR_pread64:
	case __NR_pwrite64:
	case __NR_chown:
	case __NR_getcwd: /* all paths transactionalized */
		/* cap get/set */
		/* sigaltstack */
		/* sendfile, sendfile64 */
	case __NR_vfork:
#ifdef CONFIG_X86_32
	case __NR_ugetrlimit:
	case __NR_mmap2: /* ANON only */
	case __NR_munmap:
	case __NR_truncate64:
	case __NR_ftruncate64:
	case __NR_stat64: 
	case __NR_lstat64:		
	case __NR_fstat64:		
	case __NR_lchown32:
	case __NR_fchown32:
	case __NR_chown32:
#elif defined (CONFIG_X86_64)
	case __NR_getrlimit:
	case __NR_mmap:
	case __NR_munmap:
#endif
		/* pivot_root */
		/* mincore, madvise, madvise1 */
	case __NR_getdents64:
#ifdef CONFIG_X86_32
	case __NR_fcntl64: /* see FCNTL comment above */
#endif
	case __NR_gettid:
		/* readahead */
		/* xattr* */
		/* tkill */
		/* futex */
		/* sched_*affinity */
		/* get/set thread area - Chris */
		/* io_* */
		/* fadvise64, fadvise64_64 */
		/* __NR_exit_group */
		/* epoll* */
		/* remap file pages */
		/* set_tid_address  - Chris */
		/* timer_* */
	case __NR_clock_gettime:
		/* what about settime, getres */
	case __NR_clock_nanosleep:
		/* tgkill */
	case __NR_utimes:
		/* mbind */
		/* mq_* */
		/* kexec_load */
		/* waitid */
		/* add_key, request_key, keyctl*/
		/* ioprio* */
		/* inotify* */
		/* migrate_pages */
	case __NR_openat:		
	case __NR_mkdirat:		
	case __NR_mknodat:		
	case __NR_fchownat:		
	case __NR_futimesat:
#ifdef CONFIG_X86_32
	case __NR_fstatat64:
#elif defined (CONFIG_X86_64)
	case __NR_newfstatat:
#endif
	case __NR_unlinkat:		
	case __NR_renameat:		
	case __NR_linkat:		
	case __NR_symlinkat:		
	case __NR_readlinkat:		
	case __NR_fchmodat:		
	case __NR_faccessat :
		/* pselect6, ppoll */
		/* unshare */
       /* get_robust_limit is tricky cuz it can access other pid's lists */
	case __NR_get_robust_list: /* all paths transactionalized */
	case __NR_set_robust_list: /* all paths transactionalized */
		/* splice, vmsplice */
		/* sync_file_range */
		/* tee */
		/* move_pages */
#ifdef CONFIG_X86_32
	case __NR_getcpu:
#elif defined (CONFIG_X86_64)
		/* getcpu is a vsyscall in x86_64 */
#endif
		/* epoll_wait */
	case __NR_utimensat:
		/* signalfd */
		/* timerfd */
		/* eventfd */
	case __NR_xbegin :
	case __NR_xend :
	case __NR_xabort:
	case __NR_rt_sigaction:
	case __NR_rt_sigprocmask:

		break;
		// supported only for Xforked tasks
	case __NR_execve:
	case __NR_brk:
		if(current->xforked)
			break;
	default:
		if(current->transaction->unsupported_operation_action == UNSUPPORTED_ABORT){
			// Don't leap out of the stack
			atomic_set(&current->transaction->status, TX_ABORTED);
			set_thread_flag(TIF_IRET);
			printk(KERN_ERR "Aborting on unsupported syscall in tx: %lu\n", *syscall);
		} else if(current->transaction->unsupported_operation_action == UNSUPPORTED_ERROR_CODE){
			printk(KERN_ERR "Warning: Stopped execution of unsupported syscall in tx: %lu\n", *syscall);
			*syscall = __NR_xbogus;
			current->xbogus_return_code = -ENOTXSUPPORT;
		} else {
#ifdef CONFIG_TX_KSTM_WARNINGS
			printk(KERN_ERR "Warning: Executing unsupported syscall in tx: %lu\n", *syscall);
#endif
		}
	}
}

asmlinkage long sys_xbegin(int flags, 
			   int __user *xsw) {
		
	int durable = flags & TX_NONDURABLE ? 0 : 1;
	
	/*DEBUG
	printk(KERN_ERR "Xbegin with %d, %d args\n", usertm, autoretry);
	printk(KERN_ERR "Beginning transaction (%d)\n", current->pid);
	*/

	//if count < 0, xabort rolled everything back
	//mark us untransactional, inactive
	//DON, this could be done in sys_xabort, but that might break things?
	if(current->transaction->abortWithErr){
		current->transaction->abortWithErr = 0;
		terminate_transaction();
		return -1;
	}
		
	// Mark task as transactional
	current->transactional = 1;
	current->usertm = (flags & TX_NOUSER_ROLLBACK) ? 1 : 0;
	current->xsw = xsw;
	current->transaction->autoretry = (flags & TX_NOAUTO_RETRY) ? 0 : 1;
	if(flags & TX_ERROR_UNSUPPORTED){
		current->transaction->unsupported_operation_action = UNSUPPORTED_ERROR_CODE;
	} else if(flags & TX_LIVE_DANGEROUSLY){
		current->transaction->unsupported_operation_action = UNSUPPORTED_LIVE_DANGEROUSLY;
	} else {
		current->transaction->unsupported_operation_action = UNSUPPORTED_ABORT;
	}
	init_jbd_kstm_tx(&current->transaction->jbd, durable);
	set_signal_recv_deferrable(durable & 0x2);

	if(current->transaction->count == 0)
		atomic_inc(&tx_count);

	if(current->usertm)
		return 0;

#ifdef CONFIG_TX_USER_PTM	
	///////////////////////////////////////////
	// Create COW duplicate of address space and save the old one to
	// roll back
	
	prepare_checkpoint(current);
#endif

#ifdef  CONFIG_TX_KSTM_ABORT_OBJ_ON_ADD
        current->create_count = 0;
#endif

#ifdef  CONFIG_TX_KSTM_ABORT_OBJ_ON_UPGRADE
        current->upgrade_count = 0;
#endif

	return current->transaction->count;
}

asmlinkage long sys_xend(volatile struct pt_regs regs){

	// "Commit" or "abort" the new address space
	int rv;

	/* DEBUG 
	if(current->transactional && current->usertm)
		printk(KERN_ERR "Ending transaction (%d)\n", current->pid);
	*/

	if(current->usertm && !current->transactional)
		return 0;

	// Assert that we are currently transactional
	//BUG_ON(current->transactional == 0);
	if (!current->transactional){
#ifdef CONFIG_TX_KSTM_WARNINGS
		printk(KERN_ERR "WARNING: xend called outside of a transaction\n");
#endif
		return -ENOTX;
	}

	// Dump the tx workset to the logs for our own edification
	//debug_dump_workset(current->transaction);

#ifdef CONFIG_TX_KSTM_ABORT_ONCE
	/* Abort every tx syscall at least once to test recoverability*/
	if(current->transaction->count < 1){
		atomic_set(&current->transaction->status, TX_ABORTED);
	}
#endif

	if((rv = endTransaction(current->transaction)) == 0
	   || current->usertm){

		if(rv && current->usertm){
			rv = -ETXABORT;
		}


		terminate_transaction();

		stats_end_tx(current->eax);

	} else { //Abort

		/* Often swallowed, but not always */
		rv = -ETXABORT;

		/* DEBUG
		if(current->transactional && current->usertm)
			printk(KERN_ERR "aborting up (%d)\n", current->pid);
		*/

		current->transaction->count++;
		
		if(!current->usertm){
			if(!current->transaction->autoretry)
				current->transaction->abortWithErr = 1;
			current->need_autoretry = 1;
		}

		common_tx_reset();

		stats_abort_tx(current->eax);

		// Let someone else run to resolve the conflict we lost
		// Especially important on UP
		schedule();
	}

	return rv;
}

asmlinkage long sys_xabort(volatile struct pt_regs regs){

	BUG_ON((current->transactional == 0));

	/* DEBUG
	printk(KERN_ERR "Aborting transaction\n");
	*/

	stats_abort_tx(current->eax);

	atomic_set(&current->transaction->status, TX_ABORTED);
#ifdef CONFIG_TX_USER_HTM
	/* Only abort the kernel end of things */
	endTransactionKernel(current->transaction);
#else
	endTransaction(current->transaction);
#endif

	current->transaction->count++;

	if(current->usertm)
		terminate_transaction();
	else { 
		if(!current->transaction->autoretry)
			current->transaction->abortWithErr = 1;
		current->need_autoretry = 1;		
		common_tx_reset();
	}

	return 0;
}

EXPORT_SYMBOL(check_asymmetric_conflict);
#else

// Define xbegin and xend as null routines

asmlinkage long sys_xbegin(int usertm, int __user *xsw, int autoretry, int durable) { 
  return 0;
}

asmlinkage long sys_xend(struct pt_regs regs){
  return 0;
}

asmlinkage long sys_xabort(struct pt_regs regs){
  return 0;
}


#endif // CONFIG_TX_SYSCALLS

asmlinkage long sys_xbogus(void){
	return current->xbogus_return_code;
}

EXPORT_SYMBOL(abort_self);
EXPORT_SYMBOL(tx_count);
EXPORT_SYMBOL(contentionManager);
EXPORT_SYMBOL(abortTransaction);
EXPORT_SYMBOL(atomic_cachep); //usb/gadget/g_file_storage wants it
