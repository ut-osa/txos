#ifndef _LINUX_TRANSACTION_H
#define _LINUX_TRANSACTION_H

#include <linux/linkage.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <asm/current.h>
#include <asm/ptrace.h>
#include <linux/mutex.h>
#include <linux/err.h>
#include <linux/mm_types.h>
#include <linux/hardirq.h>
#include <linux/thread_info.h>
#include <linux/debugtx.h>

// Transaction status word
#define TX_INACTIVE   0
#define TX_ACTIVE     1
#define TX_ABORTED    2
#define TX_COMMITTING 3
#define TX_ABORTING   4
#define TX_ABRT_NOTX  5 /* Roll back into non-tx mode */

// Simplify validation of simple fields
#define TX_VALIDATE(a, b, field) if(a->field != b->field){ \
		printk(KERN_ERR "Inconsistent value for %p (%p)\n", &(a->field), &(b->field)); \
		BUG(); }
#define TX_VALIDATE_ATOMIC(a, b, field)					\
	if(atomic_read(&a->field) != atomic_read(&b->field)){		\
		printk(KERN_ERR "Inconsistent value for %p\n", &(a->field)); \
		BUG(); }

// Simplify commit also

#define TX_COMMIT(a, b, field) a->field = b->field
#define TX_COMMIT_ATOMIC(a, b, field) atomic_set(&(a)->field, atomic_read(&(b)->field))

#define tx_preemptible(count) (current_thread_info()->preempt_count2 == count)

// System syscalls to begin/end tx on a single syscall - some overlap
// with sys_xbegin/end
#ifndef CONFIG_X86_64
asmlinkage void preSyscallHook(unsigned long eax, struct pt_regs regs);
asmlinkage long postSyscallHook(volatile unsigned long eax, volatile struct pt_regs regs);
#else
//asmlinkage void preSyscallHook64(unsigned long rax, struct pt_regs *regs);
//asmlinkage long postSyscallHook64(unsigned long rax, struct pt_regs *regs);
#endif

void common_tx_reset(void);
void checkWhitelist(unsigned long *syscall);
#ifdef CONFIG_TX_KSTM_STATS
void stats_begin_tx(unsigned long syscall);
void init_tx_stats(void);
#else
#define init_tx_stats()
#define stats_begin_tx(eax)
#define stats_abort_tx(eax)
#define stats_end_tx(eax)
#endif

// sys_xbegin flags
#define TX_DEFAULTS         0
#define TX_ABORT_UNSUPPORTED 0
#define TX_NONDURABLE       1
#define TX_NOUSER_ROLLBACK  2
#define TX_NOAUTO_RETRY     4
#define TX_ERROR_UNSUPPORTED 8
#define TX_LIVE_DANGEROUSLY 16

// User syscalls to begin/end tx
asmlinkage long sys_xbegin(int flags, int __user *xsw);
asmlinkage long sys_xend(struct pt_regs regs);
asmlinkage long sys_xabort(struct pt_regs regs);
asmlinkage long sys_xbogus(void);

enum access_mode { ACCESS_R, ACCESS_RW, ACCESS_EXCL, ACCESS_PIPE_READ, 
		   ACCESS_PIPE_WRITE, ACCESS_PIPE_RW, NUM_ACCESS_MODES };

void init_tx_proc(void);
#ifdef CONFIG_TX_KSTM_STATS
extern void kstm_stats_sched(struct task_struct *prev, struct task_struct *next);
#else
#define kstm_stats_sched(prev, next)
#endif

#ifdef CONFIG_TX_KSTM_PROF
extern unsigned long long shadowCopyCycles;
#endif	


#ifdef CONFIG_TX_KSTM

#define shadow(obj) (obj)->shadow
#define parent(obj) (obj)->parent

#ifdef CONFIG_TX_KSTM_ASSERTIONS
#define KSTM_BUG_ON(x) BUG_ON(x)
#else
#define KSTM_BUG_ON(x) do{}while(0)
#endif

static inline void check_int(void){
#ifdef CONFIG_TX_KSTM_ASSERTIONS
	BUG_ON(in_interrupt());
#endif
}

enum tx_object_type { TYPE_FILE, TYPE_INODE, TYPE_DENTRY, TYPE_LIST_HEAD, TYPE_HLIST_HEAD, \
		      TYPE_VFSMOUNT, TYPE_SUPER_BLOCK, TYPE_LIST2_HEAD};

//
// Just use an atomic counter for now - this may have negative
// performance consequences
extern atomic_t timestamp_counter;
// The number of active tx in the system
extern atomic_t tx_count;

/* A structure to track deferred operations */
#define DEFERRED_TYPE_TTY_WRITE 0
#define DEFERRED_TYPE_FSYNC     1
struct deferred_tty_write {
	char *buf;
	size_t count;
	ssize_t (*write)(struct tty_struct *, struct file *, const unsigned char *, size_t);
};

struct deferred_fsync {
	int datasync;
	struct file *file;
};

struct deferred_object_operation {
	struct list_head list;
	unsigned long type;
	union{
		struct deferred_tty_write tty_write;
		struct deferred_fsync fsync;
	} u;
};

/* An entry in a transaction's working set */
typedef struct txobj_thread_list_node {
	struct skiplist_head workset_list; //This is how we connect to the workset

	struct list_head object_list; // This is how we connect to the object's 
  	                              //reader list (although this includes 
	                              //writers) 
#ifdef CONFIG_TX_KSTM_DORDER
	struct list_head data_writer_list; // An in-order list of tx data writes
#endif
	struct transaction *tx; // The owner of this list
	enum tx_object_type type;
	void * shadow_obj;
	void * orig_obj;
#ifdef CONFIG_TX_KSTM_ASSERTIONS
	void * checkpoint_obj;
#endif

	struct transactional_object * tx_obj; // The tx object we are attached to

	enum access_mode rw;
#ifdef CONFIG_TX_KSTM_ASSERTIONS
	int (*validate)(struct txobj_thread_list_node *);
#endif
	int (*lock)(struct txobj_thread_list_node *, int blocking);
	int (*unlock)(struct txobj_thread_list_node *, int blocking);
	int (*commit)(struct txobj_thread_list_node *);
	int (*abort)(struct txobj_thread_list_node *);
	/* Free the shadow and checkpoint copies, do any other cleanup
	 * (like decrementing the refcount on the stable copy
	 */
	int (*release)(struct txobj_thread_list_node *, int early);

	/* This list is for deferred operations on this object that
	 * don't necessarily merit conflict detection, such at tty
	 * writes */
	struct list_head deferred_operations;
	/* XXX: Will eventually expand this into something more
	 * general for other "non-traditional" file types
	 */
	struct tty_struct *tty;

} txobj_thread_list_node_t;

typedef struct transactional_object {
	// Reference count, pointer to a field in a tx_list for economy
	// XXX: Add later
	//atomic_t *ref_count;

	// Type encoding
	enum tx_object_type type;
	
	// Writer
	struct transaction *writer;

	// List of readers
	struct list_head readers;

	// Spinlock, for synchronization - acquire after object's
	// non-blocking lock
	spinlock_t lock;
	

} transactional_object_t;

#define LOCK_XOBJ(xobj) spin_lock(&(xobj)->lock)
#define UNLOCK_XOBJ(xobj) spin_unlock(&(xobj)->lock)

/* Accounting for durable transactions.  Here because
 * including jbd code in transaction.h leads to
 * ugliness */
#define TX_NOT_DURABLE 0
#define TX_DURABLE 1
#define TX_COMMITTING_DURABLE 2

struct jbd_kstm_tx {
	int nblocks;
	int durable;
	struct super_block *sb;
	struct handle_s *handle;
};

enum unsupported_behavior { UNSUPPORTED_ABORT, UNSUPPORTED_ERROR_CODE, UNSUPPORTED_LIVE_DANGEROUSLY };

struct transaction {
/* The threads associated with this transaction */
	struct list_head tasks;
	atomic_t task_count;
	// Used _only_ for garbage collection on the wait queues
	atomic_t ref_count;

	// Tx status word
	atomic_t status;

   	//autoretry
 	int autoretry;
	
	// Timestamp
	unsigned int timestamp;

	// Number of retries
	int count;

   	// Abort and return a -1 after a sys_xabort
   	int abortWithErr;

	// What to do on an unsupported operation
	enum unsupported_behavior unsupported_operation_action;
	
	struct skiplist_head object_list;
	/* Lists are the exception to kernel virtual address - lists
	 * are locked in kva order _after all other objects */
	struct skiplist_head list_list;
#ifdef CONFIG_TX_KSTM_DORDER
	struct list_head data_writer_list;
#endif
	spinlock_t workset_lock;

	// used to commit writes
	struct task_struct *committing_task;

	/* The wait queue for loser transactions */
	wait_queue_head_t losers;

	/* The wait queue for commit */
	wait_queue_head_t siblings;
	
	/* Protects the tasks list and orphan lists */
	spinlock_t lock;

	struct list_head orphaned_atomic_ops;
	struct list_head orphaned_fsnotify;
	struct list_head orphaned_allocs;

	struct list_head orphaned_page_allocs;
	struct list_head orphaned_page_frees;

	struct rcu_head *deferred_frees;

	/* Bookeeping for jbd journal transactions */
	struct jbd_kstm_tx jbd;
};

// XXX: Worth eliding in single thread case?
#define WORKSET_LOCK(t) spin_lock(&((t)->workset_lock))
#define WORKSET_UNLOCK(t) spin_unlock(&((t)->workset_lock))

extern struct kmem_cache *transaction_struct_cachep;
# define alloc_transaction_struct() kmem_cache_alloc(transaction_struct_cachep, GFP_KERNEL)
# define free_transaction_struct(tx) kmem_cache_free(transaction_struct_cachep, (tx))

extern struct kmem_cache *deferred_object_operation_struct_cachep;
# define alloc_deferred_object_operation() \
	kmem_cache_alloc(deferred_object_operation_struct_cachep, GFP_KERNEL)
# define free_deferred_object_operation(tx) \
	kmem_cache_free(deferred_object_operation_struct_cachep, (tx))

extern void abort_self(struct transaction *, int);
extern int endTransaction(struct transaction *t);
extern int abortTransaction(struct transaction *t);

#ifndef TX_CONFIG_FAKE_STATIC
static inline void * tx_status_check(void *obj, enum access_mode mode, int noabort){
	int status = atomic_read(&current->transaction->status);

	switch(status){
	case TX_INACTIVE:
	case TX_COMMITTING:
	case TX_ABORTING:
		return obj;
	case TX_ABORTED:
		if(!noabort)
			abort_self(NULL, 0);
		/* Return if we can't abort for some reason */
		return ERR_PTR(-ETXABORT);
	case TX_ACTIVE:
		return NULL;
	default:
		printk(KERN_ERR "Bad value at %p, %d\n", &current->transaction->status, status);
		BUG();
	}
}
#else
#define tx_status_check(obj, mode, noabort) obj
#endif

#define require_notx() if(live_transaction()) BUG();

/* Custom memory pool implementation */
#define TX_POOL_SIZE 100
#define cpu() raw_smp_processor_id()

/* workset entry cache */
#define alloc_tx_thread_list_node() kmem_cache_alloc(cachep_tx_thread_list, GFP_KERNEL);
#define free_tx_thread_list_node(tx) kmem_cache_free(cachep_tx_thread_list, tx);
extern struct kmem_cache *cachep_tx_thread_list;
extern struct kmem_cache *cachep_tx_list;
extern struct kmem_cache *cachep_tx_hlist;
extern struct kmem_cache *cachep_tx_vfsmount;
/* task checkpoint cache */
extern struct kmem_cache *cp_cachep;

int tx_chkpt_task_fields(struct task_struct *tsk);

// Contention manager function - priority / timestamp
// Returns true if a wins the conflict over b
int contentionManager(struct transaction *a, struct transaction *b, int *should_sleep);


#ifndef CONFIG_TX_FAKE_STATIC
static inline int inactive_transaction(void){ 
	return atomic_read(&current->transaction->status) == TX_INACTIVE;
}

static inline int active_transaction(void){ 
	return atomic_read(&current->transaction->status) != TX_INACTIVE;
}

/* a live transaction is one that is still active or aborted (and
 * doesn't know it is dead yet).  An active one includes committing
 * and aborting
 */
static inline int live_transaction(void){ 
	int status = atomic_read(&current->transaction->status);
	return status == TX_ACTIVE || status == TX_ABORTED;
}

static inline int committing_transaction(void){ 
	int status = atomic_read(&current->transaction->status);
	return status == TX_COMMITTING;
}

static inline int aborting_transaction(void){ 
	int status = atomic_read(&current->transaction->status);
	return status == TX_ABORTING;
}


#else

#define inactive_transaction() 1
#define active_transaction() 0
#define live_transaction() 0
#define committing_transaction() 0
#define aborting_transaction() 0

#endif

extern struct kmem_cache *atomic_cachep;
#define alloc_atomic_buf() kmem_cache_alloc(atomic_cachep, GFP_ATOMIC)
#define free_atomic_buf(item) kmem_cache_free(atomic_cachep, (item))
extern struct kmem_cache *alloc_cachep;
#define alloc_alloc_buf() kmem_cache_alloc(alloc_cachep, GFP_ATOMIC)
#define free_alloc_buf(item) kmem_cache_free(alloc_cachep, (item))


static inline int _record_tx_alloc(void *buf, struct kmem_cache *cache, 
				   struct alloc_record_buf *rbuf){
	if(rbuf->count == MAX_TX_ALLOCS)
		return 0;

	rbuf->recs[rbuf->count].buf = buf;
	rbuf->recs[rbuf->count++].cache = cache;
	return 1;
}

static inline void record_tx_alloc(void *buf, struct kmem_cache *cache){
	struct alloc_record_buf *rbuf;
	if(!live_transaction())
		return;

	list_for_each_entry(rbuf, &current->allocs, list)
		if(_record_tx_alloc(buf, cache, rbuf))
			return;

	rbuf = alloc_alloc_buf();
	rbuf->count = 0;
	INIT_LIST_HEAD(&rbuf->list);
	list_add(&rbuf->list, &current->allocs);
	_record_tx_alloc(buf, cache, rbuf);
}

static inline int _record_tx_free(void *buf, struct alloc_record_buf *rbuf){
	int count = rbuf->count;

	while(--count >= 0){
		if(rbuf->recs[count].buf == buf){
			rbuf->recs[count].buf = NULL;
			if(count == rbuf->count - 1)
				rbuf->count--;
			return 1;
		} else if(rbuf->recs[count].buf == NULL
			  && count == rbuf->count - 1){
			rbuf->count--;
		} 
	}

	return 0;
}

static inline void record_tx_free(void *buf){
	struct alloc_record_buf *rbuf;

	if(!live_transaction())
		return;
	
	list_for_each_entry(rbuf, &current->allocs, list)
		if(_record_tx_free(buf, rbuf))
			return;

	BUG();
}

static inline void record_tx_lock(void *addr, enum tx_lock_type type){
	if(!live_transaction())
		return;

	BUG_ON(current->nr_locks >= MAX_TX_LOCKS);
		
	current->locks[current->nr_locks].lock = addr;
	current->locks[current->nr_locks++].type = type;
}

static inline void record_tx_unlock(void *addr, enum tx_lock_type type){
	int count = current->nr_locks - 1;
	int found = 0;

	if(!live_transaction())
		return;

	while(count >= 0){
		if(current->locks[count].lock == addr){
			current->locks[count].lock = NULL;
			if(count == current->nr_locks - 1)
				current->nr_locks--;
			found = 1;
		} else if(current->locks[count].lock == NULL
			  && count == current->nr_locks - 1){
			current->nr_locks--;
		} else if(found)
			return;

		count--;
	}

	KSTM_BUG_ON(!found);
}

static inline int _record_tx_atomic(tx_atomic_t *addr, int val, enum atomic_op_type type, 
				    struct atomic_op_record_buf *buf){
	int i;
	int count;
	struct atomic_op_record *cursor;

	/* All recorded atomic ops are add.  Put in some smarts to save memory */
	//if(type == ATOMIC_OP_ADD)
	count = buf->count;
	cursor = buf->recs;
	for(i = 0; i < count; i++, cursor++){
		if(cursor->addr == addr)
			break;
	}
	
	if(i == count){
		if(i == MAX_TX_ATOMIC_OPS){
			return 0;
		} else {
			buf->count++;
			cursor->addr = addr;
			cursor->val = val;
			cursor->type = type;
		
		}
	} else { 
		cursor->val += val;
	}
	
	return 1;
}

static inline void record_tx_atomic(tx_atomic_t *addr, int val, enum atomic_op_type type){

	struct atomic_op_record_buf *buf;

	if(!live_transaction())
		return;

	list_for_each_entry(buf, &current->atomic_ops, list)
		if(_record_tx_atomic(addr, val, type, buf))
			return;

	buf = alloc_atomic_buf();
	buf->count = 0;
	list_add(&buf->list, &current->atomic_ops);
	if(_record_tx_atomic(addr, val, type, buf))
		return;

	BUG();
}

void init_tx_global(void);
struct txobj_thread_list_node * tx_check_add_obj(struct transactional_object * xobj,
						 enum tx_object_type type, 
						 enum access_mode mode,
						 int *should_sleep,
						 struct transaction **winner);
struct transaction * check_asymmetric_conflict(struct transactional_object * xobj,
					       enum access_mode mode, int can_sleep,
					       int test_only);
txobj_thread_list_node_t * workset_has_object(struct transactional_object *xobj);
txobj_thread_list_node_t * workset_has_object_locked(struct transactional_object *xobj);

struct transaction * upgrade_xobj_mode(struct transactional_object *xobj, enum access_mode mode, int *should_sleep);
					      
void init_tx_object(struct transactional_object *new_tx_obj, enum tx_object_type type);
void remove_xnode_reference(struct transaction * t, struct transactional_object *xobj);
void early_release(struct transactional_object *xobj, int commit);

int commit_tx_rw(struct address_space *mapping, struct transaction *tx);
int abort_tx_rw(struct address_space *mapping, struct transaction *tx);

#ifdef CONFIG_TX_KSTM_DEBUG_STALL_ON_CONFLICT

#define log_enemy_abort() do{						\
		printk(KERN_ERR "(%d, %s) Aborting enemy, preempt_count2 = %d\n", current->pid, current->comm, preempt_count2());	\
		dump_stack();						\
		DEBUG_BREAKPOINT();					\
	} while(0);



#define log_self_abort() do{ printk(KERN_ERR "(%d) Aborting self\n", current->pid); \
		DEBUG_BREAKPOINT();					\
	} while(0);
		

#define log_stall(pd, tx) do{\
		printk(KERN_ERR "(%d) Sleeping on conflict with %d, tx = %p\n",	\
		       current->pid,					\
		       list_entry((pd), struct task_struct, transaction_entry)->pid, (tx)); \
		DEBUG_BREAKPOINT();					\
	} while(0)


#define log_retry()  printk(KERN_ERR "(%d) Retrying after tx commit\n", current->pid)

#else

#define log_enemy_abort()
#define log_self_abort()
#define log_stall(pid, tx)
#define log_retry()

#endif // CONFIG_TX_KSTM_DEBUG_STALL_ON_CONFLICT

static inline void wait_on_tx(struct transaction *tx){
	//int timestamp = tx->timestamp;
	log_stall((tx)->tasks.next, (tx));

	/* Don't use any particular condition - just wait on the
	 * queue.  We can't rely on the transaction struct being valid
	 * by the time the scheduler decides to wake us up.  Yes, this
	 * interface is deprecated, but I don't care.
	 */
	interruptible_sleep_on(&tx->losers);
	log_retry();		     
}

int attempt_xforked_death(struct task_struct *tsk);

static inline void precognitive_check_asymmetric_conflict(struct transactional_object *xobj, enum access_mode mode){
	struct transaction *winner = NULL;
	if(inactive_transaction() && tx_preemptible(0)){
		while((atomic_read(&tx_count) != 0)
		      && (winner = 
			  check_asymmetric_conflict(xobj, mode, 
						    tx_preemptible(0),
						    1)
			      )){
			/* Sleep until the winner commits */
			wait_on_tx(winner);
		}
	}
}

static inline void workset_add(struct txobj_thread_list_node *node, struct skiplist_head *head){
	struct skiplist_head *cur = head;
	int level = head->level - 1;
	WORKSET_LOCK(current->transaction);
	while(level >= 0){
		struct txobj_thread_list_node *item;

		/* If the next element at this level is the head, drop down one */
		if(cur->next[level] == head){
			level--;
			continue;
		}

		item = skiplist_entry(cur->next[level], struct txobj_thread_list_node, workset_list);

		KSTM_BUG_ON(item == node);
		/* Sort by kernel virtual address */
		if(item->orig_obj < node->orig_obj)
			cur = cur->next[level];
		else 
			level--;
	} 

	insert_skiplist_at(&node->workset_list, head, cur);
	WORKSET_UNLOCK(current->transaction);
}

#else

#define active_transaction() 0
#define live_transaction() 0
#define check_dcache_lock() 0
#define committing_transaction() 0

#define shadow(obj) NULL

#define abort_self(tx, y)

#define KSTM_BUG_ON(x) do{}while(0)

#define record_tx_alloc(a, b)
#define record_tx_free(a)
#define record_tx_lock(a, b)
#define record_tx_unlock(a, b)
#define record_tx_fd_get(fd, state);
#define record_tx_fd_put(fd);

#define require_notx()

#define  precognitive_check_asymmetric_conflict(obj, mode)
#endif

#define assert_shadow(obj) if(active_transaction()) KSTM_BUG_ON(!shadow(obj))

#endif	//_LINUX_TRANSACTION_H
 
