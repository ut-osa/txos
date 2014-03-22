#include <linux/transaction.h>
#include <linux/tx_inodes.h>
#include <linux/mm.h>
#include <linux/osamagic.h>
#include <linux/err.h>
#include <linux/writeback.h>
#include <linux/tx_pages.h>
#include <linux/ext3_fs_i.h>
#include <linux/ext2_fs_i.h>
#include <linux/proc_fs.h>
#include <linux/blkdev.h>
#include <linux/shmem_fs.h>
#include <linux/mqueue.h>
#include <linux/tty.h>
#include <net/sock.h>

#ifdef CONFIG_TX_KSTM

/* DEP: I think it is actually ok to do these allocations non-atomically */
static inline void * __alloc_tx_inode(struct kmem_cache *source, size_t size, gfp_t flags){
	//in_atomic() to handle prepare_tx_write in do_no_page()
	if(source && !in_atomic())
		return kmem_cache_alloc(source, flags);
	else
		return kmalloc(size, flags);
}

#define alloc_tx_inode(source, size) __alloc_tx_inode(source, size, GFP_KERNEL)
#define alloc_tx_inode_atomic(source, size) __alloc_tx_inode(source, size, GFP_ATOMIC)

static inline void __free_tx_inode(struct _inode *_inode){
	if(_inode->source)
		kmem_cache_free(_inode->source, _inode->i_parent);
	else
		kfree(_inode->i_parent);
}

static void free_tx_inode_callback(struct rcu_head * head){
	struct _inode *_inode = container_of(head, struct _inode, i_rcu);
	__free_tx_inode(_inode);
}

static inline void free_tx_inode(struct _inode *_inode){
	if(atomic_dec_return(&_inode->tx_refcount) <= 0)
		call_rcu(&_inode->i_rcu, free_tx_inode_callback);
}


int lock_inode(struct txobj_thread_list_node * xnode, int blocking){

	struct inode * inode = (struct inode *) xnode->orig_obj;
	struct _inode * _inode = (struct _inode *) xnode->shadow_obj;
	if(blocking)
		mutex_lock(&inode->i_mutex);
	else {
		spin_lock(&inode->i_lock);

	}

	if(_inode->i_op->lock)
		_inode->i_op->lock(inode, blocking);

	return 0;
}

static inline int __unlock_inode(struct txobj_thread_list_node * xnode,
		int blocking, int data){

	struct inode * inode = (struct inode *) xnode->orig_obj;
	struct _inode * _inode = inode->i_contents;

	if(_inode->i_op->unlock)
		_inode->i_op->unlock(inode, blocking);

	if(blocking) {
		int tx_truncate = _inode->tx_truncate;
		struct deferred_object_operation *op, *n;

		if(unlikely(tx_truncate))
			_inode->tx_truncate--;

		/* Piggy back on unlock to do pending file data updates */
		if(data) {
			switch(atomic_read(&current->transaction->status)){
			case TX_ABORTING:
				abort_tx_rw(_inode->i_mapping, current->transaction);
				break;
			case TX_COMMITTING:
				commit_tx_rw(_inode->i_mapping, current->transaction);
				break;
			default:
				BUG();
			}
		}

		list_for_each_entry_safe(op, n, &xnode->deferred_operations, list){
			switch(op->type){
			case DEFERRED_TYPE_TTY_WRITE:
			{
				struct tty_ldisc *ld;
				ssize_t write_bytes;
				if(committing_transaction()){
					ld = tty_ldisc_ref_wait(xnode->tty);		
					BUG_ON(!ld->write);
					write_bytes = finish_tty_write(ld->write,
								       _inode,
								       xnode->tty,
								       NULL,
								       op->u.tty_write.buf,
								       op->u.tty_write.count);
					BUG_ON(write_bytes != op->u.tty_write.count);
					tty_ldisc_deref(ld);
				}
				kfree(op->u.tty_write.buf);
				break;
			}
			default:
				BUG();
			}
			list_del(&op->list);
			free_deferred_object_operation(op);
		}

		/* Mark inodes we update dirty.  Must wait to do this
		 * until after we release all nonblocking locks. 
		 *
		 * XXX: If this ever changes, revisit
		 * __mark_inode_dirty and friends.
		 */
		if(_inode->tx_dirty) {
			__mark_inode_dirty(inode, _inode->tx_dirty);
			_inode->tx_dirty = 0;
		}

		mutex_unlock(&inode->i_mutex); 

		if(unlikely(tx_truncate))
			_inode->i_op->truncate(_inode);

	} else {
		spin_unlock(&inode->i_lock);
	}

	return 0;
}

int lock_inode_tty_write(struct txobj_thread_list_node *xnode, int blocking) {
	if(blocking)
		mutex_lock(&xnode->tty->atomic_write_lock);
	return lock_inode(xnode, blocking);
}

int unlock_inode_tty_write(struct txobj_thread_list_node *xnode, int blocking) {
	int rv = __unlock_inode(xnode, blocking, 1);
	if(blocking)
		mutex_unlock(&xnode->tty->atomic_write_lock);
	return rv;
}


int unlock_inode_data_rw(struct txobj_thread_list_node *xnode, int blocking) {
	return __unlock_inode(xnode, blocking, 1);
}

int unlock_inode_data_r(struct txobj_thread_list_node *xnode, int blocking) {
	return __unlock_inode(xnode, blocking, 1);
}

static int unlock_inode_nodata(struct txobj_thread_list_node *xnode,
		int blocking) {
	return __unlock_inode(xnode, blocking, 0);
}

int release_inode(struct txobj_thread_list_node * xnode, int early){
	
	struct inode *inode = (struct inode *)xnode->orig_obj;
#ifdef CONFIG_TX_KSTM_ASSERTIONS
	__free_tx_inode((struct _inode *) xnode->checkpoint_obj);
#endif
	/* Put our reference */
	iput(inode);
	
	return 0;
}



int commit_inode(struct txobj_thread_list_node * xnode){
				
	struct inode * inode = (struct inode *)xnode->orig_obj;
	struct _inode *shadow_inode = xnode->shadow_obj;

	/* Only update these fields on a write copy */
	if(xnode->rw == ACCESS_RW){
		struct _inode * old_inode = inode->i_contents;
		
		if(shadow_inode->i_op->commit)
			shadow_inode->i_op->commit(shadow_inode, xnode->rw,
					xnode->unlock == unlock_inode_data_rw);

		shadow_inode->shadow = NULL;
		shadow_inode->rw = ACCESS_R; 

		/* XXX: This needs to be last.  Apparently the i_sb
		 * pointer can be followed without a lock
		 */
		inode->i_contents = shadow_inode;

		free_tx_inode(old_inode);
	
	} else {
		atomic_dec(&shadow_inode->tx_readcount);
		if(shadow_inode->i_op->commit)
			shadow_inode->i_op->commit(shadow_inode, xnode->rw,
					xnode->unlock == unlock_inode_data_rw);
	}
	atomic_dec(&shadow_inode->tx_refcount);


	return 0;
}


int abort_inode(struct txobj_thread_list_node * xnode){
				
	struct inode * inode = (struct inode *)xnode->orig_obj;
	struct _inode *shadow_inode = (struct _inode *) xnode->shadow_obj;

	/* If we have a newly created inode, we actually have to
	 * commit the state so that the file system can then free
	 * it */
	if(inode->i_state & I_NEW){
		//commit_inode(xnode);
		BUG();
	}

	// Give the specific file system a chance to clean up
	if(shadow_inode->i_op->abort)
		shadow_inode->i_op->abort(shadow_inode, xnode->rw);

	// Dump our speculative inode
	if(xnode->rw == ACCESS_R){
		atomic_dec(&shadow_inode->tx_readcount);
		atomic_dec(&shadow_inode->tx_refcount);
	} else
		free_tx_inode(shadow_inode);

	return 0;
}

#ifdef CONFIG_TX_KSTM_ASSERTIONS
int validate_inode(struct txobj_thread_list_node * xnode){
				
	struct _inode * inode = ((struct inode *)xnode->orig_obj)->i_contents;
	struct _inode * checkpoint_inode = (struct _inode *) xnode->checkpoint_obj;
	struct _inode * shadow_inode = (struct _inode *) xnode->shadow_obj;

	BUG_ON(xnode->rw == ACCESS_RW && inode == shadow_inode);
	
	TX_VALIDATE(inode, checkpoint_inode, i_ino);
	TX_VALIDATE(inode, checkpoint_inode, i_nlink);
	TX_VALIDATE(inode, checkpoint_inode, i_uid);
	TX_VALIDATE(inode, checkpoint_inode, i_gid);
	TX_VALIDATE(inode, checkpoint_inode, i_rdev);
	TX_VALIDATE(inode, checkpoint_inode, i_version);
	TX_VALIDATE(inode, checkpoint_inode, i_size);

	TX_VALIDATE(inode, checkpoint_inode, i_blkbits);
	TX_VALIDATE(inode, checkpoint_inode, i_mode);

	// Yes, let's commit the ops too (alloc)
	TX_VALIDATE(inode, checkpoint_inode, i_op);
	TX_VALIDATE(inode, checkpoint_inode, i_fop);

	TX_VALIDATE(inode, checkpoint_inode, i_mapping);

	/* The dread address_space struct */
	/*
	TX_VALIDATE(inode, checkpoint_inode, i_data.host);
	TX_VALIDATE(inode, checkpoint_inode, i_data.page_tree.height);
	TX_VALIDATE(inode, checkpoint_inode, i_data.page_tree.gfp_mask);
	TX_VALIDATE(inode, checkpoint_inode, i_data.page_tree.rnode);
	TX_VALIDATE(inode, checkpoint_inode, i_data.i_mmap_writable);
	TX_VALIDATE(inode, checkpoint_inode, i_data.i_mmap.prio_tree_node);
	TX_VALIDATE(inode, checkpoint_inode, i_data.i_mmap.index_bits);
	TX_VALIDATE(inode, checkpoint_inode, i_data.i_mmap.raw);
	TX_VALIDATE(inode, checkpoint_inode, i_data.i_mmap_nonlinear.next);
	TX_VALIDATE(inode, checkpoint_inode, i_data.i_mmap_nonlinear.prev);
	TX_VALIDATE(inode, checkpoint_inode, i_data.truncate_count);
	TX_VALIDATE(inode, checkpoint_inode, i_data.nrpages);
	TX_VALIDATE(inode, checkpoint_inode, i_data.writeback_index);
	TX_VALIDATE(inode, checkpoint_inode, i_data.a_ops);
	TX_VALIDATE(inode, checkpoint_inode, i_data.flags);
	TX_VALIDATE(inode, checkpoint_inode, i_data.backing_dev_info);
	TX_VALIDATE(inode, checkpoint_inode, i_data.private_list.next);
	TX_VALIDATE(inode, checkpoint_inode, i_data.private_list.prev);
	TX_VALIDATE(inode, checkpoint_inode, i_data.assoc_mapping);
	*/

	/* I don't believe this changes on the shadow copy */
	/*
	TX_VALIDATE(inode, shadow_inode, i_data.host);
	TX_VALIDATE(inode, shadow_inode, i_data.page_tree.height);
	TX_VALIDATE(inode, shadow_inode, i_data.page_tree.gfp_mask);
	TX_VALIDATE(inode, shadow_inode, i_data.page_tree.rnode);
	TX_VALIDATE(inode, shadow_inode, i_data.i_mmap_writable);
	TX_VALIDATE(inode, shadow_inode, i_data.i_mmap.prio_tree_node);
	TX_VALIDATE(inode, shadow_inode, i_data.i_mmap.index_bits);
	TX_VALIDATE(inode, shadow_inode, i_data.i_mmap.raw);
	TX_VALIDATE(inode, shadow_inode, i_data.i_mmap_nonlinear.next);
	TX_VALIDATE(inode, shadow_inode, i_data.i_mmap_nonlinear.prev);
	TX_VALIDATE(inode, shadow_inode, i_data.truncate_count);
	TX_VALIDATE(inode, shadow_inode, i_data.nrpages);
	TX_VALIDATE(inode, shadow_inode, i_data.writeback_index);
	TX_VALIDATE(inode, shadow_inode, i_data.a_ops);
	TX_VALIDATE(inode, shadow_inode, i_data.flags);
	TX_VALIDATE(inode, shadow_inode, i_data.backing_dev_info);
	TX_VALIDATE(inode, shadow_inode, i_data.private_list.next);
	TX_VALIDATE(inode, shadow_inode, i_data.private_list.prev);
	TX_VALIDATE(inode, shadow_inode, i_data.assoc_mapping);
	*/
	
	TX_VALIDATE(inode, checkpoint_inode, i_sb);

	TX_VALIDATE(inode, checkpoint_inode, i_cindex);
	TX_VALIDATE(inode, checkpoint_inode, i_flags);

	if(inode->i_op->validate)
		inode->i_op->validate(inode, checkpoint_inode, shadow_inode, xnode->rw);

	/* Even heavier validation for R-only objects */
	if(xnode->rw == ACCESS_R){
		TX_VALIDATE(inode, shadow_inode, i_ino);
		TX_VALIDATE(inode, shadow_inode, i_nlink);
		TX_VALIDATE(inode, shadow_inode, i_uid);
		TX_VALIDATE(inode, shadow_inode, i_gid);
		TX_VALIDATE(inode, shadow_inode, i_rdev);
		TX_VALIDATE(inode, shadow_inode, i_version);
		TX_VALIDATE(inode, shadow_inode, i_size);
		TX_VALIDATE(inode, shadow_inode, i_blkbits);
		TX_VALIDATE(inode, shadow_inode, i_mode);

		KSTM_BUG_ON(inode->i_sb != shadow_inode->i_sb);

		TX_VALIDATE(inode, shadow_inode, i_cindex);
		TX_VALIDATE(inode, shadow_inode, i_flags);

		// Yes, let's commit the ops too (alloc)
		TX_VALIDATE(inode, shadow_inode, i_op);
		TX_VALIDATE(inode, shadow_inode, i_fop);
	}

	return 0;
}

static inline struct _inode *__checkpoint_inode(struct _inode *_inode){
	struct _inode *checkpoint_inode;
	void *checkpoint_parent = unlikely(in_atomic())?
		alloc_tx_inode_atomic(_inode->source, _inode->i_parent_size):
		alloc_tx_inode(_inode->source, _inode->i_parent_size);
	
	if(!checkpoint_parent)
		return NULL;

	memcpy(checkpoint_parent, _inode->i_parent, _inode->i_parent_size);
	checkpoint_inode = get_inode_from_parent(_inode, checkpoint_parent);
	atomic_set(&checkpoint_inode->tx_refcount, 1);
	checkpoint_inode->i_parent = checkpoint_parent;

	return checkpoint_inode;

}
#else
#define checkpoint_inode(_inode)

#endif // CONFIG_TX_KSTM_ASSERTIONS

static inline int __setup_list_node(txobj_thread_list_node_t *list_node,
				     struct inode *inode,
				     struct _inode *shadow_inode,
#ifdef CONFIG_TX_KSTM_ASSERTIONS
				     struct _inode *checkpoint_inode,
#endif
				     enum access_mode mode,
				    struct transactional_object *xobj){

#ifdef CONFIG_TX_KSTM_DORDER
	INIT_LIST_HEAD(&list_node->data_writer_list);
#endif
	list_node->tx = current->transaction;
	list_node->type = TYPE_INODE;
	list_node->shadow_obj = shadow_inode;
	list_node->orig_obj = inode;
	list_node->rw = mode;
	list_node->lock = lock_inode;
	list_node->unlock = unlock_inode_nodata;
	list_node->commit = commit_inode;
	list_node->abort  = abort_inode;
	list_node->release = release_inode;
	INIT_LIST_HEAD(&list_node->deferred_operations);
	list_node->tty = NULL;
	list_node->tx_obj = xobj;

#ifdef CONFIG_TX_KSTM_ASSERTIONS
	list_node->checkpoint_obj = checkpoint_inode;
	list_node->validate = validate_inode;
#endif
	workset_add(list_node, &(current->transaction->object_list));
	return 0;
}

static inline int inode_mutex_locked(struct mutex *mutex){
	int rv = 0;
	int i;
	int bound = current->nr_locks;
	struct lock_record *rec = current->locks;
	for(i = 0; i < bound; i++, rec++){
		if(rec->lock == mutex){
			KSTM_BUG_ON(rec->type != MUTEX);
			rv = 1;
			break;
		}
	}
	return rv;
}


static inline int lock_my_inode(struct inode *inode, int need_mutex, int multi_proc){
	if(need_mutex){
		
		/* The _sputex_ lock, originally suggested by Chris */
		if(current_thread_info()->preempt_count2 > 0){
			int i = 0;
			int locked = 0;
			/* Abort if we can't get the mutex without blocking
			 * and we have a spinlock 
			 */
			while(i < 100 && (locked = mutex_trylock(&inode->i_mutex)) == 0) {
				asm("rep;nop\n\t"); // relax a bit
			} 
			if(!locked)
				return 1;
		} else
			mutex_lock(&inode->i_mutex);
	}
		
	spin_lock(&inode->i_lock);

	if(multi_proc)
		LOCK_XOBJ(&inode->xobj);
	return 0;
}

static inline void unlock_my_inode(struct inode *inode, int need_mutex, int multi_proc){

	if(multi_proc)
		UNLOCK_XOBJ(&inode->xobj);
	spin_unlock(&inode->i_lock);

	if(need_mutex)
		mutex_unlock(&inode->i_mutex);
}

static inline struct _inode *__shadow_copy_inode(struct inode *inode,
						 struct _inode *_inode,
						 struct transactional_object *xobj,
						 enum access_mode mode,
						 int noabort,
						 int task_count, 
						 int need_mutex){
 	void * shadow_parent;
	struct _inode *shadow_inode;

	KSTM_BUG_ON(mode == ACCESS_R);

	//alloc a shadow inode
	//this can be executed in interrupt context
	//due to prepare_tx_write() in do_no_page()
	shadow_parent = unlikely(in_atomic())?
		alloc_tx_inode_atomic(_inode->source, _inode->i_parent_size):
		alloc_tx_inode(_inode->source, _inode->i_parent_size);
	
	if(!shadow_parent)
	   goto tx_cache_get_inode_fail1;

	/* Pointer acrobatics to get the offset of the inode in the
	 * bigger struct 
	 */
	shadow_inode = get_inode_from_parent(_inode, shadow_parent);

	if(task_count == 1){
		need_mutex = 1 - inode_mutex_locked(&inode->i_mutex);
		if(lock_my_inode(inode, need_mutex, 0)){
			/* Put back the new allocations */
			shadow_inode->source = _inode->source;
			shadow_inode->i_parent = shadow_parent;
			__free_tx_inode(shadow_inode);
			LOCK_XOBJ(xobj);
			remove_xnode_reference(current->transaction, xobj);
			UNLOCK_XOBJ(xobj);
			if(noabort)
				return ERR_PTR(-ETXABORT);
			abort_self(NULL, 0);
		}
	}

	memcpy(shadow_parent, _inode->i_parent, _inode->i_parent_size);

	shadow_inode->i_parent = shadow_parent;

	atomic_set(&shadow_inode->tx_refcount, 1);

	if(task_count == 1)
		unlock_my_inode(inode, need_mutex, 0);

	KSTM_BUG_ON(shadow_inode->i_op == NULL);

	shadow_inode->shadow = _inode;
	shadow_inode->rw = mode;

	/* Finish init'ing the shadow copy */
	//list_init_tx(&shadow_inode->i_dentry, mode);
	if(shadow_inode->i_op->init_tx)
		shadow_inode->i_op->init_tx(shadow_inode, mode);

	OSA_PROTECT_ADDR(inode, sizeof(struct inode));

	return shadow_inode;

 tx_cache_get_inode_fail1:
	BUG();
	return ERR_PTR(-ETXABORT);
}

struct _inode * __tx_cache_get_inode(struct inode * inode,
		enum access_mode mode, int noabort) {

	txobj_thread_list_node_t * list_node = NULL;
	struct _inode *_inode;
	struct _inode * shadow_inode = ERR_PTR(-ETXABORT);
	int task_count = atomic_read(&current->transaction->task_count);
	int should_sleep = 0;
	struct transaction *winner;
	int need_mutex;

#ifdef CONFIG_TX_KSTM_PROF
	unsigned long long cycles, a;
	rdtscll(cycles);
#endif
#ifdef CONFIG_TX_KSTM_ASSERTIONS
	struct _inode * checkpoint_inode = NULL;
	BUG_ON(inode == NULL);
#endif

	/* Protect the read with an rcu read lock */
	rcu_read_lock();
 	_inode = inode->i_contents;
	rcu_read_unlock();

	KSTM_BUG_ON(_inode == NULL);
	KSTM_BUG_ON(shadow(_inode));

	/* We should never get a speculative inode in the lock or new state */
	KSTM_BUG_ON(inode->i_state & I_NEW);

	/* Next, make sure we don't already have the object */
	list_node = workset_has_object(&inode->xobj);

	/* If single-proc tx, defer this, as it is a bit expensive */
	if(task_count > 1){
		need_mutex = 1 - inode_mutex_locked(&inode->i_mutex);
		if(lock_my_inode(inode, need_mutex, 1))
			abort_self(NULL, 0);		
		if(!list_node)
			list_node = workset_has_object_locked(&inode->xobj);
	} else
		need_mutex = 1; // shut up the compiler - it will be properly set in __shadow_copy if needed

	if(list_node) {
		shadow_inode = list_node->shadow_obj;
		if(list_node->rw < mode){
			struct _inode *old_shadow_inode;
			/* Upgrade the mode */
			if(task_count == 1)
				LOCK_XOBJ(&inode->xobj);
			winner = 
				upgrade_xobj_mode(list_node->tx_obj, mode, &should_sleep);
			if(winner){
				if(!should_sleep)
					winner = NULL;
					
				if(task_count == 1)
					UNLOCK_XOBJ(&inode->xobj);
				else
					unlock_my_inode(inode, need_mutex, 1);
				abort_self(winner, 0);
			} 
			list_node->rw = mode;
			if(task_count == 1)
				UNLOCK_XOBJ(&inode->xobj);

			/* the object is read-shared and we must copy it */
			old_shadow_inode = shadow_inode;
			shadow_inode = __shadow_copy_inode(inode, _inode,
							   &inode->xobj, mode, noabort, 
							   task_count, need_mutex);
			if(unlikely(IS_ERR(shadow_inode))){
				if(task_count > 1)
					unlock_my_inode(inode, need_mutex, 1);
				goto out;
			}
			
			list_node->rw = mode;
			list_node->shadow_obj = shadow_inode;

			atomic_dec(&old_shadow_inode->tx_readcount);
			if(inode->i_contents == old_shadow_inode)
				atomic_dec(&old_shadow_inode->tx_refcount);
			else 
				free_tx_inode(old_shadow_inode);
		}  
		if(task_count > 1)
			unlock_my_inode(inode, need_mutex, 1);
		goto out;
	}

	/* At this point, we definitely don't have the object.  Add
	 * it!
	 */
	
	/* We need to lock the inode here and then retain the xobj
	 * lock until were done checkpointing 
	 */
	
	if(task_count == 1)
		LOCK_XOBJ(&inode->xobj);
	list_node = tx_check_add_obj(&inode->xobj, TYPE_INODE, mode, &should_sleep, &winner);

	if(unlikely(!list_node)){
		if(!should_sleep)
			winner = NULL;

		if(task_count > 1)
			unlock_my_inode(inode, need_mutex, 1);
		else
			UNLOCK_XOBJ(&inode->xobj);
		abort_self(winner, 0);
	}
	
	if(task_count == 1)
		UNLOCK_XOBJ(&inode->xobj);

	/* Go ahead an increment the refcount so we don't get freed */
	tx_atomic_inc_nolog(&inode->i_count);

	// Allocate the shadow copy and update the local workset

	if(mode == ACCESS_R){
		// Share it
		shadow_inode = _inode;
		atomic_inc(&_inode->tx_refcount);
		atomic_inc(&_inode->tx_readcount);
	} else {
		// Get our own
		shadow_inode = __shadow_copy_inode(inode, _inode, 
						   &inode->xobj, mode, noabort,
						   task_count, need_mutex);
		if(unlikely(IS_ERR(shadow_inode)))
			goto out;
	}

#ifdef CONFIG_TX_KSTM_ASSERTIONS
	/* Assume _inode won't change again without us getting aborted
	 * at this point.  
	 */
	checkpoint_inode = __checkpoint_inode(_inode);
	if(unlikely(checkpoint_inode == NULL)){
		if(shadow_inode != _inode)
			__free_tx_inode(shadow_inode);
		shadow_inode = ERR_PTR(-ETXABORT);
		goto out;
	}
#endif

	if(unlikely(__setup_list_node(list_node, inode, shadow_inode, 
#ifdef CONFIG_TX_KSTM_ASSERTIONS
				      checkpoint_inode,
#endif				     
				      mode, &inode->xobj))){
		shadow_inode = ERR_PTR(-ETXABORT);
		goto out;
	}
	

	if(shadow_inode->i_op->init_tx)
		shadow_inode->i_op->init_tx(shadow_inode, mode);
	
	if(task_count > 1)
		unlock_my_inode(inode, need_mutex, 1);
out:
#ifdef CONFIG_TX_KSTM_PROF
	rdtscll(a);
	shadowCopyCycles += (a - cycles);
#endif	
	if (!noabort && ERR_PTR(-ETXABORT) == shadow_inode)
		abort_self(NULL, 0);

	return shadow_inode;
}

void * tx_cache_get_inode_void(void *in, enum access_mode mode){
	struct _inode *_inode = (struct _inode *)in;
	return (void*) _tx_cache_get_inode(parent(_inode), mode, 0);
}

void replace_inode_notx(struct transactional_object *xobj){
	struct inode *inode = container_of(xobj, struct inode, xobj);
	struct _inode *_inode = inode->i_contents;
	struct _inode *_new_inode;

	// i_contents are locked already - protected by XOBJ lock for now
	
//	OSA_MAGIC(OSA_BREAKSIM);

	// Allocate a copy
	void *new_inode = alloc_tx_inode_atomic(_inode->source, _inode->i_parent_size);
	memcpy(new_inode, _inode->i_parent, _inode->i_parent_size);

	_new_inode = get_inode_from_parent(_inode, new_inode);
	_new_inode->i_parent = new_inode;
	
	atomic_set(&_new_inode->tx_refcount, 0);
	atomic_set(&_new_inode->tx_readcount, 0);
	//list_commit_tx(&_new_inode->i_dentry, 1);
	if(_new_inode->i_op->commit)
		_new_inode->i_op->commit(_new_inode, ACCESS_RW, 0);

	// Replace pointer
	inode->i_contents = _new_inode;
}

#endif //CONFIG_TX_KSTM

EXPORT_SYMBOL(__tx_cache_get_inode);
