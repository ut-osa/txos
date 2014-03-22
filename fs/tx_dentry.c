#include <linux/transaction.h>
#include <linux/tx_dentry.h>
#include <linux/mm.h>
#include <linux/osamagic.h>
#include <linux/pipe_fs_i.h>
#include <linux/err.h>
#include <linux/writeback.h>
#include <linux/module.h>

#ifdef CONFIG_TX_KSTM

#define __alloc_tx_dentry(flags) kmem_cache_alloc(_dentry_cache, flags)
#define alloc_tx_dentry() __alloc_tx_dentry(GFP_KERNEL)
#define alloc_tx_dentry_atomic() __alloc_tx_dentry(GFP_ATOMIC)

#define __free_tx_dentry(dentry) kmem_cache_free(_dentry_cache, dentry)

static void free_tx_dentry_callback(struct rcu_head * head){
	struct _dentry *_dentry = container_of(head, struct _dentry, _d_rcu);
	__free_tx_dentry(_dentry);
}

static inline void free_tx_dentry(struct _dentry *_dentry){
	if(atomic_dec_return(&_dentry->tx_refcount) <= 0)
		call_rcu(&_dentry->_d_rcu, free_tx_dentry_callback);
}

int lock_dentry(struct txobj_thread_list_node * xnode, int blocking){

	struct dentry * dentry = (struct dentry *) xnode->orig_obj;
	if(!blocking)
		spin_lock(&dentry->d_lock);
	return 0;
}

int unlock_dentry(struct txobj_thread_list_node * xnode, int blocking){

	struct dentry * dentry = (struct dentry *) xnode->orig_obj;
	if(!blocking)
		spin_unlock(&dentry->d_lock);
	return 0;
}

/* Do the cleanup/freeing work */
int release_dentry(struct txobj_thread_list_node * xnode, int early){

	struct dentry *dentry = (struct dentry*) xnode->orig_obj;

	// Account for the dropped inode reference here
	if(unlikely(dentry->d_contents->d_flags & DCACHE_SPECULATIVE_CREATE)){
		KSTM_BUG_ON(atomic_read(&dentry->d_count) > 2);
		tx_atomic_add_unless(&dentry->d_count, -1, 1);
	}
				
#ifdef CONFIG_TX_KSTM_ASSERTIONS
	free_tx_dentry((struct _dentry *)xnode->checkpoint_obj);
#endif
	
        // release the transaction's reference
	dput((struct dentry *)xnode->orig_obj);

	return 0;
}


int abort_dentry(struct txobj_thread_list_node * xnode){
				
	struct dentry * orig = (struct dentry *)xnode->orig_obj;
	struct _dentry * shadow = (struct _dentry *)xnode->shadow_obj;

	if(xnode->rw == ACCESS_R){
		atomic_dec(&shadow->tx_readcount);
		atomic_dec(&shadow->tx_refcount);
	} else {
		if((shadow->d_flags & DCACHE_SPECULATIVE_CREATE)){
			struct _dentry *old_dentry = orig->d_contents;

			/* Free up the speculatively created inode reference to force deletion */
			tx_atomic_dec(&shadow->d_inode->i_count);
			tx_cache_get_inode(shadow->d_inode)->i_nlink--;
			free_tx_dentry(shadow);

			/* Use this as a signal to release_dentry */
			old_dentry->d_flags |= DCACHE_SPECULATIVE_CREATE;
			
			/* We also need the dentry to be negative */
			KSTM_BUG_ON(old_dentry->d_inode != NULL);

			/* And hack to avoid messing up the parent
			 * dentry's refcount when we put, as we will
			 * rollback the refcount increase elsewhere
			 */
			tx_atomic_inc(&old_dentry->d_parent->d_count);

		} else
			free_tx_dentry(shadow);
	}

	return 0;
}


int commit_dentry(struct txobj_thread_list_node * xnode){
				
	struct dentry * dentry = (struct dentry *)xnode->orig_obj;
	struct _dentry * shadow = (struct _dentry *)xnode->shadow_obj;

	if(xnode->rw == ACCESS_RW){
		struct _dentry *old_dentry = dentry->d_contents;

		// Commit the lists
		//list_commit_tx(&shadow->d_subdirs, 1);
		//list_commit_tx(&shadow->d_child, 1);
		//list_commit_tx(&shadow->d_alias, 1);
		//hlist_commit_tx(&shadow->d_hash, 1);

		shadow->shadow = NULL;
		shadow->rw = ACCESS_R;

		shadow->d_flags &= ~DCACHE_SPECULATIVE_CREATE;
		
		dentry->d_contents = shadow;
		
		free_tx_dentry(old_dentry);

	} else {
		atomic_dec(&shadow->tx_readcount);
	}
	atomic_dec(&shadow->tx_refcount);

	return 0;
}

#ifdef CONFIG_TX_KSTM_ASSERTIONS
int validate_dentry(struct txobj_thread_list_node * xnode){
				
	struct _dentry * orig = ((struct dentry *)xnode->orig_obj)->d_contents;
	struct _dentry *checkpoint = xnode->checkpoint_obj;
	struct _dentry *shadow = xnode->shadow_obj;

	// Don't bother validating this
	//TX_VALIDATE_ATOMIC(orig, checkpoint, d_count);

	TX_VALIDATE(orig, checkpoint, d_flags);

	// Make sure this hasn't changed.  We don't update this,
	// though, as we are going to have the shadow copy point to
	// the shadow inode
	TX_VALIDATE(orig, checkpoint, d_inode);


	// Ignore d_hash - only used in non-speculative copy
	//hlist_validate_tx(&orig->d_hash, &checkpoint->d_hash);

	TX_VALIDATE(orig, checkpoint, d_parent);

	TX_VALIDATE(orig, checkpoint, d_name.hash);
	TX_VALIDATE(orig, checkpoint, d_name.len);
	TX_VALIDATE(orig, checkpoint, d_name.name);

	// Check the child 
	//list_validate_tx(&orig->d_subdirs, &checkpoint->d_subdirs);
	//list_validate_tx(&orig->d_child, &checkpoint->d_child);
	//list_validate_tx(&orig->d_alias, &checkpoint->d_alias);

	TX_VALIDATE(orig, checkpoint, d_time);
	TX_VALIDATE(orig, checkpoint, d_op);
#ifdef CONFIG_PROFILING
	TX_VALIDATE(orig, checkpoint, d_cookie);
#endif

	if(strncmp(orig->d_iname, checkpoint->d_iname, DNAME_INLINE_LEN_MIN) != 0){
		printk(KERN_ERR "Inconsistent value for %p\n", &orig->d_iname);
		BUG();
	}

	/* Also validate the shadow */
	if(xnode->rw == ACCESS_R){

		TX_VALIDATE(orig, shadow, d_flags);

		if(orig->d_inode != shadow->d_inode)
			KSTM_BUG_ON(orig->d_inode != shadow->d_inode);
			//KSTM_BUG_ON(orig->d_inode != shadow(shadow->d_inode));

		// Ignore d_hash - only used in non-speculative copy
		//hlist_validate_tx_ro(&orig->d_hash, &shadow->d_hash);

		TX_VALIDATE(orig, shadow, d_parent);
		TX_VALIDATE(orig, shadow, d_name.hash);
		TX_VALIDATE(orig, shadow, d_name.len);

		if(shadow->d_name.name == shadow->d_iname)
			KSTM_BUG_ON(orig->d_name.name != orig->d_iname);
		else
			TX_VALIDATE(orig, shadow, d_name.name);

		// Check the child 
		//list_validate_tx_ro(&orig->d_subdirs, &shadow->d_subdirs);
		//list_validate_tx_ro(&orig->d_child, &shadow->d_child);
		//list_validate_tx_ro(&orig->d_alias, &shadow->d_alias);

		TX_VALIDATE(orig, shadow, d_time);
		TX_VALIDATE(orig, shadow, d_op);
#ifdef CONFIG_PROFILING
		TX_VALIDATE(orig, shadow, d_cookie);
#endif

		if(strncmp(orig->d_iname, shadow->d_iname, DNAME_INLINE_LEN_MIN) != 0){
			printk(KERN_ERR "Inconsistent value for %p\n", &orig->d_iname);
			BUG();
		}
	}

	return 0;
}

static inline struct _dentry *__checkpoint_dentry(struct _dentry *_dentry){

	struct _dentry *checkpoint;
	checkpoint = alloc_tx_dentry();
	if(!checkpoint)
		return NULL;

	memcpy(checkpoint, _dentry, sizeof(struct _dentry));
	atomic_set(&checkpoint->tx_refcount, 1);
	return checkpoint;

}
#else
#define checkpoint_dentry(_dentry)

#endif // CONFIG_TX_KSTM_ASSERTIONS

static inline int __setup_list_node( txobj_thread_list_node_t *list_node,
				     struct dentry *dentry,
				     struct _dentry *shadow_dentry,
#ifdef CONFIG_TX_KSTM_ASSERTIONS
				     struct _dentry *checkpoint_dentry,
#endif
				     enum access_mode mode,
				     struct transactional_object *xobj){

	list_node->type = TYPE_DENTRY;
	list_node->shadow_obj = shadow_dentry;
	list_node->orig_obj = dentry;
	list_node->rw = mode;
	list_node->lock = lock_dentry;
	list_node->unlock = unlock_dentry;
	list_node->commit = commit_dentry;
	list_node->abort  = abort_dentry;
	list_node->release = release_dentry;
	list_node->tx_obj = xobj;

#ifdef CONFIG_TX_KSTM_ASSERTIONS
	list_node->checkpoint_obj = checkpoint_dentry;
	list_node->validate = validate_dentry;
#endif
	workset_add(list_node,
		    &(current->transaction->object_list));

	return 0;
}

static inline void lock_my_dentry(struct dentry *dentry, int multi_proc){
	spin_lock(&dentry->d_lock);
	if(multi_proc)
		LOCK_XOBJ(&dentry->xobj);
}

static inline void unlock_my_dentry(struct dentry *dentry, int multi_proc){
	if(multi_proc)
		UNLOCK_XOBJ(&dentry->xobj);

	spin_unlock(&dentry->d_lock);
}

static inline struct _dentry *__shadow_copy_dentry(struct dentry *dentry,
						   struct _dentry *_dentry,
						   enum access_mode mode,
						   int task_count){
	struct _dentry *shadow_dentry;

	KSTM_BUG_ON(mode == ACCESS_R);

	//alloc a shadow dentry
	shadow_dentry = alloc_tx_dentry();
	if(!shadow_dentry)
		BUG(); /* Should probably call abort_self */

	if(task_count == 1)
		lock_my_dentry(dentry, 0);

	/* Go ahead and increment the refcount so we don't get freed.
	 * If we try to add something that is being actively deleted
	 * out from under us, just abort
	 */
	memcpy(shadow_dentry, _dentry, sizeof(struct _dentry));
	atomic_set(&shadow_dentry->tx_refcount, 1);

	if(task_count == 1)
		unlock_my_dentry(dentry, 0);

	shadow_dentry->shadow = _dentry;
	shadow_dentry->rw = mode;

	/* Fix up the d_name.name pointer */
	if(_dentry->d_iname == _dentry->d_name.name)
		shadow_dentry->d_name.name = shadow_dentry->d_iname;

	/* Finish init'ing the shadow copy */
	//list_init_tx(&shadow_dentry->d_subdirs, mode);
	//list_init_tx(&shadow_dentry->d_child, mode);
	//list_init_tx(&shadow_dentry->d_alias, mode);
	//hlist_init_tx(&shadow_dentry->d_hash, mode);

	OSA_PROTECT_ADDR(dentry, sizeof(struct _dentry));

	return shadow_dentry;
}


struct _dentry * __tx_cache_get_dentry(struct dentry * dentry, enum access_mode mode){

	txobj_thread_list_node_t * list_node = NULL;
	struct _dentry *_dentry;
	struct _dentry *shadow;
	int task_count = atomic_read(&current->transaction->task_count);
	int should_sleep = 0;
	struct transaction *winner;

#ifdef CONFIG_TX_KSTM_PROF
	unsigned long long cycles, a;
	rdtscll(cycles);
#endif
#ifdef CONFIG_TX_KSTM_ASSERTIONS
 	struct _dentry * checkpoint;
	BUG_ON(dentry == NULL);
#endif

	/* Protect the read with an rcu read lock */
	rcu_read_lock();
 	_dentry = dentry->d_contents;
	rcu_read_unlock();

	KSTM_BUG_ON(_dentry == NULL);
	KSTM_BUG_ON(shadow(_dentry));

	/* Next, make sure we don't already have the object */
	list_node = workset_has_object(&dentry->xobj);

	if(list_node) {
		if(task_count > 1)
			lock_my_dentry(dentry, 1);
	workset_hit:
		shadow = list_node->shadow_obj;
		if(list_node->rw < mode){
			struct _dentry *old_shadow;
			
			/* Upgrade the mode */
			if(task_count == 1)
				LOCK_XOBJ(&dentry->xobj);
			winner = 
				upgrade_xobj_mode(list_node->tx_obj, mode, &should_sleep);
			if(winner){
				if(!should_sleep)
					winner = NULL;
					
				if(task_count == 1)
					UNLOCK_XOBJ(&dentry->xobj);
				else
					unlock_my_dentry(dentry, 1);
				abort_self(winner, 0);
			} 
			list_node->rw = mode;

			if(task_count == 1)
				UNLOCK_XOBJ(&dentry->xobj);

			/* the object is read-shared and we must copy it */
			old_shadow = shadow;
			shadow = __shadow_copy_dentry(dentry, _dentry,
						      mode, task_count);
			
			if(unlikely(IS_ERR(shadow))){
				if(task_count > 1)
					unlock_my_dentry(dentry, 1);
				goto out;
			}

			list_node->rw = mode;
			list_node->shadow_obj = shadow;

			atomic_dec(&old_shadow->tx_readcount);
			if(dentry->d_contents == old_shadow)
				atomic_dec(&old_shadow->tx_refcount);
			else 
				free_tx_dentry(old_shadow);
		}  
		if(task_count > 1)
			unlock_my_dentry(dentry, 1);
		goto out;
	}

	/* At this point, we definitely don't have the object.  Add
	 * it!
	 */
	if(task_count > 1){
		lock_my_dentry(dentry, 1);
		/* Recheck that another task didn't add the object */
		if((list_node = workset_has_object_locked(&dentry->xobj)))
			goto workset_hit;
	} else 
		LOCK_XOBJ(&dentry->xobj);
		
	list_node = tx_check_add_obj(&dentry->xobj, TYPE_DENTRY, mode, &should_sleep, &winner);

	if(unlikely(!list_node)){
		if(!should_sleep)
			winner = NULL;
		if(task_count > 1)
			unlock_my_dentry(dentry, 1);
		else 
			UNLOCK_XOBJ(&dentry->xobj);
		abort_self(winner, 0);
	}

	if(task_count == 1)
		UNLOCK_XOBJ(&dentry->xobj);


	/* Go ahead an increment the refcount so we don't get freed */
	tx_atomic_inc_nolog(&dentry->d_count);
	
	// Allocate the shadow copy and update the local workset

	if(mode == ACCESS_R){
		// Share it
		shadow = _dentry;

		//we'll ignore this bug for now:
		//if(atomic_read(&_dentry->tx_refcount) == 1)
		//	OSA_MAGIC(OSA_BREAKSIM);

		atomic_inc(&_dentry->tx_refcount);
		atomic_inc(&_dentry->tx_readcount);
	} else {
		// Get our own
		shadow = __shadow_copy_dentry(dentry, _dentry, 
					      mode, task_count);
		if(unlikely(IS_ERR(shadow)))
			goto out;
	}

#ifdef CONFIG_TX_KSTM_ASSERTIONS
	checkpoint = __checkpoint_dentry(_dentry);
	if(unlikely(checkpoint == NULL)){
		if(shadow != _dentry)
			__free_tx_dentry(shadow);
		shadow = ERR_PTR(-ETXABORT);
		goto out;
	}
#endif

	if(unlikely(__setup_list_node(list_node, dentry, shadow, 
#ifdef CONFIG_TX_KSTM_ASSERTIONS
				      checkpoint,
#endif				     
				      mode, &dentry->xobj)))
		shadow = ERR_PTR(-ETXABORT);

	if(task_count > 1)
		unlock_my_dentry(dentry, 1);
	
out:
#ifdef CONFIG_TX_KSTM_PROF
	rdtscll(a);
	shadowCopyCycles += (a - cycles);
#endif	
	
	return shadow;
}


void * tx_cache_get_dentry_void(void *in, enum access_mode mode){
	struct _dentry *_dentry = (struct _dentry *)in;
	return (void*) _tx_cache_get_dentry(parent(_dentry), mode);
}

void replace_dentry_notx(struct transactional_object *xobj){
	struct dentry *dentry = container_of(xobj, struct dentry, xobj);
	struct _dentry *_dentry = dentry->d_contents;
	struct _dentry *_new_dentry;

	// i_contents are locked already - protected by XOBJ lock for now
	
//	OSA_MAGIC(OSA_BREAKSIM);

	// Allocate a copy
	_new_dentry = alloc_tx_dentry_atomic();
	memcpy(_new_dentry, _dentry, sizeof(struct _dentry));

	/* Fix up the dname pointers */
	if(_dentry->d_iname == _dentry->d_name.name)
		_new_dentry->d_name.name = _new_dentry->d_iname;

	atomic_set(&_new_dentry->tx_refcount, 0);
	atomic_set(&_new_dentry->tx_readcount, 0);
	//list_commit_tx(&_new_dentry->d_subdirs, 1);
	//list_commit_tx(&_new_dentry->d_child, 1);
	//list_commit_tx(&_new_dentry->d_alias, 1);
	//hlist_commit_tx(&_new_dentry->d_hash, 1);

	// Replace pointer
	dentry->d_contents = _new_dentry;
}

EXPORT_SYMBOL(__tx_cache_get_dentry);

#endif //CONFIG_TX_KSTM

