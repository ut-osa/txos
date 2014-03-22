#include <linux/fs.h>
#include <linux/transaction.h>
#include <linux/tx_file.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <asm/uaccess.h>
#include <linux/fsnotify.h>
#include <linux/tx_dentry.h>

#ifdef CONFIG_TX_KSTM

#define __alloc_tx_file(flags) kmem_cache_alloc(_filp_cachep, flags)
#define alloc_tx_file() __alloc_tx_file(GFP_KERNEL)
#define alloc_tx_file_atomic() __alloc_tx_file(GFP_ATOMIC)

#define __free_tx_file(file) kmem_cache_free(_filp_cachep, file)

static void free_tx_file_callback(struct rcu_head * head){
	struct _file *_file = container_of(head, struct _file, _f_rcu);
	__free_tx_file(_file);
}

static inline void free_tx_file(struct _file *_file){
	if(atomic_dec_return(&_file->tx_refcount) <= 0)
		call_rcu(&_file->_f_rcu, free_tx_file_callback);
}


int lock_file(struct txobj_thread_list_node * xnode, int blocking){

	struct file * file = (struct file *) xnode->orig_obj;
	if(!blocking)
		spin_lock(&file->f_ep_lock);
	return 0;
}

int unlock_file(struct txobj_thread_list_node * xnode, int blocking){

	struct file * file = (struct file *) xnode->orig_obj;
	if (!blocking) 
		spin_unlock(&file->f_ep_lock);

	return 0;
}


/* Do the cleanup/freeing work */
int release_file(struct txobj_thread_list_node * xnode, int early){
	struct file * file = (struct file *)xnode->orig_obj;

#ifdef CONFIG_TX_KSTM_ASSERTIONS
	__free_tx_file((struct _file *)xnode->checkpoint_obj);
#endif

	// drop the transaction's reference
	if(early)
		tx_atomic_dec_nolog(&file->f_count);
	else
		fput(file);

	return 0;
}


int abort_file(struct txobj_thread_list_node * xnode){
	struct _file * shadow = (struct _file *)xnode->shadow_obj;

	if(xnode->rw == ACCESS_R){
		atomic_dec(&shadow->tx_readcount);
		atomic_dec(&shadow->tx_refcount);
	} else 
		free_tx_file(shadow);

	return 0;
}


int commit_file(struct txobj_thread_list_node * xnode){
				
	struct file * orig = (struct file *)xnode->orig_obj;
	struct _file * shadow = (struct _file *)xnode->shadow_obj;

	KSTM_BUG_ON(orig->tx_alloc && xnode->rw == ACCESS_R);

	orig->tx_alloc = 0;

	if(xnode->rw == ACCESS_RW){
		struct _file *old_file = orig->f_contents;

		shadow->shadow = NULL;
		shadow->rw = ACCESS_R;

		orig->f_contents = shadow;

		free_tx_file(old_file);

	} else {
		atomic_dec(&shadow->tx_readcount);
	}
	atomic_dec(&shadow->tx_refcount);

	return 0;
}

#ifdef CONFIG_TX_KSTM_ASSERTIONS
int validate_file(struct txobj_thread_list_node * xnode){
				
	struct _file * orig = ((struct file *) xnode->orig_obj)->f_contents;
	struct _file * checkpoint = (struct _file *)xnode->checkpoint_obj;
	struct _file * shadow = (struct _file *)xnode->shadow_obj;

	TX_VALIDATE(orig, checkpoint, f_path.dentry);
	TX_VALIDATE(orig, checkpoint, f_path.mnt);

	TX_VALIDATE(orig, checkpoint, f_flags);
	TX_VALIDATE(orig, checkpoint, f_mode);
	TX_VALIDATE(orig, checkpoint, f_pos);

	TX_VALIDATE(orig, checkpoint, f_uid);
	TX_VALIDATE(orig, checkpoint, f_gid);

	TX_VALIDATE(orig, checkpoint, f_version);

#ifdef CONFIG_SECURITY
	TX_VALIDATE(orig, checkpoint, f_security);
#endif

	/* Even heavier validation for R-only objects */
	if(xnode->rw == ACCESS_R){

		TX_VALIDATE(orig, shadow, f_dentry);		
		if(orig->f_vfsmnt != shadow->f_vfsmnt)
			KSTM_BUG_ON(shadow->f_vfsmnt->shadow != orig->f_vfsmnt);

		TX_VALIDATE(orig, shadow, f_flags);
		TX_VALIDATE(orig, shadow, f_mode);
		TX_VALIDATE(orig, shadow, f_pos);


		TX_VALIDATE(orig, shadow, f_uid);
		TX_VALIDATE(orig, shadow, f_gid);

		TX_VALIDATE(orig, shadow, f_version);

#ifdef CONFIG_SECURITY
		TX_VALIDATE(orig, shadow, f_security);
#endif
	}

	return 0;
}

static inline struct _file *__checkpoint_file(struct _file *_file){

	struct _file *checkpoint;
	checkpoint = alloc_tx_file();
	if(!checkpoint)
		return NULL;

	memcpy(checkpoint, _file, sizeof(struct _file));
	atomic_set(&checkpoint->tx_refcount, 1);
	return checkpoint;

}
#else
#define checkpoint_file(_file)
#endif // CONFIG_TX_KSTM_ASSERTIONS


static inline int __setup_list_node( txobj_thread_list_node_t *list_node,
				     struct file *file,
				     struct _file *shadow_file,
#ifdef CONFIG_TX_KSTM_ASSERTIONS
				     struct _file *checkpoint_file,
#endif
				     enum access_mode mode,
				     struct transactional_object *xobj){

	list_node->type = TYPE_FILE;
	list_node->shadow_obj = shadow_file;
	list_node->orig_obj = file;
	list_node->rw = mode;
	list_node->lock = lock_file;
	list_node->unlock = unlock_file;
	list_node->commit = commit_file;
	list_node->abort  = abort_file;
	list_node->release = release_file;
	INIT_LIST_HEAD(&list_node->deferred_operations);
	list_node->tx_obj = xobj;

#ifdef CONFIG_TX_KSTM_ASSERTIONS
	list_node->checkpoint_obj = checkpoint_file;
	list_node->validate = validate_file;
#endif
	workset_add(list_node,
		 &(current->transaction->object_list));

	return 0;
}


static inline struct _file *__shadow_copy_file(struct file *file,
					       struct _file *_file,
					       enum access_mode mode){
	struct _file *shadow_file;

	KSTM_BUG_ON(mode == ACCESS_R);

	//alloc a shadow file
	shadow_file = alloc_tx_file();
	if(!shadow_file)
		BUG(); /* Should probably call abort_self */

	/* Go ahead and increment the refcount so we don't get freed.
	 * If we try to add something that is being actively deleted
	 * out from under us, just abort
	 */
	memcpy(shadow_file, _file, sizeof(struct _file));
	atomic_set(&shadow_file->tx_refcount, 1);

	shadow_file->shadow = _file;
	shadow_file->rw = mode;

	OSA_PROTECT_ADDR(file, sizeof(struct _file));

	return shadow_file;
}

struct _file * __tx_cache_get_file(struct file * file, enum access_mode mode){

	txobj_thread_list_node_t * list_node = NULL;
	struct _file * shadow, *_file;
	int task_count = atomic_read(&current->transaction->task_count);
	int should_sleep = 0;
	struct transaction *winner;


#ifdef CONFIG_TX_KSTM_PROF
	unsigned long long cycles, a;
	rdtscll(cycles);
#endif
#ifdef CONFIG_TX_KSTM_ASSERTIONS
 	struct _file * checkpoint;
	BUG_ON(file == NULL);
#endif

	/* Protect the read with an rcu read lock */
	rcu_read_lock();
 	_file = file->f_contents;
	rcu_read_unlock();


	/* Next, make sure we don't already have the object */
	list_node = workset_has_object(&file->xobj);
	
	if(list_node) {
		if(task_count > 1)
			LOCK_XOBJ(&file->xobj);
	workset_hit:
		shadow = list_node->shadow_obj;
		if(list_node->rw < mode){
			struct _file *old_shadow;
	
			/* Upgrade the mode */
			if(task_count == 1)
				LOCK_XOBJ(&file->xobj);
			winner = 
				upgrade_xobj_mode(list_node->tx_obj, mode, &should_sleep);
			if(winner){
				if(!should_sleep)
					winner = NULL;
					
				UNLOCK_XOBJ(&file->xobj);
				abort_self(winner, 0);
			} 
			list_node->rw = mode;
			if(task_count == 1)
				UNLOCK_XOBJ(&file->xobj);

			/* the object is read-shared and we must copy it */
			old_shadow = shadow;
			shadow = __shadow_copy_file(file, _file,
						    mode);

			if(unlikely(IS_ERR(shadow))){
				if(task_count > 1)
					UNLOCK_XOBJ(&file->xobj);
				goto out;
			}

			list_node->rw = mode;
			list_node->shadow_obj = shadow;

			atomic_dec(&old_shadow->tx_readcount);
			if(file->f_contents == old_shadow)
				atomic_dec(&old_shadow->tx_refcount);
			else 
				free_tx_file(old_shadow);
		}  
		if(task_count > 1)
			UNLOCK_XOBJ(&file->xobj);
		goto out;
	}

	/* At this point, we definitely don't have the object.  Add
	 * it!
	 */
	LOCK_XOBJ(&file->xobj);
	if(task_count > 1){
		/* Recheck that another task didn't add the object */
		if((list_node = workset_has_object_locked(&file->xobj)))
			goto workset_hit;
	}


	list_node = tx_check_add_obj(&file->xobj, TYPE_FILE, mode, &should_sleep, &winner);

	if(unlikely(!list_node)){
		if(!should_sleep)
			winner = NULL;
		UNLOCK_XOBJ(&file->xobj);
		abort_self(winner, 0);
	}
	if(task_count == 1)
		UNLOCK_XOBJ(&file->xobj);
	
	/* Go ahead an increment the refcount so we don't get freed */
	tx_atomic_inc_nolog(&file->f_count);

	// Allocate the shadow copy and update the local workset

	if(mode == ACCESS_R){
		// Share it
		shadow = _file;
		atomic_inc(&_file->tx_refcount);
		atomic_inc(&_file->tx_readcount);
	} else {
		// Get our own
		shadow = __shadow_copy_file(file, _file, 
					    mode);
		if(unlikely(IS_ERR(shadow)))
			goto out;
	}
	

#ifdef CONFIG_TX_KSTM_ASSERTIONS
	checkpoint = __checkpoint_file(_file);
	if(unlikely(checkpoint == NULL)){
		if(shadow != _file)
			__free_tx_file(shadow);
		shadow = ERR_PTR(-ETXABORT);
		goto out;
	}
#endif

	if(unlikely(__setup_list_node(list_node, file, shadow, 
#ifdef CONFIG_TX_KSTM_ASSERTIONS
				      checkpoint,
#endif				     
				      mode, &file->xobj)))
		shadow = ERR_PTR(-ETXABORT);
	
	if(task_count > 1)
		UNLOCK_XOBJ(&file->xobj);

out:
#ifdef CONFIG_TX_KSTM_PROF
	rdtscll(a);
	shadowCopyCycles += (a - cycles);
#endif	

	return shadow;
}

EXPORT_SYMBOL(__tx_cache_get_file);

void * tx_cache_get_file_void(void *in, enum access_mode mode){
	return (void*) __tx_cache_get_file((struct file *) in, mode);
}

/* When we're transactional, we need to maintain a copy of fs when
 * modifying it. This can be tricky since fs may be shared after
 * a clone() with the CLONE_FS flag set. We'll ignore that case for now.
 */
struct fs_struct * tx_cache_get_fs(struct task_struct *t) {
	if (atomic_read(&t->transaction->status) != TX_INACTIVE) {
		tx_chkpt_task_fields(t);
		//printk(KERN_ERR "in tx_cache_get_fs!\n");
		if (atomic_read(&t->fs->count) > 1) {
			//we have a problem. Shame on you for trying to write 
			//transactionally to a shared structure!
			BUG();
		} else if (t->cp->fs == t->fs || t->cp->fs == NULL) {
			t->cp->fs = t->fs;
			t->fs = copy_fs_struct(t->cp->fs);
		}
		//printk(KERN_ERR "eager fsptr=%x stable fsptr=%x\n",
		//       t->fs, t->cp->fs);
		BUG_ON(unlikely(t->fs == NULL));
	}
	return t->fs;
}

void tx_commit_fs(struct task_struct *tsk) {
	if (tsk->cp->fs != NULL && tsk->cp->fs != tsk->fs) {
		write_lock(&tsk->cp->fs->lock);
		if (atomic_read(&tsk->cp->fs->count) > 1) {
			//we'll just steamroller over effects of other process
			//since this shouldn't happen anyway    
			tsk->cp->fs->umask = tsk->fs->umask;
			tsk->cp->fs->root = tsk->fs->root;
			tsk->cp->fs->pwd = tsk->fs->pwd;
			tsk->cp->fs->altroot = tsk->fs->altroot;
			tsk->cp->fs->rootmnt = tsk->fs->rootmnt;
			tsk->cp->fs->pwdmnt = tsk->fs->pwdmnt;
			tsk->cp->fs->altrootmnt = tsk->fs->altrootmnt;
			write_unlock(&tsk->cp->fs->lock);
			BUG_ON(atomic_read(&tsk->fs->count) > 1);
			put_fs_struct(tsk->fs);
			tsk->fs = tsk->cp->fs;
		} else {
			//just need to keep eagerly written values!
			write_unlock(&tsk->cp->fs->lock);
			put_fs_struct(tsk->cp->fs);
		}
	}
}

void tx_rollback_fs(struct task_struct *tsk) {
	if (current->fs != current->cp->fs &&
	    current->cp->fs != NULL){
		BUG_ON(atomic_read(&current->fs->count) > 1);
		//we do not use put_fs_struct since all         
		//the actions of dget and mntget are already    
		//rolled back                                   
		kmem_cache_free(fs_cachep, current->fs);
	}
}

#else

struct fs_struct * tx_cache_get_fs(struct task_struct *t) {
  return t->fs;
}

#endif //CONFIG_TX_KSTM
