#include <linux/transaction.h>
#include <linux/tx_super.h>
#include <linux/mm.h>
#include <linux/osamagic.h>
#include <linux/pipe_fs_i.h>
#include <linux/err.h>
#include <linux/writeback.h>
#include <linux/tx_pages.h>
#include <linux/ext3_fs_i.h>
#include <linux/ext3_fs_sb.h>
#include <linux/ext2_fs_sb.h>
#include <linux/proc_fs.h>
#include <linux/blkdev.h>
#include <linux/shmem_fs.h>

#ifdef CONFIG_TX_KSTM

#define __alloc_tx_super_block(flags) kmem_cache_alloc(_super_block_cache, flags)
#define alloc_tx_super_block() __alloc_tx_super_block(GFP_KERNEL)
#define alloc_tx_super_block_atomic() __alloc_tx_super_block(GFP_ATOMIC)

#define __free_tx_super_block(super_block) kmem_cache_free(_super_block_cache, super_block)

static void free_tx_super_block_callback(struct rcu_head * head){
	struct _super_block *_super_block = container_of(head, struct _super_block, s_rcu);
	__free_tx_super_block(_super_block);
}

static inline void free_tx_super_block(struct _super_block *_super_block){
	if(atomic_dec_return(&_super_block->tx_refcount) <= 0)
		call_rcu(&_super_block->s_rcu, free_tx_super_block_callback);
}


/* Don't think I need the sb mutex to commit */

int release_super_block(struct txobj_thread_list_node * xnode, int early){
	
	struct super_block *super_block = (struct super_block *)xnode->orig_obj;
#ifdef CONFIG_TX_KSTM_ASSERTIONS
	free_tx_super_block(xnode->checkpoint_obj);
#endif
	/* Put our reference */
	put_super(super_block);
	
	return 0;
}


int abort_super_block(struct txobj_thread_list_node * xnode){
				
	struct _super_block *shadow = (struct _super_block *)xnode->shadow_obj;
	if(xnode->rw == ACCESS_R){
		atomic_dec(&shadow->tx_readcount);
		atomic_dec(&shadow->tx_refcount);
	} else 
		free_tx_super_block(shadow);

	return 0;
}


int commit_super_block(struct txobj_thread_list_node * xnode){
				
	struct super_block * sb = (struct super_block *)xnode->orig_obj;
	struct _super_block *shadow = (struct _super_block *)xnode->shadow_obj;

	if(xnode->rw == ACCESS_RW){
		struct _super_block *old_sb = sb->s_contents;
		shadow->shadow = NULL;
		shadow->rw = ACCESS_R;

		sb->s_contents = shadow;

		free_tx_super_block(old_sb);

	} else {
		atomic_dec(&shadow->tx_readcount);
	}

	if(sb->s_op->commit)
		sb->s_op->commit(sb, shadow, xnode->rw);

	atomic_dec(&shadow->tx_refcount);

	return 0;
}

#ifdef CONFIG_TX_KSTM_ASSERTIONS
int validate_super_block(struct txobj_thread_list_node * xnode){
				
	struct super_block *super = (struct super_block *) xnode->orig_obj;
	struct _super_block * sb = super->s_contents;
	struct _super_block * checkpoint_sb = (struct _super_block *) xnode->checkpoint_obj;
	struct _super_block * shadow_sb = (struct _super_block *) xnode->shadow_obj;

	// Don't sweat s_dirt
	TX_VALIDATE(sb, checkpoint_sb, s_flags);
	TX_VALIDATE(sb, checkpoint_sb, s_fs_info);

	if(xnode->rw == ACCESS_R){
		TX_VALIDATE(sb, shadow_sb, s_flags);
		TX_VALIDATE(sb, shadow_sb, s_fs_info);
	}

	if(super->s_op->validate)
		super->s_op->validate(super, checkpoint_sb, shadow_sb, xnode->rw);

	return 0;
}

static inline struct _super_block *__checkpoint_super_block(struct _super_block *_super_block){

	struct _super_block *checkpoint;
	checkpoint = alloc_tx_super_block();
	if(!checkpoint)
		return NULL;

	memcpy(checkpoint, _super_block, sizeof(struct _super_block));
	atomic_set(&checkpoint->tx_refcount, 1);
	return checkpoint;

}
#else
#define checkpoint_super_block(_super_block)
#endif // CONFIG_TX_KSTM_ASSERTIONS

static inline int __setup_list_node( txobj_thread_list_node_t *list_node,
				     struct super_block *super_block,
				     struct _super_block *shadow_super_block,
#ifdef CONFIG_TX_KSTM_ASSERTIONS
				     struct _super_block *checkpoint_super_block,
#endif
				     enum access_mode mode,
				     struct transactional_object *xobj){

	list_node->type = TYPE_SUPER_BLOCK;
	list_node->shadow_obj = shadow_super_block;
	list_node->orig_obj = super_block;
	list_node->rw = mode;
	list_node->lock = NULL;
	list_node->unlock = NULL;
	list_node->commit = commit_super_block;
	list_node->abort  = abort_super_block;
	list_node->release = release_super_block;
	list_node->tx_obj = xobj;

#ifdef CONFIG_TX_KSTM_ASSERTIONS
	list_node->checkpoint_obj = checkpoint_super_block;
	list_node->validate = validate_super_block;
#endif
	workset_add(list_node,
		    &(current->transaction->object_list));

	return 0;
}

static inline void lock_my_super(struct super_block *super, int multi_proc){
	spin_lock(&sb_lock);
	if(multi_proc)
		LOCK_XOBJ(&super->xobj);
}

static inline void unlock_my_super(struct super_block *super, int multi_proc){
	if(multi_proc)
		UNLOCK_XOBJ(&super->xobj);

	spin_unlock(&sb_lock);
}


static inline struct _super_block *__shadow_copy_super_block(struct super_block *super_block,
							     struct _super_block *_super_block,
							     enum access_mode mode,
							     int task_count){
	struct _super_block *shadow_super_block;

	KSTM_BUG_ON(mode == ACCESS_R);

	//alloc a shadow super_block
	shadow_super_block = alloc_tx_super_block();
	if(!shadow_super_block)
		BUG(); /* Should probably call abort_self */

	if(task_count == 1)
		lock_my_super(super_block, 0);

	/* Go ahead and increment the refcount so we don't get freed.
	 * If we try to add something that is being actively deleted
	 * out from under us, just abort
	 */
	memcpy(shadow_super_block, _super_block, sizeof(struct _super_block));
	atomic_set(&shadow_super_block->tx_refcount, 1);

	if(task_count == 1)
		unlock_my_super(super_block, 0);

	shadow_super_block->shadow = _super_block;
	shadow_super_block->rw = mode;

	OSA_PROTECT_ADDR(super_block, sizeof(struct _super_block));

	return shadow_super_block;
}


struct _super_block * __tx_cache_get_super_block(struct super_block * super_block, enum access_mode mode){

	struct _super_block * shadow, *_super_block;
	txobj_thread_list_node_t * list_node = NULL;
	int task_count = atomic_read(&current->transaction->task_count);
	int should_sleep = 0;
	struct transaction *winner;

#ifdef CONFIG_TX_KSTM_PROF
	unsigned long long cycles, a;
#endif
#ifdef CONFIG_TX_KSTM_ASSERTIONS
	struct _super_block * checkpoint;
	BUG_ON(super_block == NULL);
#endif

	/* Protect the read with an rcu read lock */
	rcu_read_lock();
	_super_block = super_block->s_contents;
	rcu_read_unlock();

	KSTM_BUG_ON(_super_block == NULL);
	KSTM_BUG_ON(shadow(_super_block));

	/* Next, make sure we don't already have the object */
	list_node = workset_has_object(&super_block->xobj);

	if(list_node){
		if(task_count > 1)
			lock_my_super(super_block, 1);

	workset_hit:
		shadow = list_node->shadow_obj;
		if(list_node->rw < mode){
			struct _super_block *old_shadow;
			int should_sleep = 0;
			struct transaction *winner;

			/* Upgrade the mode */
			if(task_count == 1)
				LOCK_XOBJ(&super_block->xobj);
			winner = 
				upgrade_xobj_mode(list_node->tx_obj, mode, &should_sleep);
			if(winner){
				if(!should_sleep)
					winner = NULL;

				if(task_count == 1)
					UNLOCK_XOBJ(&super_block->xobj);
				else
					unlock_my_super(super_block, 1);
				abort_self(winner, 0);
			} 
			list_node->rw = mode;

			if(task_count == 1)
				UNLOCK_XOBJ(&super_block->xobj);

			/* the object is read-shared and we must copy it */
			old_shadow = shadow;
			shadow = __shadow_copy_super_block(super_block, _super_block,
							   mode, task_count);

			if(unlikely(IS_ERR(shadow))){
				if(task_count > 1)
					unlock_my_super(super_block, 1);
				goto out;
			}

			list_node->rw = mode;
			list_node->shadow_obj = shadow;

			atomic_dec(&old_shadow->tx_readcount);
			if(super_block->s_contents == old_shadow)
				atomic_dec(&old_shadow->tx_refcount);
			else 
				free_tx_super_block(old_shadow);
		}
		if(task_count > 1)
			unlock_my_super(super_block, 1);
		goto out;
	}

	/* At this point, we definitely don't have the object.  Add
	 * it!
	 */
	lock_my_super(super_block, task_count != 1);

	/* Recheck that another task didn't add the object */
	if((list_node = workset_has_object_locked(&super_block->xobj)))
		goto workset_hit;
	
	list_node = tx_check_add_obj(&super_block->xobj, TYPE_SUPER_BLOCK, mode, &should_sleep, &winner);

	if(unlikely(!list_node)){
		if(!should_sleep)
			winner = NULL;
		
		unlock_my_super(super_block, task_count != 1);
		abort_self(winner, 0);
	}

	/* Go ahead an increment the refcount so we don't get freed */
	super_block->s_count++;
	
	// Allocate the shadow copy and update the local workset

	if(mode == ACCESS_R){
		// Share it
		shadow = _super_block;

		atomic_inc(&_super_block->tx_refcount);
		atomic_inc(&_super_block->tx_readcount);
	} else {
		// Get our own
		shadow = __shadow_copy_super_block(super_block, _super_block, 
						   mode, 2);// We already have the lock
		if(unlikely(IS_ERR(shadow)))
			goto out;
	}

#ifdef CONFIG_TX_KSTM_ASSERTIONS
	checkpoint = __checkpoint_super_block(_super_block);
	if(unlikely(checkpoint == NULL)){
		if(shadow != _super_block)
			__free_tx_super_block(shadow);
		shadow = ERR_PTR(-ETXABORT);
		goto out;
	}
#endif

	if(unlikely(__setup_list_node(list_node, super_block, shadow, 
#ifdef CONFIG_TX_KSTM_ASSERTIONS
				      checkpoint,
#endif				     
				      mode, &super_block->xobj)))
		shadow = ERR_PTR(-ETXABORT);

	unlock_my_super(super_block, task_count != 1);
	
out:
#ifdef CONFIG_TX_KSTM_PROF
	rdtscll(a);
	shadowCopyCycles += (a - cycles);
#endif	
	
	return shadow;
}

void * tx_cache_get_super_block_void(void *in, enum access_mode mode){
	struct _super_block *_super_block = (struct _super_block *)in;
	return (void*) _tx_cache_get_super(parent(_super_block), mode);
}

void replace_super_block_notx(struct transactional_object *xobj){
	struct super_block *super_block = container_of(xobj, struct super_block, xobj);
	struct _super_block *_super_block = super_block->s_contents;
	struct _super_block *_new_super_block;

	// i_contents are locked already - protected by XOBJ lock for now
	
	// Allocate a copy
	_new_super_block = alloc_tx_super_block_atomic();
	memcpy(_new_super_block, _super_block, sizeof(struct _super_block));

	atomic_set(&_new_super_block->tx_refcount, 0);
	atomic_set(&_new_super_block->tx_readcount, 0);

	// Replace pointer
	super_block->s_contents = _new_super_block;
}

EXPORT_SYMBOL(__tx_cache_get_super_block);

#endif //CONFIG_TX_KSTM
