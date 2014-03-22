#include <linux/mount.h>
#include <linux/transaction.h>
#include <linux/tx_vfsmount.h>
#include <linux/dcache.h>
#include <linux/tx_dentry.h>
#include <linux/module.h>


#ifdef CONFIG_TX_KSTM

# define alloc_tx_vfsmount() kmem_cache_alloc(cachep_tx_vfsmount, GFP_KERNEL)
# define free_tx_vfsmount(tx) kmem_cache_free(cachep_tx_vfsmount, (tx))
struct kmem_cache *cachep_tx_vfsmount;

/* vfsmount structs don't seem to include locks */

/* Do the cleanup/freeing work */
int release_vfsmount(struct txobj_thread_list_node * xnode, int early){
				
	struct vfsmount * orig = (struct vfsmount *)xnode->orig_obj;
	struct vfsmount * shadow = (struct vfsmount *)xnode->shadow_obj;
#ifdef CONFIG_TX_KSTM_ASSERTIONS
	struct vfsmount * checkpoint = (struct vfsmount *)xnode->checkpoint_obj;
#endif

	// drop the transaction's reference
	mntput(orig);

	free_tx_vfsmount(shadow);

#ifdef CONFIG_TX_KSTM_ASSERTIONS		
	free_tx_vfsmount(checkpoint);
#endif
	return 0;
}


int abort_vfsmount(struct txobj_thread_list_node * xnode){

	struct vfsmount * orig = (struct vfsmount *)xnode->orig_obj;
	atomic_dec(&orig->mnt_hash.tx_count);
	atomic_dec(&orig->mnt_mounts.tx_count);
	atomic_dec(&orig->mnt_child.tx_count);
	atomic_dec(&orig->mnt_expire.tx_count);
	atomic_dec(&orig->mnt_share.tx_count);
	atomic_dec(&orig->mnt_slave_list.tx_count);
	atomic_dec(&orig->mnt_slave.tx_count);

	return 0;
}


int commit_vfsmount(struct txobj_thread_list_node * xnode){
				
	struct vfsmount * orig = (struct vfsmount *)xnode->orig_obj;
	struct vfsmount * shadow = (struct vfsmount *)xnode->shadow_obj;

	/* Only commit these fields on RW mode */
	if(xnode->rw == ACCESS_RW){

		TX_COMMIT(orig, shadow, mnt_parent);
		if(orig->mnt_parent->shadow)
			orig->mnt_parent = orig->mnt_parent->shadow;

		list_commit_tx(&shadow->mnt_hash, 0);
		TX_COMMIT(orig, shadow, mnt_mountpoint);
		TX_COMMIT(orig, shadow, mnt_root);
		TX_COMMIT(orig, shadow, mnt_sb);
		list_commit_tx(&shadow->mnt_mounts, 0);
		list_commit_tx(&shadow->mnt_child, 0);
		TX_COMMIT(orig, shadow, mnt_flags);
		strcpy(orig->mnt_devname, shadow->mnt_devname);
		list_commit_tx(&shadow->mnt_expire, 0);
		list_commit_tx(&shadow->mnt_share, 0);
		list_commit_tx(&shadow->mnt_slave_list, 0);
		list_commit_tx(&shadow->mnt_slave, 0);
		TX_COMMIT(orig, shadow, mnt_master);
		TX_COMMIT(orig, shadow, mnt_ns);
		TX_COMMIT(orig, shadow, mnt_expiry_mark);
		TX_COMMIT(orig, shadow, mnt_pinned);
	} else {
		atomic_dec(&orig->mnt_hash.tx_count);
		atomic_dec(&orig->mnt_mounts.tx_count);
		atomic_dec(&orig->mnt_child.tx_count);
		atomic_dec(&orig->mnt_expire.tx_count);
		atomic_dec(&orig->mnt_share.tx_count);
		atomic_dec(&orig->mnt_slave_list.tx_count);
		atomic_dec(&orig->mnt_slave.tx_count);
	}
	return 0;
}

#ifdef CONFIG_TX_KSTM_ASSERTIONS
int validate_vfsmount(struct txobj_thread_list_node * xnode){
				
	struct vfsmount * orig = xnode->orig_obj;
	struct vfsmount *checkpoint = xnode->checkpoint_obj;
	struct vfsmount *shadow = xnode->shadow_obj;

	list_validate_tx(&orig->mnt_hash, &checkpoint->mnt_hash);
	TX_VALIDATE(orig, checkpoint, mnt_parent);
	TX_VALIDATE(orig, checkpoint, mnt_mountpoint);
	TX_VALIDATE(orig, checkpoint, mnt_root);
	TX_VALIDATE(orig, checkpoint, mnt_sb);
	list_validate_tx(&orig->mnt_mounts, &checkpoint->mnt_mounts);
	list_validate_tx(&orig->mnt_child, &checkpoint->mnt_child);
	TX_VALIDATE(orig, checkpoint, mnt_flags);
	BUG_ON(0 != strcmp(orig->mnt_devname, checkpoint->mnt_devname));
	list_validate_tx(&orig->mnt_expire, &checkpoint->mnt_expire);
	list_validate_tx(&orig->mnt_share, &checkpoint->mnt_share);
	list_validate_tx(&orig->mnt_slave_list, &checkpoint->mnt_slave_list);
	list_validate_tx(&orig->mnt_slave, &checkpoint->mnt_slave);
	TX_VALIDATE(orig, checkpoint, mnt_master);
	TX_VALIDATE(orig, checkpoint, mnt_ns);
	TX_VALIDATE(orig, checkpoint, mnt_expiry_mark);
	TX_VALIDATE(orig, checkpoint, mnt_pinned);
	
	/* Even heavier validation for R-only objects */
	if(xnode->rw == ACCESS_R){
		if(orig->mnt_parent != shadow->mnt_parent)
			KSTM_BUG_ON(shadow->mnt_parent->shadow != orig->mnt_parent);

		TX_VALIDATE(orig, shadow, mnt_mountpoint);

		list_validate_tx_ro(&orig->mnt_hash, &shadow->mnt_hash);
		TX_VALIDATE(orig, shadow, mnt_root);
		TX_VALIDATE(orig, shadow, mnt_sb);
		list_validate_tx_ro(&orig->mnt_mounts, &shadow->mnt_mounts);
		list_validate_tx_ro(&orig->mnt_child, &shadow->mnt_child);
		TX_VALIDATE(orig, shadow, mnt_flags);
		BUG_ON(0 != strcmp(orig->mnt_devname, shadow->mnt_devname));
		strcpy(orig->mnt_devname, shadow->mnt_devname);
		list_validate_tx_ro(&orig->mnt_expire, &shadow->mnt_expire);
		list_validate_tx_ro(&orig->mnt_share, &shadow->mnt_share);
		list_validate_tx_ro(&orig->mnt_slave_list, &shadow->mnt_slave_list);
		list_validate_tx_ro(&orig->mnt_slave, &shadow->mnt_slave);
		TX_VALIDATE(orig, shadow, mnt_master);
		TX_VALIDATE(orig, shadow, mnt_ns);
		TX_VALIDATE(orig, shadow, mnt_expiry_mark);
		TX_VALIDATE(orig, shadow, mnt_pinned);
	}

	return 0;
}
#endif

static struct vfsmount * __tx_cache_get_vfsmount(struct vfsmount * vfsmount, enum access_mode mode){

	struct vfsmount * shadow;
	txobj_thread_list_node_t * list_node = NULL;
	struct vfsmount *tmp;
	int should_sleep = 0;
	struct transaction *winner;

#ifdef CONFIG_TX_KSTM_PROF
	unsigned long long cycles, a;
#endif
#ifdef CONFIG_TX_KSTM_ASSERTIONS
 	struct vfsmount * checkpoint;
	BUG_ON(vfsmount == NULL);
#endif

	/* If this is already a shadow copy, return it */
	OSA_PROTECT_SUSPEND();
	if(vfsmount->shadow){
		if(vfsmount->rw >= mode){
			OSA_PROTECT_RESUME();
			return vfsmount;
		} else {
			vfsmount = vfsmount->shadow;
		}
	}
	OSA_PROTECT_RESUME();

	/* Some initial checks for non-active tx status */
	if((tmp = tx_status_check(vfsmount, mode, 0)) != NULL){
		return tmp;
	}

#ifdef CONFIG_TX_KSTM_PROF
	rdtscll(cycles);
#endif	


	/* Next, make sure we don't already have the object */
	LOCK_XOBJ(&vfsmount->xobj);
	list_node = workset_has_object_locked(&vfsmount->xobj);
	if(list_node) {

		shadow = list_node->shadow_obj;
		if(list_node->rw < mode){
			/* Upgrade the mode */
			winner = 
				upgrade_xobj_mode(list_node->tx_obj, mode, &should_sleep);
			if(winner){
				if(!should_sleep)
					winner = NULL;
					
				UNLOCK_XOBJ(&vfsmount->xobj);
				abort_self(winner, 0);
			} 
			list_node->rw = mode;

			shadow->rw = mode;
			shadow->mnt_hash.rw = mode;
			shadow->mnt_mounts.rw = mode;
			shadow->mnt_child.rw = mode;
			shadow->mnt_expire.rw = mode;
			shadow->mnt_share.rw = mode;
			shadow->mnt_slave_list.rw = mode;
			shadow->mnt_slave.rw = mode;
		} 
#ifdef CONFIG_TX_KSTM_PROF
		rdtscll(a);
		shadowCopyCycles += (a - cycles);
#endif	
		UNLOCK_XOBJ(&vfsmount->xobj);
		return shadow;
	}

	/* At this point, we definitely don't have the object.  Add
	 * it!
	 */
	list_node = tx_check_add_obj(&vfsmount->xobj, TYPE_VFSMOUNT, mode, &should_sleep, &winner);

	if(unlikely(!list_node)){
#ifdef CONFIG_TX_KSTM_PROF
		rdtscll(a);
		shadowCopyCycles += (a - cycles);
#endif	
		if(!should_sleep)
			winner = NULL;
		UNLOCK_XOBJ(&vfsmount->xobj);
		abort_self(winner, 0);
	}
	UNLOCK_XOBJ(&vfsmount->xobj);
	
	// Allocate the shadow copy and update the local workset
	
	//alloc a shadow object
	shadow = alloc_tx_vfsmount();
	if(!shadow)
		goto fail1;

	/* Go ahead an increment the refcount so we don't get freed */
	tx_atomic_inc_nolog(&vfsmount->mnt_count);

	memcpy(shadow, vfsmount, sizeof(struct vfsmount));

	/* XXX: We are not going to overwrite the parent in the shadow
	 * copy so that we can just memcpy the whole thing when we are
	 * done.  Be aware.
	 */

	shadow->shadow = vfsmount;
	shadow->rw = mode;

#ifdef CONFIG_TX_KSTM_ASSERTIONS

	checkpoint = alloc_tx_vfsmount();
	if(!checkpoint)
		goto fail2;
	memcpy(checkpoint, shadow, sizeof(struct vfsmount));
#endif

	/* Be sure to init the shadow lists */
	list_init_tx(&shadow->mnt_hash, mode);
	list_init_tx(&shadow->mnt_mounts, mode);
	list_init_tx(&shadow->mnt_child, mode);
	list_init_tx(&shadow->mnt_expire, mode);
	list_init_tx(&shadow->mnt_share, mode);
	list_init_tx(&shadow->mnt_slave_list, mode);
	list_init_tx(&shadow->mnt_slave, mode);
	
	list_node->type = TYPE_VFSMOUNT;
	list_node->shadow_obj = shadow;
	list_node->orig_obj = vfsmount;
	list_node->rw = mode;
	list_node->lock = NULL;
	list_node->unlock = NULL;
	list_node->commit = commit_vfsmount;
	list_node->abort  = abort_vfsmount;
	list_node->release= release_vfsmount;
	list_node->tx_obj = &vfsmount->xobj;

#ifdef CONFIG_TX_KSTM_ASSERTIONS
	list_node->checkpoint_obj = checkpoint;
	list_node->validate = validate_vfsmount;
#endif
	workset_add(list_node,
		    &(current->transaction->object_list));

	OSA_PROTECT_ADDR(vfsmount, sizeof(struct vfsmount));

#ifdef CONFIG_TX_KSTM_PROF
	rdtscll(a);
	shadowCopyCycles += (a - cycles);
#endif	
	return shadow;

#ifdef CONFIG_TX_KSTM_ASSERTIONS
fail2:
	free_tx_vfsmount(checkpoint);
#endif
fail1:
	free_tx_vfsmount(shadow);
	BUG();
#ifdef CONFIG_TX_KSTM_PROF
	rdtscll(a);
	shadowCopyCycles += (a - cycles);
#endif	
	return ERR_PTR(-ETXABORT);
}

struct vfsmount * tx_cache_get_vfsmount(struct vfsmount * vfsmount){
	return __tx_cache_get_vfsmount(vfsmount, ACCESS_RW);
}

struct vfsmount * tx_cache_get_vfsmount_ro(struct vfsmount * vfsmount){
	return __tx_cache_get_vfsmount(vfsmount, ACCESS_R);
}

void * tx_cache_get_vfsmount_void(void *in, enum access_mode mode){
	return (void*) __tx_cache_get_vfsmount((struct vfsmount *) in, mode);
}

struct vfsmount * mnt_get_parent(struct vfsmount *d){

	struct vfsmount *rv;

	// Only bother with all this for non-null inodes
	if(!d->mnt_parent)
		return d->mnt_parent;

	rv = __tx_cache_get_vfsmount(d->mnt_parent, ACCESS_RW);

	// Update the vfsmount to cache the update
	d->mnt_parent = rv;

	return rv;
}

struct vfsmount * mnt_get_parent_ro(struct vfsmount *d){

	struct vfsmount *rv;

	// Only bother with all this for non-null inodes
	if(!d->mnt_parent)
		return d->mnt_parent;

	rv = __tx_cache_get_vfsmount(d->mnt_parent, ACCESS_R);

	// Update the vfsmount to cache the update
	d->mnt_parent = rv;

	return rv;
}

struct dentry * mnt_get_mountpoint(struct vfsmount *d){

	//struct dentry *rv;

	// Only bother with all this for non-null inodes
	//if(!d->mnt_mountpoint)
		return d->mnt_mountpoint;

	//rv = tx_cache_get_dentry(d->mnt_mountpoint);

	// Update the vfsmount to cache the update
	//d->mnt_mountpoint = rv;

	//return rv;
}

struct dentry * mnt_get_mountpoint_ro(struct vfsmount *d){

	//struct dentry *rv;

	// Only bother with all this for non-null inodes
	//if(!d->mnt_mountpoint)
		return d->mnt_mountpoint;

	//rv = tx_cache_get_dentry_ro(d->mnt_mountpoint);

	// Update the vfsmount to cache the update
	//d->mnt_mountpoint = rv;

		//return rv;
}


#else

struct vfsmount * tx_cache_get_vfsmount(struct vfsmount * vfsmount){
	return vfsmount;
}

struct vfsmount * tx_cache_get_vfsmount_ro(struct vfsmount * vfsmount){
	return vfsmount;
}

struct vfsmount * mnt_get_parent(struct vfsmount *d){
	return d->mnt_parent;
}

struct vfsmount * mnt_get_parent_ro(struct vfsmount *d){
	return d->mnt_parent;
}

struct dentry * mnt_get_mountpoint(struct vfsmount *d){
	return d->mnt_mountpoint;
}

struct dentry * mnt_get_mountpoint_ro(struct vfsmount *d){
	return d->mnt_mountpoint;
}


#endif //CONFIG_TX_KSTM

EXPORT_SYMBOL(mnt_get_parent);
EXPORT_SYMBOL(mnt_get_parent_ro);
EXPORT_SYMBOL(mnt_get_mountpoint);
EXPORT_SYMBOL(mnt_get_mountpoint_ro);
