#ifndef _LINUX_FS_NOTIFY_H
#define _LINUX_FS_NOTIFY_H

/*
 * include/linux/fsnotify.h - generic hooks for filesystem notification, to
 * reduce in-source duplication from both dnotify and inotify.
 *
 * We don't compile any of this away in some complicated menagerie of ifdefs.
 * Instead, we rely on the code inside to optimize away as needed.
 *
 * (C) Copyright 2005 Robert Love
 */

#ifdef __KERNEL__

#include <linux/dnotify.h>
#include <linux/inotify.h>
#include <linux/audit.h>
#include <linux/transaction.h>
#include <linux/tx_inodes.h>
#include <linux/tx_dentry.h>
#include <linux/tx_file.h>

/*
 * fsnotify_d_instantiate - instantiate a dentry for inode
 * Called with dcache_lock held.
 */
static inline void fsnotify_d_instantiate(struct _dentry *entry,
					  struct inode *inode)
{
	inotify_d_instantiate(entry, inode);
}

/*
 * fsnotify_d_move - entry has been moved
 * Called with dcache_lock and entry->d_lock held.
 */
static inline void _fsnotify_d_move(struct dentry *entry)
{
	inotify_d_move(tx_cache_get_dentry(entry));
}

/*
 * fsnotify_move - file old_name at old_dir was moved to new_name at new_dir
 */
static inline void _fsnotify_move(struct inode *old_dir, struct inode *new_dir,
				 const char *old_name, const char *new_name,
				 int isdir, struct inode *target, struct inode *source)
{
	u32 cookie = inotify_get_cookie();

	if (old_dir == new_dir)
		inode_dir_notify(old_dir, DN_RENAME);
	else {
		inode_dir_notify(old_dir, DN_DELETE);
		inode_dir_notify(new_dir, DN_CREATE);
	}

	if (isdir)
		isdir = IN_ISDIR;
	inotify_inode_queue_event(old_dir, IN_MOVED_FROM|isdir,cookie,old_name,
				  source);
	inotify_inode_queue_event(new_dir, IN_MOVED_TO|isdir, cookie, new_name,
				  source);

	if (target) {
		inotify_inode_queue_event(target, IN_DELETE_SELF, 0, NULL, NULL);
		inotify_inode_is_dead(target);
	}

	if (source) {
		inotify_inode_queue_event(source, IN_MOVE_SELF, 0, NULL, NULL);
	}
	audit_inode_child(new_name, source, new_dir);
}

/*
 * fsnotify_nameremove - a filename was removed from a directory
 */
static inline void _fsnotify_nameremove(struct dentry *dentry, int isdir)
{
	struct _dentry *_dentry = tx_cache_get_dentry(dentry);
	if (isdir)
		isdir = IN_ISDIR;
	dnotify_parent(_dentry, DN_DELETE);
	inotify_dentry_parent_queue_event(_dentry, IN_DELETE|isdir, 0, _dentry->d_name.name);
}

/*
 * fsnotify_inoderemove - an inode is going away
 */
static inline void _fsnotify_inoderemove(struct inode *inode)
{
	inotify_inode_queue_event(inode, IN_DELETE_SELF, 0, NULL, NULL);
	inotify_inode_is_dead(inode);
}

/*
 * fsnotify_create - 'name' was linked in
 */
static inline void _fsnotify_create(struct inode *inode, struct dentry *dentry)
{
	struct _dentry *_dentry = tx_cache_get_dentry_ro(dentry);
	inode_dir_notify(inode, DN_CREATE);
	inotify_inode_queue_event(inode, IN_CREATE, 0, _dentry->d_name.name,
				  _dentry->d_inode);
	audit_inode_child(_dentry->d_name.name, _dentry->d_inode, inode);
}

/*
 * fsnotify_mkdir - directory 'name' was created
 */
static inline void _fsnotify_mkdir(struct inode *inode, struct dentry *dentry)
{
	struct _dentry *_dentry = tx_cache_get_dentry_ro(dentry);
	inode_dir_notify(inode, DN_CREATE);
	inotify_inode_queue_event(inode, IN_CREATE | IN_ISDIR, 0, 
				  _dentry->d_name.name, _dentry->d_inode);
	audit_inode_child(_dentry->d_name.name, _dentry->d_inode, inode);
}

/*
 * fsnotify_access - file was read
 */
static inline void _fsnotify_access(struct dentry *dentry)
{
	struct inode *inode;
	struct _dentry *_dentry = tx_cache_get_dentry_ro(dentry);
	u32 mask = IN_ACCESS;
	inode = _dentry->d_inode;
	if (S_ISDIR(d_get_inode(_dentry)->i_mode))
		mask |= IN_ISDIR;

	dnotify_parent(_dentry, DN_ACCESS);
	inotify_dentry_parent_queue_event(_dentry, mask, 0, _dentry->d_name.name);
	inotify_inode_queue_event(inode, mask, 0, NULL, NULL);
}

/*
 * fsnotify_modify - file was modified
 */
static inline void _fsnotify_modify(struct dentry *dentry)
{
	struct _dentry *_dentry = tx_cache_get_dentry_ro(dentry);
	struct inode *inode = _dentry->d_inode;
	u32 mask = IN_MODIFY;

	if (S_ISDIR(inode->i_contents->i_mode))
		mask |= IN_ISDIR;

	dnotify_parent(_dentry, DN_MODIFY);
	inotify_dentry_parent_queue_event(_dentry, mask, 0, _dentry->d_name.name);
	inotify_inode_queue_event(inode, mask, 0, NULL, NULL);
}

/*
 * fsnotify_open - file was opened
 */
static inline void _fsnotify_open(struct dentry *dentry)
{
	struct inode *inode;
	struct _dentry *_dentry = tx_cache_get_dentry_ro(dentry);
	u32 mask = IN_OPEN;
	inode = _dentry->d_inode;
	if (S_ISDIR(inode->i_contents->i_mode))
		mask |= IN_ISDIR;

	inotify_dentry_parent_queue_event(_dentry, mask, 0, _dentry->d_name.name);
	inotify_inode_queue_event(inode, mask, 0, NULL, NULL);
}

/*
 * fsnotify_close - file was closed
 */
static inline void _fsnotify_close(struct dentry *dentry, mode_t mode)
{
	//struct _file *_file = tx_cache_get_file_ro(file);
	struct _dentry *_dentry = tx_cache_get_dentry_ro(dentry);
	struct inode *inode = _dentry->d_inode;
	const char *name = _dentry->d_name.name;
	//mode_t mode = _file->f_mode;
	u32 mask = (mode & FMODE_WRITE) ? IN_CLOSE_WRITE : IN_CLOSE_NOWRITE;

	if (S_ISDIR(inode->i_contents->i_mode))
		mask |= IN_ISDIR;

	inotify_dentry_parent_queue_event(_dentry, mask, 0, name);
	inotify_inode_queue_event(inode, mask, 0, NULL, NULL);
}

/*
 * fsnotify_xattr - extended attributes were changed
 */
static inline void _fsnotify_xattr(struct dentry *dentry)
{
	struct inode *inode;
	struct _dentry *_dentry = tx_cache_get_dentry_ro(dentry);
	u32 mask = IN_ATTRIB;
	inode = _dentry->d_inode;


	if (S_ISDIR(inode->i_contents->i_mode))
		mask |= IN_ISDIR;

	inotify_dentry_parent_queue_event(_dentry, mask, 0, _dentry->d_name.name);
	inotify_inode_queue_event(inode, mask, 0, NULL, NULL);
}

/*
 * fsnotify_change - notify_change event.  file was modified and/or metadata
 * was changed.
 */
static inline void _fsnotify_change(struct dentry *dentry, unsigned int ia_valid)
{
	struct inode *inode;
	int dn_mask = 0;
	u32 in_mask = 0;
	struct _dentry *_dentry = tx_cache_get_dentry_ro(dentry);
	inode = _dentry->d_inode;

	if (ia_valid & ATTR_UID) {
		in_mask |= IN_ATTRIB;
		dn_mask |= DN_ATTRIB;
	}
	if (ia_valid & ATTR_GID) {
		in_mask |= IN_ATTRIB;
		dn_mask |= DN_ATTRIB;
	}
	if (ia_valid & ATTR_SIZE) {
		in_mask |= IN_MODIFY;
		dn_mask |= DN_MODIFY;
	}
	/* both times implies a utime(s) call */
	if ((ia_valid & (ATTR_ATIME | ATTR_MTIME)) == (ATTR_ATIME | ATTR_MTIME))
	{
		in_mask |= IN_ATTRIB;
		dn_mask |= DN_ATTRIB;
	} else if (ia_valid & ATTR_ATIME) {
		in_mask |= IN_ACCESS;
		dn_mask |= DN_ACCESS;
	} else if (ia_valid & ATTR_MTIME) {
		in_mask |= IN_MODIFY;
		dn_mask |= DN_MODIFY;
	}
	if (ia_valid & ATTR_MODE) {
		in_mask |= IN_ATTRIB;
		dn_mask |= DN_ATTRIB;
	}

	if (dn_mask)
		dnotify_parent(_dentry, dn_mask);
	if (in_mask) {
		if (S_ISDIR(inode->i_contents->i_mode))
			in_mask |= IN_ISDIR;
		inotify_inode_queue_event(inode, in_mask, 0, NULL, NULL);
		inotify_dentry_parent_queue_event(_dentry, in_mask, 0,
						  _dentry->d_name.name);
	}
}

#ifdef CONFIG_INOTIFY	/* inotify helpers */

/*
 * fsnotify_oldname_init - save off the old filename before we change it
 */
static inline const char *fsnotify_oldname_init(const char *name)
{
	char *rv = kstrdup(name, GFP_KERNEL);
	record_tx_alloc(rv, NULL);
	return rv;
}

/*
 * fsnotify_oldname_free - free the name we got from fsnotify_oldname_init
 */
static inline void fsnotify_oldname_free(const char *old_name)
{
	kfree(old_name);
}

#else	/* CONFIG_INOTIFY */

static inline const char *fsnotify_oldname_init(const char *name)
{
	return NULL;
}

static inline void fsnotify_oldname_free(const char *old_name)
{
}

#endif	/* ! CONFIG_INOTIFY */

#ifdef CONFIG_TX_KSTM

#include <linux/fsnotify_tx.h>

extern struct kmem_cache *fsnotify_cachep;
#define alloc_fsnotify_buf() kmem_cache_alloc(fsnotify_cachep, GFP_ATOMIC)
#define free_fsnotify_buf(item) kmem_cache_free(fsnotify_cachep, (item))

static inline void queue_fsnotify_event(enum fsnotify_id id, void *arg1,
					void *arg2, void *arg3,
					void *arg4, int arg5,
					void *arg6, void *arg7){

	struct fsnotify_event_buf *buf = NULL;

	if(!list_empty(&current->fs_notify)){
		buf = list_entry(current->fs_notify.prev, struct fsnotify_event_buf, list);
		if(buf->count == MAX_TX_FSNOTIFY)
			buf = NULL;
	}

	if(!buf){
		buf = alloc_fsnotify_buf();
		buf->count = 0;
		INIT_LIST_HEAD(&buf->list);
		list_add_tail(&buf->list, &current->fs_notify);
	}

	buf->recs[buf->count].id = id;
	buf->recs[buf->count].arg1 = arg1;
	buf->recs[buf->count].arg2 = arg2;
	buf->recs[buf->count].arg3 = arg3;
	buf->recs[buf->count].arg4 = arg4;
	buf->recs[buf->count].arg5 = arg5;
	buf->recs[buf->count].arg6 = arg6;
	buf->recs[buf->count++].arg7 = arg7;
}

static inline void deliver_fs_notify_events(struct list_head *lst){
	struct fsnotify_event_buf *buf, *n;

	list_for_each_entry_safe(buf, n, lst, list){
	
		int i = 0, lim = buf->count;
		while(i < lim){
	
			struct fsnotify_event_record * rec = &buf->recs[i];

			switch(rec->id){
			case D_MOVE:
				_fsnotify_d_move((struct dentry *) rec->arg1);
				break;
			case MOVE:
				_fsnotify_move((struct inode *)rec->arg1, (struct inode *)rec->arg2,
					       (const char *)rec->arg3, (const char *)rec->arg4,
					       rec->arg5, (struct inode *)rec->arg6, 
					       (struct inode *) rec->arg7);
				fsnotify_oldname_free((const char *)rec->arg3);
				break;
			case NAMEREMOVE:
				_fsnotify_nameremove((struct dentry *)rec->arg1, (int)rec->arg5);  // Avoid int/pointer size mismatch
				break;
			case INODEREMOVE:
				_fsnotify_inoderemove((struct inode *)rec->arg1);
				break;
			case CREATE:
				_fsnotify_create((struct inode *)rec->arg1, (struct dentry *)rec->arg2);
				break;
			case MKDIR:
				_fsnotify_mkdir((struct inode *)rec->arg1, (struct dentry *)rec->arg2);
				break;
			case ACCESS:
				_fsnotify_access((struct dentry *)rec->arg1);
				break;
			case MODIFY:
				_fsnotify_modify((struct dentry *)rec->arg1);
				break;
			case FSNOTIFY_OPEN:
				_fsnotify_open((struct dentry *)rec->arg1);
				break;
			case CLOSE:
			{
				unsigned int md = (unsigned int) rec->arg5;  // Avoid int/pointer size mismatch
				mode_t mode = (mode_t) md;
				_fsnotify_close((struct dentry *) rec->arg1, mode);
				break;
			}
			case XATTR:
				_fsnotify_xattr((struct dentry *)rec->arg1);
				break;
			case CHANGE:
				_fsnotify_change((struct dentry *)rec->arg1, (unsigned int) rec->arg5);  // Avoid int/pointer size mismatch
				break;
			default:
				printk(KERN_ERR "Unknown fsnotify id %d\n", rec->id);
				BUG();
			}
			i++;
		}
		list_del(&buf->list);
		free_fsnotify_buf(buf);
	}
}

/* Wicked hack to put in a layer of indirection so that fsnotify happens at commit time */

#define fsnotify_d_move(entry) live_transaction() ?			\
	queue_fsnotify_event(D_MOVE, entry, NULL, NULL, NULL, 0, NULL, NULL)	\
	: _fsnotify_d_move(entry)

#define fsnotify_move(old_dir, new_dir, old_name, new_name, isdir, target, source) \
	live_transaction() ?						\
	queue_fsnotify_event(MOVE, old_dir, new_dir, old_name, new_name, isdir, target, source)  \
	: _fsnotify_move(old_dir, new_dir, old_name, new_name, isdir, target, source) 

#define fsnotify_nameremove(dentry, isdir) live_transaction() ?		\
	queue_fsnotify_event(NAMEREMOVE, dentry, NULL, NULL, NULL, isdir, NULL, NULL) \
	: _fsnotify_nameremove(dentry, isdir)

#define fsnotify_inoderemove(inode) live_transaction() ?		\
	queue_fsnotify_event(INODEREMOVE, inode, NULL, NULL, NULL, 0, NULL, NULL) \
	: _fsnotify_inoderemove(inode)

#define fsnotify_create(inode, dentry) live_transaction() ?		\
	queue_fsnotify_event(CREATE, inode, dentry, NULL, NULL, 0, NULL, NULL) \
	: _fsnotify_create(inode, dentry)

#define fsnotify_mkdir(inode, dentry) live_transaction() ?		\
	queue_fsnotify_event(MKDIR, inode, dentry, NULL, NULL, 0, NULL, NULL) \
	: _fsnotify_mkdir(inode, dentry)

#define fsnotify_access(dentry)						\
	do{								\
		if(live_transaction())					\
		{							\
			if((dentry->d_flags & DCACHE_INOTIFY_PARENT_WATCHED) \
			   || (!list_empty(&(dentry)->d_inode->inotify_watches))) \
				queue_fsnotify_event(ACCESS, parent(dentry), NULL, NULL, NULL, 0, NULL, NULL); \
		}							\
		else							\
			_fsnotify_access(parent(dentry));		\
	}while(0)

#define fsnotify_modify(dentry)	live_transaction() ?			\
	queue_fsnotify_event(MODIFY, dentry, NULL, NULL, NULL, 0, NULL, NULL) \
	: _fsnotify_modify(dentry)

#define fsnotify_open(dentry)						\
	do{								\
		if(live_transaction())					\
		{							\
			if((dentry->d_flags & DCACHE_INOTIFY_PARENT_WATCHED) \
			   || (!list_empty(&(dentry)->d_inode->inotify_watches))) \
				queue_fsnotify_event(FSNOTIFY_OPEN, parent(dentry), NULL, NULL, NULL, 0, NULL, NULL); \
		}							\
		else							\
			_fsnotify_open(parent(dentry));			\
	}while(0)
	

#define fsnotify_close(fle) do{					\
		struct _file *_f = tx_cache_get_file_ro(fle);	\
		unsigned int m = 0;					\
		m |= _f->f_mode;					\
		live_transaction() ?					\
			queue_fsnotify_event(CLOSE, (_f)->f_dentry, NULL, NULL, NULL, m, NULL, NULL) \
			: _fsnotify_close((_file)->f_dentry, _file->f_mode); \
	} while(0)

#define fsnotify_xattr(dentry) live_transaction() ? 			\
	queue_fsnotify_event(XATTR, dentry, NULL, NULL, NULL, 0, NULL, NULL)	\
	: _fsnotify_xattr(dentry) 

#define fsnotify_change(dentry, ia_valid) live_transaction() ?		\
	queue_fsnotify_event(CHANGE, dentry, NULL, NULL, NULL, ia_valid, NULL, NULL) \
	: _fsnotify_change(dentry, ia_valid)

#else /* config tx kstm */
#define fsnotify_d_move(entry) _fsnotify_d_move(entry) 
#define fsnotify_move(old_dir, new_dir, old_name, new_name, isdir, target, source) \
	_fsnotify_move(old_dir, new_dir, old_name, new_name, isdir, target, source) 

#define fsnotify_nameremove(dentry, isdir) _fsnotify_nameremove(dentry, isdir) 
#define fsnotify_inoderemove(inode) _fsnotify_inoderemove(inode) 
#define fsnotify_create(inode, dentry) _fsnotify_create(inode, dentry) 
#define fsnotify_mkdir(inode, dentry) _fsnotify_mkdir(inode, dentry) 
#define fsnotify_access(dentry) _fsnotify_access(dentry) 
#define fsnotify_modify(dentry) _fsnotify_modify(dentry) 
#define fsnotify_open(dentry) _fsnotify_open(dentry) 
#define fsnotify_close(file) _fsnotify_close(file) 
#define fsnotify_xattr(dentry) _fsnotify_xattr(dentry) 
#define fsnotify_change(dentry, ia_valid) _fsnotify_change(dentry, ia_valid) 

#endif /* config tx kstm */

#endif	/* __KERNEL__ */

#endif	/* _LINUX_FS_NOTIFY_H */
