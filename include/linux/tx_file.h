#ifndef _LINUX_TX_VFSMOUNT_H
#define _LINUX_TX_VFSMOUNT_H

#include <linux/fs.h>
#include <linux/tx_dentry.h>

void * tx_cache_get_file_void(void *, enum access_mode);
struct _file * __tx_cache_get_file(struct file * file, enum access_mode mode);

#ifdef CONFIG_TX_KSTM
static inline struct _file * _tx_cache_get_file(struct file *file, 
						enum access_mode mode){
	void *tmp;						
	struct _file *rv;
	if((tmp = tx_status_check(file, mode, 0)) != NULL){
		if (IS_ERR(tmp)) return tmp;
		rcu_read_lock();
		rv = file->f_contents;
		rcu_read_unlock();
		return rv;
	}
	return __tx_cache_get_file(file, mode);	
}

#endif // CONFIG_TX_KSTM

#define tx_cache_get_file(file) _tx_cache_get_file(file, ACCESS_RW)
#define tx_cache_get_file_ro(file) \
	_tx_cache_get_file(file, ACCESS_R)


static inline struct _dentry *_f_get_dentry(const struct _file* f, enum access_mode mode){
	
	if(!f->f_dentry)
		return NULL;

	return _tx_cache_get_dentry(f->f_dentry, mode);
}

#define f_get_dentry(d) _f_get_dentry(d, ACCESS_RW)
#define f_get_dentry_ro(d) _f_get_dentry(d, ACCESS_R)

#define file_get_dentry(d) f_get_dentry(tx_cache_get_file(d))
#define file_get_dentry_ro(d) f_get_dentry_ro(tx_cache_get_file_ro(d))

struct fs_struct * tx_cache_get_fs(struct task_struct *t);

void tx_commit_fs(struct task_struct *tsk);
void tx_rollback_fs(struct task_struct *tsk);

/* DEP: Functions below hoisted from include/linux/fs.h to get proper
 * tx indirection while staying inlined
 */

static inline void file_accessed(const struct _file *file)
{
	if (!(file->f_flags & O_NOATIME))
		touch_atime(file->f_path.mnt, f_get_dentry(file));
}

#endif //_LINUX_TX_FILE_H

