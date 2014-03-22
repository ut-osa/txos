/* tx_fork.h
 * 
 * Not much here, just checkpointing signal_struct
 */

#include <linux/sched.h>
#include <linux/slab.h>

extern struct kmem_cache *signal_cachep;

void tx_chkpt_signal(struct task_struct *tsk);
void tx_rollback_signal(struct task_struct *tsk);
void tx_commit_signal(struct task_struct *tsk);
