#ifndef _LINUX_TX_JBD_H
#define _LINUX_TX_JBD_H

#include <linux/ext3_jbd.h>

#ifdef CONFIG_JBD

void init_jbd_kstm_tx(struct jbd_kstm_tx *j, int durable);
void commit_prev_jbd(struct jbd_kstm_tx *j);
int start_jbd_tx(struct jbd_kstm_tx *j, int commit);
int stop_jbd_tx(struct jbd_kstm_tx *j, int commit);

static inline int durable_committing_tx(void) {
	return atomic_read(&current->transaction->status) == TX_COMMITTING
		&& current->transaction->jbd.durable;
}

static inline struct handle_s *jbd_tx_journal_start(struct inode *inode,
		int nblocks) {
	handle_t *handle;
	/* If we are in a committing durable transaction, we want that handle.
	 * Otherwise start a new one */
	KSTM_BUG_ON(atomic_read(&current->transaction->status) != TX_COMMITTING);
	if(current->transaction->jbd.durable == TX_COMMITTING_DURABLE) {
		handle = current->transaction->jbd.handle;
	}
	else {
		handle = ext3_journal_start(inode, nblocks);
	}
	return handle;
}

static inline int jbd_tx_journal_stop(handle_t *handle) {
	int err = 0;
	if(handle && handle != current->transaction->jbd.handle) {
		err = ext3_journal_stop(handle);
	}
	return err;
}

#else
#define init_jbd_kstm_tx(j, durable) 0
#define start_jbd_tx(jbd, commit) 0
#define stop_jbd_tx(jbd, commit) 0
#endif

#endif
