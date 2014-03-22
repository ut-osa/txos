#include <linux/ext3_jbd.h>
#include <linux/tx_super.h>
#include <linux/tx_jbd.h>

handle_t marker_handle;

void init_jbd_kstm_tx(struct jbd_kstm_tx *j, int durable) {
	j->nblocks = 0;
	j->durable = durable ? TX_DURABLE : TX_NOT_DURABLE;
	j->sb = NULL;
	j->handle = NULL;
}

int start_jbd_tx(struct jbd_kstm_tx *j, int commit) {
	int err = 0;
	if(j->durable && j->nblocks > 0 && commit) {
		struct _super_block *sb = tx_cache_get_super(j->sb);

#ifdef CONFIG_TX_KSTM_SYNC_DURABLE
		journal_force_commit(EXT3_SB(j->sb)->s_journal);
#endif

#ifdef CONFIG_TX_KSTM_XJBD_DYNAMIC
		j->handle =
			ext3_journal_start_sb(parent(sb), JBD_DEFAULT_GUESS);
#else
		/* Add a buffer credit for the superblock */
		j->nblocks++;
		j->handle =
			ext3_journal_start_sb(parent(sb), j->nblocks);
#endif

		if(IS_ERR(j->handle)) {
			err = PTR_ERR(j->handle);
			j->handle = NULL;
		}

#ifdef CONFIG_TX_KSTM_XJBD
		j->handle->h_extensible = 1;
#endif

		/* Mark this handle synchronous: anything we put it in should get
		 * written to the log by the time we finish with journal_stop */
		j->handle->h_sync = 1;
		j->durable = TX_COMMITTING_DURABLE;
	}

	j->nblocks = 0;

	return err;
}

int stop_jbd_tx(struct jbd_kstm_tx *j, int commit) {
	int err = 0;
	if(commit && j->handle) {
		err = ext3_journal_stop(j->handle);
		j->handle = NULL;
		j->durable = TX_DURABLE;
	}
	return 0;
}
