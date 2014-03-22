#ifndef _FS_EXT3_SDIRENT_H
#define _FS_EXT3_SDIRENT_H

typedef struct ext3_dir_entry_2 ext3_dirent;

/* Node in the linked list of speculative dentries */
struct ext3_sdirent {
	struct list_head sdentries;	/* List of speculative entries on this inode */
	sector_t blkno;					/* Which page of the directory */
	int offset;							/* Offset within page */
	ext3_dirent _entry;				/* Actual overlay bytes */
};

/* Cursor into the list of speculative and non-speculative dentries */
struct ext3_cur_sdirent {
	struct list_head *next_sdirent;	/* Next available speculative dirent */
	struct ext3_dir_entry_2 *entry;	/* Actual speculative or stable dirent */
	char *real_addr;						/* Real address this entry reflects */

	struct _ext3_inode_info *inode;	/* Inode containing directory data */
	sector_t blkno;						/* Which directory page cursor is on */
	char *blk_addr;						/* Address of the current directory page */
};

int ext3_init_sdirent_cache(void);

extern struct kmem_cache *sdirent_cachep;

#define sdirent_entry(sdirent) \
	list_entry((sdirent), struct ext3_sdirent, sdentries)

static inline int sdirent_lt(struct ext3_sdirent *sdirent, sector_t next_blkno,
		int next_offset) {
 return (sdirent->blkno < next_blkno) ||
	 	(sdirent->blkno == next_blkno && sdirent->offset < next_offset);
}

static void init_cur_sdirent(struct ext3_cur_sdirent *cur,
		struct _ext3_inode_info *inode) {
	cur->next_sdirent = parent(inode)->sdentries.next;
	cur->inode = inode;
}

/*
static void init_cur_sdirent_page(struct ext3_cur_sdirent *cur,
		struct page *page, int live_tx) {
	struct inode *inode = page->mapping->host;
	 * dP: Owen, is inode already in the workset?
	if(live_tx) {
		inode = tx_cache_get_inode_ro(inode);
	}
	cur->inode = EXT3_I(inode);
	cur->next_sdirent = cur->inode->sdentries.next;
	cur->pageno = page->index;
	cur->kaddr = page_address(page);
	cur->entry = NULL;
	cur->real_addr = NULL;
}
*/

static void move_cur_sdirent_bh(struct ext3_cur_sdirent *cur,
		struct buffer_head *bh, int blkno) {
	if(unlikely(blkno <= cur->blkno)) {
		cur->next_sdirent = parent(cur->inode)->sdentries.next;
	}
	cur->blkno = blkno;
	cur->blk_addr = bh->b_data;
	cur->entry = NULL;
	cur->real_addr = NULL;
}

static loff_t cur_sdirent_offset(struct ext3_cur_sdirent *cur) {
	return cur->real_addr - cur->blk_addr;
}

static loff_t blk_offset(struct _inode *inode, sector_t blkno) {
	return blkno << inode->i_blkbits;
}

static loff_t sdirent_offset(struct _inode *inode, struct ext3_sdirent *s) {
	return blk_offset(inode, s->blkno) + s->offset;
}

/* Take a cursor and an address after the current dirent, and
 * get either a reference to the cached dirent, or to a speculatively
 * written dirent */
static void _get_sdirent_read(struct ext3_cur_sdirent *cur, char *addr) {
	struct list_head *sdirent_listp;
	struct ext3_sdirent *sdirent;
	struct ext3_inode_info *inode = parent(cur->inode);
	int offset = addr - cur->blk_addr;	/* The desired offset within the page */

	/* Advance to the next speculative update with an offset >= pos */
	for(sdirent_listp = cur->next_sdirent,
				sdirent = sdirent_entry(sdirent_listp);
			sdirent_listp != &inode->sdentries &&
				sdirent_lt(sdirent_entry(sdirent_listp), cur->blkno, offset);
			sdirent_listp = sdirent_listp->next,
				sdirent = sdirent_entry(sdirent_listp));

	cur->next_sdirent = sdirent_listp;

	/* If we didn't land on a speculative dirent with that address, return a
	 * reference to the on-disk dirent. */
	if(sdirent_listp == &inode->sdentries || sdirent->blkno != cur->blkno
			|| sdirent->offset != offset) {
		cur->entry = (ext3_dirent*)addr;
	}
	else {
		cur->entry = &sdirent->_entry;
	}
	cur->real_addr = addr;
}

static inline void get_sdirent_read(struct ext3_cur_sdirent *cur, char *addr,
		int live_tx) {
	if(live_tx) {
		_get_sdirent_read(cur, addr);
	}
	else {
		cur->entry = (ext3_dirent*)addr;
		cur->real_addr = addr;
	}
}

/* Take an overlay sdirent and check the overlays on either side.  If
 * one is from the same block, assume that this buffer has already been
 * added to the list of those that will be dirtied by the transaction */
static void _dirty_sdirent_bh(struct ext3_sdirent *s,
		struct list_head *h) {
	if((s->sdentries.prev == h ||
				sdirent_entry(s->sdentries.prev)->blkno != s->blkno)
			&& (s->sdentries.next == h ||
				sdirent_entry(s->sdentries.next)->blkno != s->blkno)) {
		current->transaction->jbd.nblocks++;
	}
}

/* Take a read cursor for the current dirent and make it into a write cursor
 * by making an overlay dirent */
static void _get_sdirent_write(struct ext3_cur_sdirent *cur) {
	struct ext3_sdirent *spec =
		(struct ext3_sdirent*)kmem_cache_alloc(sdirent_cachep, GFP_NOFS);

	/* Owen, help.
	BUG_ON(cur->inode->vfs_inode.rw < ACCESS_RW);
	*/

	spec->blkno = cur->blkno;
	spec->offset = ((char*)cur->entry) - cur->blk_addr;
	memcpy(&spec->_entry, cur->entry, EXT3_DIR_REC_LEN(cur->entry->name_len));

	list_add_tail(&spec->sdentries, cur->next_sdirent);
	cur->next_sdirent = &spec->sdentries;
	cur->entry = &spec->_entry;

	_dirty_sdirent_bh(spec, &parent(cur->inode)->sdentries);
}

static inline void get_sdirent_write(struct ext3_cur_sdirent *cur,
		int live_tx) {
	/* If the real address and dirent are the same, we don't have a
	 * speculative entry */
	if(live_tx && (char*)cur->entry == cur->real_addr) {
		_get_sdirent_write(cur);
	}
}

/* Create a new blank overlay entry at the specified address */
static void _get_sdirent_blank(struct ext3_cur_sdirent *cur, char *addr) {
	struct _inode *inode = &cur->inode->_vfs_inode;
	loff_t spec_offset = blk_offset(inode, cur->blkno) +
		cur_sdirent_offset(cur);
	struct ext3_sdirent *spec =
		(struct ext3_sdirent*)kmem_cache_alloc(sdirent_cachep, GFP_NOFS);
	spec->blkno = cur->blkno;
	spec->offset = addr - cur->blk_addr;

	/* This pointer might be bogus if the first test succeeds, but
	 * it's more convenient to write it like this */
	if(cur->next_sdirent == &cur->inode->parent->sdentries ||
			sdirent_offset(inode, sdirent_entry(cur->next_sdirent)) > spec_offset) 
	{
		list_add_tail(&spec->sdentries, cur->next_sdirent);
	}
	else {
		list_add(&spec->sdentries, cur->next_sdirent);
	}
	cur->next_sdirent = &spec->sdentries;
	cur->entry = &spec->_entry;
	cur->real_addr = addr;

	_dirty_sdirent_bh(spec, &parent(cur->inode)->sdentries);
}

static inline void get_sdirent_blank(struct ext3_cur_sdirent *cur, char *addr,
		int live_tx) {
	if(live_tx) {
		_get_sdirent_blank(cur, addr);
	}
	else {
		cur->entry = (ext3_dirent*)addr;
		cur->real_addr = addr;
	}
}

/* To delete a speculative dirent, just drop it from the list */
static void _drop_sdirent(struct ext3_cur_sdirent *cur) {
	if((char*)cur->entry != cur->real_addr) {
		struct ext3_sdirent *sdir = container_of(cur->entry, struct ext3_sdirent,
				_entry);
		list_del(&sdir->sdentries);
		kmem_cache_free(sdirent_cachep, sdir);
	}
}

static inline void drop_sdirent(struct ext3_cur_sdirent *cur, int live_tx) {
	if(live_tx) {
		_drop_sdirent(cur);
	}
}

#endif
