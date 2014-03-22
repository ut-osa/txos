/*
 *  linux/fs/ext2/dir.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/dir.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext2 directory handling functions
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *
 * All code that works with directory layout had been switched to pagecache
 * and moved here. AV
 */

#include "ext2.h"
#include <linux/pagemap.h>
#include <linux/tx_dentry.h>
#include <linux/tx_inodes.h>
#include <linux/tx_super.h>
#include <linux/tx_file.h>

typedef struct ext2_dir_entry_2 ext2_dirent;

#ifdef CONFIG_TX_KSTM
/* Node in the linked list of speculative dentries */
struct ext2_sdirent {
	struct list_head sdentries;	/* List of speculative entries on this inode */
	int pageno;							/* Which page of the directory */
	int offset;							/* Offset within page */
	ext2_dirent _entry;				/* Actual overlay bytes */
};

static struct kmem_cache *sdirent_cachep;

int ext2_init_sdirent_cache() {
	int err = 0;
	sdirent_cachep = kmem_cache_create("ext2_sdirent",
			sizeof(struct ext2_sdirent), 0,
			SLAB_HWCACHE_ALIGN | SLAB_DESTROY_BY_RCU, NULL, NULL);
	if(sdirent_cachep == NULL) {
		err = -ENOMEM;
	}
	return err;
}

#define sdirent_entry(sdirent) \
	list_entry((sdirent), struct ext2_sdirent, sdentries)

#define sdirent_lt(sdirent, next_pageno, next_offset) \
	(((sdirent)->pageno < (next_pageno)) || \
	 ((sdirent)->pageno == (next_pageno) && (sdirent)->offset < (next_offset)))

static void init_cur_sdirent(struct ext2_cur_sdirent *cur,
		struct ext2_inode_info *inode) {
	cur->next_sdirent = inode->sdentries.next;
	cur->inode = inode;
}

static void init_cur_sdirent_page(struct ext2_cur_sdirent *cur,
		struct page *page, int live_tx) {
	struct inode *inode = page->mapping->host;
	/*
	 * dP: Owen, is inode already in the workset?
	if(live_tx) {
		inode = tx_cache_get_inode_ro(inode);
	}
	*/
	cur->inode = EXT2_I(inode);
	cur->next_sdirent = cur->inode->sdentries.next;
	cur->pageno = page->index;
	cur->kaddr = page_address(page);
	cur->entry = NULL;
	cur->real_addr = NULL;
}

static void move_cur_sdirent_page(struct ext2_cur_sdirent *cur,
		int pageno, char *kaddr) {
	if(unlikely(pageno <= cur->pageno)) {
		cur->next_sdirent = cur->inode->sdentries.next;
	}
	cur->pageno = pageno;
	cur->kaddr = kaddr;
	cur->entry = NULL;
	cur->real_addr = NULL;
}

static loff_t cur_sdirent_offset(struct ext2_cur_sdirent *cur) {
	return cur->real_addr - cur->kaddr;
}

static loff_t sdirent_offset(struct ext2_sdirent *s) {
	return (s->pageno << PAGE_CACHE_SHIFT) + s->offset;
}

/* Take a cursor and an address after the current dirent, and
 * get either a reference to the cached dirent, or to a speculatively
 * written dirent */
static void _get_sdirent_read(struct ext2_cur_sdirent *cur, char *addr) {
	struct list_head *sdirent_listp;
	struct ext2_sdirent *sdirent;
	struct ext2_inode_info *inode = cur->inode;
	int offset = addr - cur->kaddr;	/* The desired offset within the page */

	/* Advance to the next speculative update with an offset >= pos */
	for(sdirent_listp = cur->next_sdirent,
				sdirent = sdirent_entry(sdirent_listp);
			sdirent_listp != &cur->inode->sdentries &&
				sdirent_lt(sdirent_entry(sdirent_listp), cur->pageno, offset);
			sdirent_listp = sdirent_listp->next,
				sdirent = sdirent_entry(sdirent_listp));

	cur->next_sdirent = sdirent_listp;

	/* If we didn't land on a speculative dirent with that address, return a
	 * reference to the on-disk dirent. */
	if(sdirent_listp == &inode->sdentries || sdirent->pageno != cur->pageno
			|| sdirent->offset != offset) {
		cur->entry = (ext2_dirent*)addr;
	}
	else {
		cur->entry = &sdirent->_entry;
	}
	cur->real_addr = addr;
}

static inline void get_sdirent_read(struct ext2_cur_sdirent *cur, char *addr,
		int live_tx) {
	if(live_tx) {
		_get_sdirent_read(cur, addr);
	}
	else {
		cur->entry = (ext2_dirent*)addr;
		cur->real_addr = addr;
	}
}

/* Take a read cursor for the current dirent and make it into a write cursor
 * by making an overlay dirent */
static void _get_sdirent_write(struct ext2_cur_sdirent *cur) {
	struct ext2_sdirent *spec =
		(struct ext2_sdirent*)kmem_cache_alloc(sdirent_cachep, GFP_NOFS);

	spec->pageno = cur->pageno;
	spec->offset = ((char*)cur->entry) - cur->kaddr;
	memcpy(&spec->_entry, cur->entry, EXT2_DIR_REC_LEN(cur->entry->name_len));

	list_add_tail(&spec->sdentries, cur->next_sdirent);
	cur->next_sdirent = &spec->sdentries;
	cur->entry = &spec->_entry;
}

static inline void get_sdirent_write(struct ext2_cur_sdirent *cur,
		int live_tx) {
	/* If the real address and dirent are the same, we don't have a
	 * speculative entry */
	if(live_tx && (char*)cur->entry == cur->real_addr) {
		_get_sdirent_write(cur);
	}
}

/* Create a new blank overlay entry at the specified address */
static void _get_sdirent_blank(struct ext2_cur_sdirent *cur, char *addr) {
	loff_t spec_offset =
		(cur->pageno << PAGE_CACHE_SHIFT) + (addr - cur->kaddr);
	struct ext2_sdirent *spec =
		(struct ext2_sdirent*)kmem_cache_alloc(sdirent_cachep, GFP_NOFS);
	spec->pageno = cur->pageno;
	spec->offset = addr - cur->kaddr;

	/* This pointer might be bogus if the first test succeeds, but
	 * it's more convenient to write it like this */
	if(cur->next_sdirent == &cur->inode->sdentries ||
			sdirent_offset(sdirent_entry(cur->next_sdirent)) > spec_offset) {
		list_add_tail(&spec->sdentries, cur->next_sdirent);
	}
	else {
		list_add(&spec->sdentries, cur->next_sdirent);
	}
	cur->next_sdirent = &spec->sdentries;
	cur->entry = &spec->_entry;
	cur->real_addr = addr;
}

static inline void get_sdirent_blank(struct ext2_cur_sdirent *cur, char *addr,
		int live_tx) {
	if(live_tx) {
		_get_sdirent_blank(cur, addr);
	}
	else {
		cur->entry = (ext2_dirent*)addr;
		cur->real_addr = addr;
	}
}

/* To delete a speculative dirent, just drop it from the list */
static void _drop_sdirent(struct ext2_cur_sdirent *cur) {
	if((char*)cur->entry != cur->real_addr) {
		struct ext2_sdirent *sdir = container_of(cur->entry, struct ext2_sdirent,
				_entry);
		list_del(&sdir->sdentries);
		kmem_cache_free(sdirent_cachep, sdir);
	}
}

static inline void drop_sdirent(struct ext2_cur_sdirent *cur, int live_tx) {
	if(live_tx) {
		_drop_sdirent(cur);
	}
}

void ext2_init_sdirents(struct _inode *inode, enum access_mode mode) {
	INIT_LIST_HEAD(&EXT2_I(parent(inode))->sdentries);
}

#endif


/*
 * ext2 uses block-sized chunks. Arguably, sector-sized ones would be
 * more robust, but we have what we have
 */
static inline unsigned ext2_chunk_size(struct _inode *inode)
{
	//return i_get_sb_ro(inode)->s_blocksize;
	// Read only, unoptimized, never changes.  Screw it.
	return inode->i_sb->s_blocksize;
}

static inline void ext2_put_page(struct page *page)
{
	kunmap(page);
	page_cache_release(page);
}

static inline unsigned long dir_pages(struct _inode *inode)
{
	return (inode->i_size+PAGE_CACHE_SIZE-1)>>PAGE_CACHE_SHIFT;
}

/*
 * Return the offset into page `page_nr' of the last valid
 * byte in that page, plus one.
 */
static unsigned
ext2_last_byte(struct _inode *inode, unsigned long page_nr)
{
	unsigned last_byte = inode->i_size;

	last_byte -= page_nr << PAGE_CACHE_SHIFT;
	if (last_byte > PAGE_CACHE_SIZE)
		last_byte = PAGE_CACHE_SIZE;
	return last_byte;
}

static int ext2_commit_chunk(struct page *page, unsigned from, unsigned to)
{
	struct _inode *dir = tx_cache_get_inode(page->mapping->host);
	int err = 0;
	dir->i_version++;
	page->mapping->a_ops->commit_write(NULL, page, from, to);
	if (IS_DIRSYNC(dir))
		err = write_one_page(page, 1);
	else
		unlock_page(page);
	return err;
}

static void ext2_check_page(struct page *page)
{
	struct _inode *dir = tx_cache_get_inode_ro(page->mapping->host);
	struct super_block *sb = dir->i_sb;
	unsigned chunk_size = ext2_chunk_size(dir);
	char *kaddr = page_address(page);
	u32 max_inumber = le32_to_cpu(EXT2_SB(tx_cache_get_super_ro(sb))->s_es->s_inodes_count);
	unsigned offs, rec_len;
	unsigned limit = PAGE_CACHE_SIZE;
	struct ext2_cur_sdirent cur;
	char *error;
	int live_tx = live_transaction();


	if ((dir->i_size >> PAGE_CACHE_SHIFT) == page->index) {
		limit = dir->i_size & ~PAGE_CACHE_MASK;
		if (limit & (chunk_size - 1))
			goto Ebadsize;
		if (!limit)
			goto out;
	}
	for (offs = 0; offs <= limit - EXT2_DIR_REC_LEN(1); offs += rec_len) {
		init_cur_sdirent_page(&cur, page, live_tx);
		/* p = (ext2_dirent *)(kaddr + offs); */
		get_sdirent_read(&cur, kaddr + offs, live_tx);
		rec_len = le16_to_cpu(cur.entry->rec_len);

		if (rec_len < EXT2_DIR_REC_LEN(1))
			goto Eshort;
		if (rec_len & 3)
			goto Ealign;
		if (rec_len < EXT2_DIR_REC_LEN(cur.entry->name_len))
			goto Enamelen;
		if (((offs + rec_len - 1) ^ offs) & ~(chunk_size-1))
			goto Espan;
		if (le32_to_cpu(cur.entry->inode) > max_inumber)
			goto Einumber;
	}
	if (offs != limit)
		goto Eend;
out:
	SetPageChecked(page);
	return;

	/* Too bad, we had an error */

Ebadsize:
	ext2_error(sb, "ext2_check_page",
		"size of directory #%lu is not a multiple of chunk size",
		dir->i_ino
	);
	goto fail;
Eshort:
	error = "rec_len is smaller than minimal";
	goto bad_entry;
Ealign:
	error = "unaligned directory entry";
	goto bad_entry;
Enamelen:
	error = "rec_len is too small for name_len";
	goto bad_entry;
Espan:
	error = "directory entry across blocks";
	goto bad_entry;
Einumber:
	error = "inode out of bounds";
bad_entry:
	ext2_error (sb, "ext2_check_page", "bad entry in directory #%lu: %s - "
		"offset=%lu, inode=%lu, rec_len=%d, name_len=%d",
		dir->i_ino, error, (page->index<<PAGE_CACHE_SHIFT)+offs,
		(unsigned long) le32_to_cpu(cur.entry->inode),
		rec_len, cur.entry->name_len);
	goto fail;
Eend:
	/* p = (ext2_dirent *)(kaddr + offs); */
	get_sdirent_read(&cur, kaddr + offs, live_tx);
	ext2_error (sb, "ext2_check_page",
		"entry in directory #%lu spans the page boundary"
		"offset=%lu, inode=%lu",
		dir->i_ino, (page->index<<PAGE_CACHE_SHIFT)+offs,
		(unsigned long) le32_to_cpu(cur.entry->inode));
fail:
	SetPageChecked(page);
	SetPageError(page);
}

static struct page * ext2_get_page(struct _inode *dir, unsigned long n)
{
	struct address_space *mapping = dir->i_mapping;
	struct page *page;

	page = read_mapping_page(mapping, n, NULL);
	if (!IS_ERR(page)) {
		kmap(page);
		if (!PageChecked(page))
			ext2_check_page(page);
		if (PageError(page))
			goto fail;
	}
	return page;

fail:
	ext2_put_page(page);
	return ERR_PTR(-EIO);
}

#ifdef CONFIG_TX_KSTM
int ext2_commit_sdirents(struct ext2_inode_info *ei) {
	struct list_head *sdirent_listp, *nextpage_listp;
	int err = 0;

	/* Iterate through all speculative dentries */
	for(sdirent_listp = ei->sdentries.next;
			sdirent_listp != &ei->sdentries;
			sdirent_listp = nextpage_listp) {
		struct ext2_sdirent *sdirent_first = sdirent_entry(sdirent_listp);
		struct ext2_sdirent *sdirent_last;
		struct list_head *next_listp;
		struct page *page;
		char *kaddr;
		int pageno = sdirent_first->pageno;
		int from = sdirent_first->offset;
		int to;

		/* Find the last sdirent that references this page */
		for(; sdirent_listp->next != &ei->sdentries && 
				sdirent_entry(sdirent_listp->next)->pageno == pageno;
				sdirent_listp = sdirent_listp->next);
		sdirent_last = sdirent_entry(sdirent_listp);
		to = sdirent_last->offset + le16_to_cpu(sdirent_last->_entry.rec_len);
		nextpage_listp = sdirent_last->sdentries.next;

		page = ext2_get_page(tx_cache_get_inode(&ei->vfs_inode), pageno);
		err = PTR_ERR(page);
		if(IS_ERR(page))
			goto out;
		lock_page(page);
		kaddr = page_address(page);

		err = page->mapping->a_ops->prepare_write(NULL, page, from, to);
		if(err) {
			unlock_page(page);
			goto put_page;
		}

		/* Copy contents of all speculative dirents */
		for(sdirent_listp = &sdirent_first->sdentries;
				sdirent_listp != nextpage_listp;
				sdirent_listp = next_listp) {
			struct ext2_sdirent *src_sdirent = sdirent_entry(sdirent_listp);
			char *dst = kaddr + src_sdirent->offset;
			memcpy(dst, &src_sdirent->_entry,
					EXT2_DIR_REC_LEN(src_sdirent->_entry.name_len));

			next_listp = sdirent_listp->next;
			list_del(sdirent_listp);
			kmem_cache_free(sdirent_cachep, sdirent_listp);
		}

		err = ext2_commit_chunk(page, from, to);

put_page:
		ext2_put_page(page);
		if(err)
			break;
	}

out:
	mark_inode_dirty(&ei->vfs_inode);
	return err;
}

void ext2_abort_sdirents(struct ext2_inode_info *ei) {
	struct list_head *sdirent_listp, *next_listp;

	/* Iterate through all speculative dentries */
	for(sdirent_listp = ei->sdentries.next;
			sdirent_listp != &ei->sdentries;
			sdirent_listp = next_listp) {
		next_listp = sdirent_listp->next;
		list_del(sdirent_listp);
		kmem_cache_free(sdirent_cachep, sdirent_listp);
	}
}
#endif

/*
 * NOTE! unlike strncmp, ext2_match returns 1 for success, 0 for failure.
 *
 * len <= EXT2_NAME_LEN and de != NULL are guaranteed by caller.
 */
static inline int ext2_match (int len, const char * const name,
					struct ext2_dir_entry_2 * de)
{
	if (len != de->name_len)
		return 0;
	if (!de->inode)
		return 0;
	return !memcmp(name, de->name, len);
}

/*
 * p is at least 6 bytes before the end of page
 */
static inline ext2_dirent *ext2_next_entry(ext2_dirent *p)
{
	return (ext2_dirent *)((char*)p + le16_to_cpu(p->rec_len));
}

static inline unsigned 
ext2_validate_entry(char *base, unsigned offset, unsigned mask)
{
	ext2_dirent *de = (ext2_dirent*)(base + offset);
	ext2_dirent *p = (ext2_dirent*)(base + (offset&mask));
	while ((char*)p < (char*)de) {
		if (p->rec_len == 0)
			break;
		p = ext2_next_entry(p);
	}
	return (char *)p - base;
}

#ifdef CONFIG_TX_KSTM
static inline void ext2_next_entry_cur(struct ext2_cur_sdirent *cur,
		int live_tx) {
	char *cur_addr = cur->real_addr + le16_to_cpu(cur->entry->rec_len);
	get_sdirent_read(cur, cur_addr, live_tx);
}

static inline void
ext2_validate_entry_cur(struct ext2_cur_sdirent *cur, char *base,
		unsigned offset, unsigned mask, int live_tx) {
	char *cur_addr = base + (offset&mask);
	char *dest_addr = base + offset;
	cur->next_sdirent = cur->inode->sdentries.next;
	get_sdirent_read(cur, cur_addr, live_tx);
	while(cur->real_addr < dest_addr) {
		if(cur->entry->rec_len == 0)
			break;
		ext2_next_entry_cur(cur, live_tx);
	}
}
#endif

static unsigned char ext2_filetype_table[EXT2_FT_MAX] = {
	[EXT2_FT_UNKNOWN]	= DT_UNKNOWN,
	[EXT2_FT_REG_FILE]	= DT_REG,
	[EXT2_FT_DIR]		= DT_DIR,
	[EXT2_FT_CHRDEV]	= DT_CHR,
	[EXT2_FT_BLKDEV]	= DT_BLK,
	[EXT2_FT_FIFO]		= DT_FIFO,
	[EXT2_FT_SOCK]		= DT_SOCK,
	[EXT2_FT_SYMLINK]	= DT_LNK,
};

#define S_SHIFT 12
static unsigned char ext2_type_by_mode[S_IFMT >> S_SHIFT] = {
	[S_IFREG >> S_SHIFT]	= EXT2_FT_REG_FILE,
	[S_IFDIR >> S_SHIFT]	= EXT2_FT_DIR,
	[S_IFCHR >> S_SHIFT]	= EXT2_FT_CHRDEV,
	[S_IFBLK >> S_SHIFT]	= EXT2_FT_BLKDEV,
	[S_IFIFO >> S_SHIFT]	= EXT2_FT_FIFO,
	[S_IFSOCK >> S_SHIFT]	= EXT2_FT_SOCK,
	[S_IFLNK >> S_SHIFT]	= EXT2_FT_SYMLINK,
};

static inline void ext2_set_de_type(ext2_dirent *de, struct _inode *inode)
{
	mode_t mode = inode->i_mode;
	// DEP - living dangerously
	if (EXT2_HAS_INCOMPAT_FEATURE(i_get_sb(inode), EXT2_FEATURE_INCOMPAT_FILETYPE))
		de->file_type = ext2_type_by_mode[(mode & S_IFMT)>>S_SHIFT];
	else
		de->file_type = 0;
}

static int
ext2_readdir (struct file * filp, void * dirent, filldir_t filldir)
{
	struct _file *_filp = tx_cache_get_file(filp);
	loff_t pos = _filp->f_pos;
	struct _inode *inode = d_get_inode(f_get_dentry(_filp));
	struct super_block *sb = inode->i_sb;
	struct ext2_cur_sdirent cur_de;
	unsigned int offset = pos & ~PAGE_CACHE_MASK;
	unsigned long n = pos >> PAGE_CACHE_SHIFT;
	unsigned long npages = dir_pages(inode);
	unsigned chunk_mask = ~(ext2_chunk_size(inode)-1);
	unsigned char *types = NULL;
	int need_revalidate = _filp->f_version != inode->i_version;
	int live_tx = live_transaction();

	if (pos > inode->i_size - EXT2_DIR_REC_LEN(1))
		return 0;

	if (EXT2_HAS_INCOMPAT_FEATURE(tx_cache_get_super_ro(sb), EXT2_FEATURE_INCOMPAT_FILETYPE))
		types = ext2_filetype_table;

	init_cur_sdirent(&cur_de, EXT2_I(parent(inode)));
	for ( ; n < npages; n++, offset = 0) {
		char *kaddr, *limit;
		struct page *page = ext2_get_page(inode, n);

		if (IS_ERR(page)) {
			ext2_error(sb, __FUNCTION__,
				   "bad page in #%lu",
				   inode->i_ino);
			_filp->f_pos += PAGE_CACHE_SIZE - offset;
			return -EIO;
		}
		kaddr = page_address(page);
		move_cur_sdirent_page(&cur_de, n, kaddr);
		if (unlikely(need_revalidate)) {
			if (offset) {
				ext2_validate_entry_cur(&cur_de, kaddr, offset, chunk_mask,
						live_tx);
				offset = cur_sdirent_offset(&cur_de);
				_filp->f_pos = (n<<PAGE_CACHE_SHIFT) + offset;
			}
			_filp->f_version = inode->i_version;
			need_revalidate = 0;
		}

		/* de = (ext2_dirent *)(kaddr+offset); */
		get_sdirent_read(&cur_de, kaddr+offset, live_tx);

		limit = kaddr + ext2_last_byte(inode, n) - EXT2_DIR_REC_LEN(1);
		for ( ; cur_de.real_addr <= limit;
				ext2_next_entry_cur(&cur_de, live_tx)) {
			if (cur_de.entry->rec_len == 0) {
				ext2_error(sb, __FUNCTION__,
					"zero-length directory entry");
				ext2_put_page(page);
				return -EIO;
			}
			if (cur_de.entry->inode) {
				int over;
				unsigned char d_type = DT_UNKNOWN;

				if (types && cur_de.entry->file_type < EXT2_FT_MAX)
					d_type = types[cur_de.entry->file_type];

				offset = (char *)(cur_de.real_addr) - kaddr;
				over = filldir(dirent, cur_de.entry->name, cur_de.entry->name_len,
						(n<<PAGE_CACHE_SHIFT) | offset,
						le32_to_cpu(cur_de.entry->inode), d_type);
				if (over) {
					ext2_put_page(page);
					return 0;
				}
			}
			_filp->f_pos += le16_to_cpu(cur_de.entry->rec_len);
		}
		ext2_put_page(page);
	}
	return 0;
}

/*
 *	ext2_find_entry()
 *
 * finds an entry in the specified directory with the wanted name. It
 * returns the page in which the entry was found, and the entry itself
 * (as a parameter - res_dir). Page is returned mapped and unlocked.
 * Entry is guaranteed to be valid.
 */
void ext2_find_entry (struct ext2_cur_sdirent *cur_de, struct _inode * dir,
		      struct _dentry *dentry, struct page ** res_page)
{
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	unsigned reclen = EXT2_DIR_REC_LEN(namelen);
	unsigned long start, n;
	unsigned long npages = dir_pages(dir);
	struct page *page = NULL;
	struct ext2_inode_info *ei = EXT2_I(parent(dir));
	int live_tx = live_transaction();

	if (npages == 0)
		goto out;

	/* OFFSET_CACHE */
	*res_page = NULL;

	start = ei->i_dir_start_lookup;
	if (start >= npages)
		start = 0;
	n = start;
	
	init_cur_sdirent(cur_de, ei);
	do {
		char *kaddr;

		page = ext2_get_page(dir, n);
		if (!IS_ERR(page)) {
			kaddr = page_address(page);
			move_cur_sdirent_page(cur_de, n, kaddr);
			get_sdirent_read(cur_de, kaddr, live_tx);
			kaddr += ext2_last_byte(dir, n) - reclen;
			while (cur_de->real_addr <= kaddr) {
				if (cur_de->entry->rec_len == 0) {
					ext2_error(dir->i_sb, __FUNCTION__,
						"zero-length directory entry");
					ext2_put_page(page);
					goto out;
				}
				if (ext2_match (namelen, name, cur_de->entry))
					goto found;
				ext2_next_entry_cur(cur_de, live_tx);
			}
			ext2_put_page(page);
		}
		if (++n >= npages)
			n = 0;
		/* next page is past the blocks we've got */
		if (unlikely(n > (parent(dir)->i_blocks >> (PAGE_CACHE_SHIFT - 9)))) {
			ext2_error(dir->i_sb, __FUNCTION__,
				"dir %lu size %lld exceeds block count %llu",
				dir->i_ino, dir->i_size,
				   (unsigned long long)parent(dir)->i_blocks);
			goto out;
		}
	} while (n != start);
out:
	cur_de->real_addr = NULL;
	return;

found:
	*res_page = page;
	ei->i_dir_start_lookup = n;

	return;
}

void ext2_dotdot (struct ext2_cur_sdirent *cur, struct _inode *dir,
		  struct page **p)
{
	struct page *page = ext2_get_page(dir, 0);
	int live_tx = live_transaction();
	cur->entry = NULL;

	if (!IS_ERR(page)) {
		init_cur_sdirent_page(cur, page, live_tx);
		get_sdirent_read(cur, cur->kaddr, live_tx);
		ext2_next_entry_cur(cur, live_tx);
		*p = page;
	}
}

ino_t ext2_inode_by_name(struct _inode * dir, struct _dentry *dentry)
{
	ino_t res = 0;
	struct ext2_cur_sdirent cur_de;
	struct page *page;
	
	ext2_find_entry(&cur_de, dir, dentry, &page);
	if(cur_de.real_addr) {
		res = le32_to_cpu(cur_de.entry->inode);
		ext2_put_page(page);
	}
	return res;
}

/* Releases the page. */
void ext2_set_link(struct _inode *dir, struct ext2_cur_sdirent *cur_de,
		   struct page *page, struct _inode *inode)
{
	unsigned from = 0, to = 0;
	int err;
	int live_tx = live_transaction();

	lock_page(page);
	if(!live_tx) {
		from = cur_sdirent_offset(cur_de);
		to = from + le16_to_cpu(cur_de->entry->rec_len);
		err = page->mapping->a_ops->prepare_write(NULL, page, from, to);
		BUG_ON(err);
	}
	get_sdirent_write(cur_de, live_tx);
	cur_de->entry->inode = cpu_to_le32(inode->i_ino);
	ext2_set_de_type (cur_de->entry, inode);
	if(!live_tx) {
		err = ext2_commit_chunk(page, from, to);
	}
	else {
		unlock_page(page);
	}
	ext2_put_page(page);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
	_EXT2_I(dir)->i_flags &= ~EXT2_BTREE_FL;
	mark_inode_dirty(parent(dir));
}

/*
 *	Parent is locked.
 */
int ext2_add_link (struct _dentry *dentry, struct _inode *inode)
{
	struct _inode *dir = dentry_get_inode(dentry->d_parent);
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	unsigned chunk_size = ext2_chunk_size(dir);
	unsigned reclen = EXT2_DIR_REC_LEN(namelen);
	unsigned short rec_len, name_len;
	struct page *page = NULL;
	struct ext2_cur_sdirent cur_de;
	unsigned long npages = dir_pages(dir);
	unsigned long n;
	char *kaddr;
	unsigned from = 0, to = 0;
	int err;
	int live_tx = live_transaction();

	/*
	 * We take care of directory expansion in the same loop.
	 * This code plays outside i_size, so it locks the page
	 * to protect that region.
	 */
	init_cur_sdirent(&cur_de, EXT2_I(parent(dir)));
	for (n = 0; n <= npages; n++) {
		char *dir_end;

		page = ext2_get_page(dir, n);
		err = PTR_ERR(page);
		if (IS_ERR(page))
			goto out;
		lock_page(page);
		kaddr = page_address(page);
		move_cur_sdirent_page(&cur_de, n, kaddr);
		dir_end = kaddr + ext2_last_byte(dir, n);

		/* de = (char*)kaddr; */
		get_sdirent_read(&cur_de, kaddr, live_tx);

		kaddr += PAGE_CACHE_SIZE - reclen;
		while (cur_de.real_addr <= kaddr) {
			if (cur_de.real_addr == dir_end) {
				/* We hit i_size */
				name_len = 0;
				rec_len = chunk_size;

				get_sdirent_blank(&cur_de, cur_de.real_addr, live_tx);

				cur_de.entry->rec_len = cpu_to_le16(chunk_size);
				cur_de.entry->inode = 0;
				goto got_it;
			}
			if (cur_de.entry->rec_len == 0) {
				ext2_error(dir->i_sb, __FUNCTION__,
					"zero-length directory entry");
				err = -EIO;
				goto out_unlock;
			}
			err = -EEXIST;
			if (ext2_match (namelen, name, cur_de.entry))
				goto out_unlock;
			name_len = EXT2_DIR_REC_LEN(cur_de.entry->name_len);
			rec_len = le16_to_cpu(cur_de.entry->rec_len);
			if (!cur_de.entry->inode && rec_len >= reclen) {
				goto got_it;
			}
			if (rec_len >= name_len + reclen)
				goto got_it;

			/* de = (ext2_dirent *) ((char *) de + rec_len); */
			get_sdirent_read(&cur_de, cur_de.real_addr + rec_len, live_tx);
		}
		unlock_page(page);
		ext2_put_page(page);
	}
	BUG();
	return -EINVAL;

got_it:
	if(!live_tx) {
		from = cur_sdirent_offset(&cur_de);
		to = from + rec_len;
		err = page->mapping->a_ops->prepare_write(NULL, page, from, to);
		if(err) {
			goto out_unlock;
		}
	}
	get_sdirent_write(&cur_de, live_tx);
	if(cur_de.entry->inode) {
		/* Compact this record then create a new speculative entry
		 * in the blank space */
		cur_de.entry->rec_len = cpu_to_le16(name_len);
		get_sdirent_blank(&cur_de, cur_de.real_addr + name_len, live_tx);
		cur_de.entry->rec_len = cpu_to_le16(rec_len - name_len);
	}
	/*
	from = (char*)de - (char*)page_address(page);
	to = from + rec_len;
	err = page->mapping->a_ops->prepare_write(NULL, page, from, to);
	if (err)
		goto out_unlock;
	if (de->inode) {
		ext2_dirent *de1 = (ext2_dirent *) ((char *) de + name_len);
		de1->rec_len = cpu_to_le16(rec_len - name_len);
		de->rec_len = cpu_to_le16(name_len);
		de = de1;
	}
	*/
	cur_de.entry->name_len = namelen;
	memcpy (cur_de.entry->name, name, namelen);
	cur_de.entry->inode = cpu_to_le32(inode->i_ino);
	ext2_set_de_type (cur_de.entry, inode);
	if(!live_tx) {
		err = ext2_commit_chunk(page, from, to);
	}
	else {
		unlock_page(page);
		err = 0;
	}
	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
	_EXT2_I(dir)->i_flags &= ~EXT2_BTREE_FL;
	mark_inode_dirty(parent(dir));
	/* OFFSET_CACHE */
out_put:
	ext2_put_page(page);
out:
	return err;
out_unlock:
	unlock_page(page);
	goto out_put;
}

/*
 * ext2_delete_entry deletes a directory entry by merging it with the
 * previous entry. Page is up-to-date. Releases the page.
 */
int ext2_delete_entry (struct ext2_cur_sdirent * dir, struct page * page)
{
	struct address_space *mapping = page->mapping;
	struct _inode *inode = tx_cache_get_inode(mapping->host);
	char *kaddr = page_address(page);
	unsigned from =
		(dir->real_addr - kaddr) & ~(ext2_chunk_size(inode)-1);
	unsigned to;
	struct ext2_cur_sdirent pde = {.real_addr = NULL};
	struct ext2_cur_sdirent cur_de;
	int err;
	int live_tx = live_transaction();

	init_cur_sdirent_page(&cur_de, page, live_tx);
	get_sdirent_read(&cur_de, kaddr+from, live_tx);
	while (cur_de.real_addr < dir->real_addr) {
		if (cur_de.entry->rec_len == 0) {
			ext2_error(inode->i_sb, __FUNCTION__,
				"zero-length directory entry");
			err = -EIO;
			goto out;
		}
		pde = cur_de;
		ext2_next_entry_cur(&cur_de, live_tx);
	}
	to = (cur_de.real_addr - kaddr) + le16_to_cpu(cur_de.entry->rec_len);
	if (pde.real_addr)
		from = pde.real_addr - (char*)page_address(page);
	lock_page(page);
	if(!live_tx) {
		err = mapping->a_ops->prepare_write(NULL, page, from, to);
		BUG_ON(err);
	}
	if (pde.real_addr) {
		get_sdirent_write(&pde, live_tx);
		pde.entry->rec_len = cpu_to_le16(to-from);
		drop_sdirent(&cur_de, live_tx);
	}
	else {
		get_sdirent_write(&cur_de, live_tx);
		cur_de.entry->inode = 0;
	}
	if(!live_tx) {
		err = ext2_commit_chunk(page, from, to);
	}
	else {
		unlock_page(page);
		err = 0;
	}
	inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;
	_EXT2_I(inode)->i_flags &= ~EXT2_BTREE_FL;
	mark_inode_dirty(parent(inode));
out:
	ext2_put_page(page);
	return err;
}

/*
 * Set the first fragment of directory.
 */
int ext2_make_empty(struct _inode *inode, struct _inode *parent)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page = grab_cache_page(mapping, 0);
	unsigned chunk_size = ext2_chunk_size(inode);
	struct ext2_dir_entry_2 * de;
	int err;
	void *kaddr;

	if (!page)
		return -ENOMEM;
	err = mapping->a_ops->prepare_write(NULL, page, 0, chunk_size);
	if (err) {
		unlock_page(page);
		goto fail;
	}
	kaddr = kmap_atomic(page, KM_USER0);
	memset(kaddr, 0, chunk_size);
	de = (struct ext2_dir_entry_2 *)kaddr;
	de->name_len = 1;
	de->rec_len = cpu_to_le16(EXT2_DIR_REC_LEN(1));
	memcpy (de->name, ".\0\0", 4);
	de->inode = cpu_to_le32(inode->i_ino);
	ext2_set_de_type (de, inode);

	de = (struct ext2_dir_entry_2 *)(kaddr + EXT2_DIR_REC_LEN(1));
	de->name_len = 2;
	de->rec_len = cpu_to_le16(chunk_size - EXT2_DIR_REC_LEN(1));
	de->inode = cpu_to_le32(parent->i_ino);
	memcpy (de->name, "..\0", 4);
	ext2_set_de_type (de, inode);
	kunmap_atomic(kaddr, KM_USER0);
	err = ext2_commit_chunk(page, 0, chunk_size);
fail:
	page_cache_release(page);
	return err;
}

/*
 * routine to check that the specified directory is empty (for rmdir)
 */
int ext2_empty_dir (struct _inode * inode)
{
	struct page *page = NULL;
	unsigned long i, npages = dir_pages(inode);
	struct ext2_cur_sdirent cur_de;
	int live_tx = live_transaction();

	init_cur_sdirent(&cur_de, EXT2_I(parent(inode)));
	for (i = 0; i < npages; i++) {
		char *kaddr;
		page = ext2_get_page(inode, i);

		if (IS_ERR(page))
			continue;

		kaddr = page_address(page);
		move_cur_sdirent_page(&cur_de, i, kaddr);
		get_sdirent_read(&cur_de, kaddr, live_tx);
		kaddr += ext2_last_byte(inode, i) - EXT2_DIR_REC_LEN(1);

		while (cur_de.real_addr <= kaddr) {
			if (cur_de.entry->rec_len == 0) {
				ext2_error(inode->i_sb, __FUNCTION__,
					"zero-length directory entry");
				printk("kaddr=%p, de=%p\n", kaddr, cur_de.real_addr);
				goto not_empty;
			}
			if (cur_de.entry->inode != 0) {
				/* check for . and .. */
				if (cur_de.entry->name[0] != '.')
					goto not_empty;
				if (cur_de.entry->name_len > 2)
					goto not_empty;
				if (cur_de.entry->name_len < 2) {
					if (cur_de.entry->inode !=
						 cpu_to_le32(inode->i_ino))
						goto not_empty;
				} else if (cur_de.entry->name[1] != '.')
					goto not_empty;
			}
			ext2_next_entry_cur(&cur_de, live_tx);
		}
		ext2_put_page(page);
	}
	return 1;

not_empty:
	ext2_put_page(page);
	return 0;
}

const struct file_operations ext2_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir = ext2_readdir,
	.ioctl		= ext2_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ext2_compat_ioctl,
#endif
	.fsync		= ext2_sync_file,
};
