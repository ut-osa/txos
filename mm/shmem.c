/*
 * Resizable virtual memory filesystem for Linux.
 *
 * Copyright (C) 2000 Linus Torvalds.
 *		 2000 Transmeta Corp.
 *		 2000-2001 Christoph Rohland
 *		 2000-2001 SAP AG
 *		 2002 Red Hat Inc.
 * Copyright (C) 2002-2005 Hugh Dickins.
 * Copyright (C) 2002-2005 VERITAS Software Corporation.
 * Copyright (C) 2004 Andi Kleen, SuSE Labs
 *
 * Extended attribute support for tmpfs:
 * Copyright (c) 2004, Luke Kenneth Casson Leighton <lkcl@lkcl.net>
 * Copyright (c) 2004 Red Hat, Inc., James Morris <jmorris@redhat.com>
 *
 * This file is released under the GPL.
 */

/*
 * This virtual memory filesystem is heavily based on the ramfs. It
 * extends ramfs by the ability to use swap and honor resource limits
 * which makes it a completely usable filesystem.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/generic_acl.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/backing-dev.h>
#include <linux/shmem_fs.h>
#include <linux/mount.h>
#include <linux/writeback.h>
#include <linux/vfs.h>
#include <linux/blkdev.h>
#include <linux/security.h>
#include <linux/swapops.h>
#include <linux/mempolicy.h>
#include <linux/namei.h>
#include <linux/ctype.h>
#include <linux/migrate.h>
#include <linux/highmem.h>
#include <linux/backing-dev.h>

#include <asm/uaccess.h>
#include <asm/div64.h>
#include <asm/pgtable.h>

#include <linux/transaction.h>
#include <linux/tx_inodes.h>
#include <linux/tx_dentry.h>
#include <linux/tx_super.h>
#include <linux/tx_list.h>
#include <linux/tx_file.h>
#include <linux/osamagic.h>

/* This magic number is used in glibc for posix shared memory */
#define TMPFS_MAGIC	0x01021994

#define ENTRIES_PER_PAGE (PAGE_CACHE_SIZE/sizeof(unsigned long))
#define ENTRIES_PER_PAGEPAGE (ENTRIES_PER_PAGE*ENTRIES_PER_PAGE)
#define BLOCKS_PER_PAGE  (PAGE_CACHE_SIZE/512)

#define SHMEM_MAX_INDEX  (SHMEM_NR_DIRECT + (ENTRIES_PER_PAGEPAGE/2) * (ENTRIES_PER_PAGE+1))
#define SHMEM_MAX_BYTES  ((unsigned long long)SHMEM_MAX_INDEX << PAGE_CACHE_SHIFT)

#define VM_ACCT(size)    (PAGE_CACHE_ALIGN(size) >> PAGE_SHIFT)

/* info->flags needs VM_flags to handle pagein/truncate races efficiently */
#define SHMEM_PAGEIN	 VM_READ
#define SHMEM_TRUNCATE	 VM_WRITE

/* Definition to limit shmem_truncate's steps between cond_rescheds */
#define LATENCY_LIMIT	 64

/* Pretend that each entry is of this size in directory's i_size */
#define BOGO_DIRENT_SIZE 20

/* Flag allocation requirements to shmem_getpage and shmem_swp_alloc */
enum sgp_type {
	SGP_QUICK,	/* don't try more than file page cache lookup */
	SGP_READ,	/* don't exceed i_size, don't allocate page */
	SGP_CACHE,	/* don't exceed i_size, may allocate page */
	SGP_WRITE,	/* may exceed i_size, may allocate page */
};

/* DEP 9/5/08 - I think it is ok to just always lock these now */
static void info_lock(struct shmem_inode_info *info)
{
	spin_lock(&info->lock);
}

static void info_unlock(struct shmem_inode_info *info)
{
	spin_unlock(&info->lock);
}

static int shmem_getpage(struct inode *inode, unsigned long idx,
			 struct page **pagep, enum sgp_type sgp, int *type);

static inline struct page *shmem_dir_alloc(gfp_t gfp_mask)
{
	/*
	 * The above definition of ENTRIES_PER_PAGE, and the use of
	 * BLOCKS_PER_PAGE on indirect pages, assume PAGE_CACHE_SIZE:
	 * might be reconsidered if it ever diverges from PAGE_SIZE.
	 */
	return alloc_pages(gfp_mask, PAGE_CACHE_SHIFT-PAGE_SHIFT);
}

static inline void shmem_dir_free(struct page *page)
{
	__free_pages(page, PAGE_CACHE_SHIFT-PAGE_SHIFT);
}

static struct page **shmem_dir_map(struct page *page)
{
	return (struct page **)kmap_atomic(page, KM_USER0);
}

static inline void shmem_dir_unmap(struct page **dir)
{
	kunmap_atomic(dir, KM_USER0);
}

static swp_entry_t *shmem_swp_map(struct page *page)
{
	return (swp_entry_t *)kmap_atomic(page, KM_USER1);
}

static inline void shmem_swp_balance_unmap(void)
{
	/*
	 * When passing a pointer to an i_direct entry, to code which
	 * also handles indirect entries and so will shmem_swp_unmap,
	 * we must arrange for the preempt count to remain in balance.
	 * What kmap_atomic of a lowmem page does depends on config
	 * and architecture, so pretend to kmap_atomic some lowmem page.
	 */
	(void) kmap_atomic(ZERO_PAGE(0), KM_USER1);
}

static inline void shmem_swp_unmap(swp_entry_t *entry)
{
	kunmap_atomic(entry, KM_USER1);
}

static inline struct shmem_sb_info *SHMEM_SB(struct _super_block *sb)
{
	return sb->s_fs_info;
}

/*
 * shmem_file_setup pre-accounts the whole fixed size of a VM object,
 * for shared memory and for shared anonymous (/dev/zero) mappings
 * (unless MAP_NORESERVE and sysctl_overcommit_memory <= 1),
 * consistent with the pre-accounting of private mappings ...
 */
static inline int shmem_acct_size(unsigned long flags, loff_t size)
{
	return (flags & VM_ACCOUNT)?
		security_vm_enough_memory(VM_ACCT(size)): 0;
}

static inline void shmem_unacct_size(unsigned long flags, loff_t size)
{
	if (flags & VM_ACCOUNT)
		vm_unacct_memory(VM_ACCT(size));
}

/*
 * ... whereas tmpfs objects are accounted incrementally as
 * pages are allocated, in order to allow huge sparse files.
 * shmem_getpage reports shmem_acct_block failure as -ENOSPC not -ENOMEM,
 * so that a failure on a sparse tmpfs mapping will give SIGBUS not OOM.
 */
static inline int shmem_acct_block(unsigned long flags)
{
	return (flags & VM_ACCOUNT)?
		0: security_vm_enough_memory(VM_ACCT(PAGE_CACHE_SIZE));
}

static inline void shmem_unacct_blocks(unsigned long flags, long pages)
{
	if (!(flags & VM_ACCOUNT))
		vm_unacct_memory(pages * VM_ACCT(PAGE_CACHE_SIZE));
}

static const struct super_operations shmem_ops;
static const struct address_space_operations shmem_aops;
static const struct file_operations shmem_file_operations;
static const struct inode_operations shmem_inode_operations;
static const struct inode_operations shmem_dir_inode_operations;
static const struct inode_operations shmem_special_inode_operations;
static struct vm_operations_struct shmem_vm_ops;

static struct backing_dev_info shmem_backing_dev_info  __read_mostly = {
	.ra_pages	= 0,	/* No readahead */
	.capabilities	= BDI_CAP_NO_ACCT_DIRTY | BDI_CAP_NO_WRITEBACK,
	.unplug_io_fn	= default_unplug_io_fn,
};

static TX_LIST(shmem_swaplist);
static DEFINE_SPINLOCK(shmem_swaplist_lock);

static inline struct tx_list_head *get_swaplist(void){

	struct tx_list_head *rv = &shmem_swaplist;

	if(live_transaction()){
		spin_lock(&shmem_swaplist_lock);
		record_tx_lock(&shmem_swaplist_lock, SPIN_LOCK);
		rv = tx_cache_get_tx_list_head(&shmem_swaplist);
		spin_unlock(&shmem_swaplist_lock);
		record_tx_unlock(&shmem_swaplist_lock, SPIN_LOCK);
	}
	return rv;
}

static inline void lock_swaplist(void){
	if(!live_transaction()) {
		spin_lock(&shmem_swaplist_lock);
		check_list_asymmetric_conflict(&shmem_swaplist);
	}
}

static inline void unlock_swaplist(void){
	if(!live_transaction())
		spin_unlock(&shmem_swaplist_lock);
}

static void shmem_free_blocks(struct _inode *inode, long pages)
{
	struct shmem_sb_info *sbinfo = SHMEM_SB(i_get_sb(inode));
	if (sbinfo->max_blocks) {
		spin_lock(&sbinfo->stat_lock);
		sbinfo->free_blocks += pages;
		parent(inode)->i_blocks -= pages*BLOCKS_PER_PAGE;
		spin_unlock(&sbinfo->stat_lock);
	}
}

/*
 * shmem_recalc_inode - recalculate the size of an inode
 *
 * @inode: inode to recalc
 *
 * We have to calculate the free blocks since the mm can drop
 * undirtied hole pages behind our back.
 *
 * But normally   info->alloced == inode->i_mapping->nrpages + info->swapped
 * So mm freed is info->alloced - (inode->i_mapping->nrpages + info->swapped)
 *
 * It has to be called with the spinlock held.
 */
static void shmem_recalc_inode(struct _inode *inode)
{
	struct _shmem_inode_info *info = _SHMEM_I(inode);
	long freed;

	freed = info->alloced - info->swapped - inode->i_mapping->nrpages;
	if (freed > 0) {
		info->alloced -= freed;
		shmem_unacct_blocks(info->flags, freed);
		shmem_free_blocks(inode, freed);
	}
}

/*
 * shmem_swp_entry - find the swap vector position in the info structure
 *
 * @info:  info structure for the inode
 * @index: index of the page to find
 * @page:  optional page to add to the structure. Has to be preset to
 *         all zeros
 *
 * If there is no space allocated yet it will return NULL when
 * page is NULL, else it will use the page for the needed block,
 * setting it to NULL on return to indicate that it has been used.
 *
 * The swap vector is organized the following way:
 *
 * There are SHMEM_NR_DIRECT entries directly stored in the
 * shmem_inode_info structure. So small files do not need an addional
 * allocation.
 *
 * For pages with index > SHMEM_NR_DIRECT there is the pointer
 * i_indirect which points to a page which holds in the first half
 * doubly indirect blocks, in the second half triple indirect blocks:
 *
 * For an artificial ENTRIES_PER_PAGE = 4 this would lead to the
 * following layout (for SHMEM_NR_DIRECT == 16):
 *
 * i_indirect -> dir --> 16-19
 * 	      |	     +-> 20-23
 * 	      |
 * 	      +-->dir2 --> 24-27
 * 	      |	       +-> 28-31
 * 	      |	       +-> 32-35
 * 	      |	       +-> 36-39
 * 	      |
 * 	      +-->dir3 --> 40-43
 * 	       	       +-> 44-47
 * 	      	       +-> 48-51
 * 	      	       +-> 52-55
 */
static swp_entry_t *shmem_swp_entry(struct _shmem_inode_info *info, unsigned long index, struct page **page)
{
	unsigned long offset;
	struct page **dir;
	struct page *subdir;

	if (index < SHMEM_NR_DIRECT) {
		shmem_swp_balance_unmap();
		return info->i_direct+index;
	}
	if (!info->i_indirect) {
		if (page) {
			info->i_indirect = *page;
			*page = NULL;
		}
		return NULL;			/* need another page */
	}

	index -= SHMEM_NR_DIRECT;
	offset = index % ENTRIES_PER_PAGE;
	index /= ENTRIES_PER_PAGE;
	dir = shmem_dir_map(info->i_indirect);

	if (index >= ENTRIES_PER_PAGE/2) {
		index -= ENTRIES_PER_PAGE/2;
		dir += ENTRIES_PER_PAGE/2 + index/ENTRIES_PER_PAGE;
		index %= ENTRIES_PER_PAGE;
		subdir = *dir;
		if (!subdir) {
			if (page) {
				*dir = *page;
				*page = NULL;
			}
			shmem_dir_unmap(dir);
			return NULL;		/* need another page */
		}
		shmem_dir_unmap(dir);
		dir = shmem_dir_map(subdir);
	}

	dir += index;
	subdir = *dir;
	if (!subdir) {
		if (!page || !(subdir = *page)) {
			shmem_dir_unmap(dir);
			return NULL;		/* need a page */
		}
		*dir = subdir;
		*page = NULL;
	}
	shmem_dir_unmap(dir);
	return shmem_swp_map(subdir) + offset;
}

static void shmem_swp_set(struct _shmem_inode_info *info, swp_entry_t *entry, unsigned long value)
{
	long incdec = value? 1: -1;

	entry->val = value;
	info->swapped += incdec;
	if ((unsigned long)(entry - info->i_direct) >= SHMEM_NR_DIRECT) {
		struct page *page = kmap_atomic_to_page(entry);
		set_page_private(page, page_private(page) + incdec);
	}
}

/*
 * shmem_swp_alloc - get the position of the swap entry for the page.
 *                   If it does not exist allocate the entry.
 *
 * @info:	info structure for the inode
 * @index:	index of the page to find
 * @sgp:	check and recheck i_size? skip allocation?
 */
static swp_entry_t *shmem_swp_alloc(struct shmem_inode_info *info, unsigned long index, enum sgp_type sgp)
{
	struct inode *inode = &info->vfs_inode;
	struct _inode *_inode = tx_cache_get_inode(inode);
	struct _shmem_inode_info *_info = _SHMEM_I(_inode);
	struct shmem_sb_info *sbinfo = SHMEM_SB(i_get_sb(_inode));
	struct page *page = NULL;
	swp_entry_t *entry;

	if (sgp != SGP_WRITE &&
	    ((loff_t) index << PAGE_CACHE_SHIFT) >= i_size_read(_inode))
		return ERR_PTR(-EINVAL);

	while (!(entry = shmem_swp_entry(_info, index, &page))) {
		if (sgp == SGP_READ)
			return shmem_swp_map(ZERO_PAGE(0));
		/*
		 * Test free_blocks against 1 not 0, since we have 1 data
		 * page (and perhaps indirect index pages) yet to allocate:
		 * a waste to allocate index if we cannot allocate data.
		 */
		if (sbinfo->max_blocks) {
			spin_lock(&sbinfo->stat_lock);
			if (sbinfo->free_blocks <= 1) {
				spin_unlock(&sbinfo->stat_lock);
				return ERR_PTR(-ENOSPC);
			}
			sbinfo->free_blocks--;
			inode->i_blocks += BLOCKS_PER_PAGE;
			spin_unlock(&sbinfo->stat_lock);
		}

		info_unlock(info);
		page = shmem_dir_alloc(mapping_gfp_mask(_inode->i_mapping) | __GFP_ZERO);
		if (page)
			set_page_private(page, 0);
		info_lock(info);

		if (!page) {
			shmem_free_blocks(_inode, 1);
			return ERR_PTR(-ENOMEM);
		}
		if (sgp != SGP_WRITE &&
		    ((loff_t) index << PAGE_CACHE_SHIFT) >= i_size_read(_inode)) {
			entry = ERR_PTR(-EINVAL);
			break;
		}
		if (_info->next_index <= index)
			_info->next_index = index + 1;
	}
	if (page) {
		/* another task gave its page, or truncated the file */
		shmem_free_blocks(_inode, 1);
		shmem_dir_free(page);
	}
	if (_info->next_index <= index && !IS_ERR(entry))
		_info->next_index = index + 1;
	return entry;
}

/*
 * shmem_free_swp - free some swap entries in a directory
 *
 * @dir:        pointer to the directory
 * @edir:       pointer after last entry of the directory
 * @punch_lock: pointer to spinlock when needed for the holepunch case
 */
static int shmem_free_swp(swp_entry_t *dir, swp_entry_t *edir,
			  struct shmem_inode_info *punch_lock)
{
	struct shmem_inode_info *punch_unlock = NULL;
	swp_entry_t *ptr;
	int freed = 0;

	for (ptr = dir; ptr < edir; ptr++) {
		if (ptr->val) {
			if (unlikely(punch_lock)) {
				punch_unlock = punch_lock;
				punch_lock = NULL;
				info_lock(punch_unlock);
				if (!ptr->val)
					continue;
			}
			free_swap_and_cache(*ptr);
			*ptr = (swp_entry_t){0};
			freed++;
		}
	}
	if (punch_unlock)
		info_unlock(punch_unlock);
	return freed;
}

static int shmem_map_and_free_swp(struct page *subdir, int offset,
		int limit, struct page ***dir, struct shmem_inode_info *punch_lock)
{
	swp_entry_t *ptr;
	int freed = 0;

	ptr = shmem_swp_map(subdir);
	for (; offset < limit; offset += LATENCY_LIMIT) {
		int size = limit - offset;
		if (size > LATENCY_LIMIT)
			size = LATENCY_LIMIT;
		freed += shmem_free_swp(ptr+offset, ptr+offset+size,
							punch_lock);
		if (need_resched()) {
			shmem_swp_unmap(ptr);
			if (*dir) {
				shmem_dir_unmap(*dir);
				*dir = NULL;
			}
			cond_resched();
			ptr = shmem_swp_map(subdir);
		}
	}
	shmem_swp_unmap(ptr);
	return freed;
}

static void shmem_free_pages(struct list_head *next)
{
	struct page *page;
	int freed = 0;

	do {
		page = container_of(next, struct page, lru);
		next = next->next;
		shmem_dir_free(page);
		freed++;
		if (freed >= LATENCY_LIMIT) {
			cond_resched();
			freed = 0;
		}
	} while (next);
}

static void shmem_truncate_range(struct _inode *inode, loff_t start, loff_t end)
{
	struct _shmem_inode_info *_info = _SHMEM_I(inode);
	struct shmem_inode_info *info = parent(_info);
	unsigned long idx;
	unsigned long size;
	unsigned long limit;
	unsigned long stage;
	unsigned long diroff;
	struct page **dir;
	struct page *topdir;
	struct page *middir;
	struct page *subdir;
	swp_entry_t *ptr;
	LIST_HEAD(pages_to_free);
	long nr_pages_to_free = 0;
	long nr_swaps_freed = 0;
	int offset;
	int freed;
	int punch_hole;
	struct shmem_inode_info *needs_lock;
	struct shmem_inode_info *punch_lock;
	unsigned long upper_limit;

	inode->i_ctime = inode->i_mtime = CURRENT_TIME;
	idx = (start + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	if (idx >= _info->next_index)
		return;

	info_lock(info);
	_info->flags |= SHMEM_TRUNCATE;
	if (likely(end == (loff_t) -1)) {
		limit = _info->next_index;
		upper_limit = SHMEM_MAX_INDEX;
		_info->next_index = idx;
		needs_lock = NULL;
		punch_hole = 0;
	} else {
		if (end + 1 >= inode->i_size) {	/* we may free a little more */
			limit = (inode->i_size + PAGE_CACHE_SIZE - 1) >>
							PAGE_CACHE_SHIFT;
			upper_limit = SHMEM_MAX_INDEX;
		} else {
			limit = (end + 1) >> PAGE_CACHE_SHIFT;
			upper_limit = limit;
		}
		needs_lock = info;
		punch_hole = 1;
	}

	topdir = _info->i_indirect;
	if (topdir && idx <= SHMEM_NR_DIRECT && !punch_hole) {
		_info->i_indirect = NULL;
		nr_pages_to_free++;
		list_add(&topdir->lru, &pages_to_free);
	}
	info_unlock(info);

	if (_info->swapped && idx < SHMEM_NR_DIRECT) {
		ptr = _info->i_direct;
		size = limit;
		if (size > SHMEM_NR_DIRECT)
			size = SHMEM_NR_DIRECT;
		nr_swaps_freed = shmem_free_swp(ptr+idx, ptr+size, needs_lock);
	}

	/*
	 * If there are no indirect blocks or we are punching a hole
	 * below indirect blocks, nothing to be done.
	 */
	if (!topdir || limit <= SHMEM_NR_DIRECT)
		goto done2;

	/*
	 * The truncation case has already dropped info->lock, and we're safe
	 * because i_size and next_index have already been lowered, preventing
	 * access beyond.  But in the punch_hole case, we still need to take
	 * the lock when updating the swap directory, because there might be
	 * racing accesses by shmem_getpage(SGP_CACHE), shmem_unuse_inode or
	 * shmem_writepage.  However, whenever we find we can remove a whole
	 * directory page (not at the misaligned start or end of the range),
	 * we first NULLify its pointer in the level above, and then have no
	 * need to take the lock when updating its contents: needs_lock and
	 * punch_lock (either pointing to info->lock or NULL) manage this.
	 */

	upper_limit -= SHMEM_NR_DIRECT;
	limit -= SHMEM_NR_DIRECT;
	idx = (idx > SHMEM_NR_DIRECT)? (idx - SHMEM_NR_DIRECT): 0;
	offset = idx % ENTRIES_PER_PAGE;
	idx -= offset;

	dir = shmem_dir_map(topdir);
	stage = ENTRIES_PER_PAGEPAGE/2;
	if (idx < ENTRIES_PER_PAGEPAGE/2) {
		middir = topdir;
		diroff = idx/ENTRIES_PER_PAGE;
	} else {
		dir += ENTRIES_PER_PAGE/2;
		dir += (idx - ENTRIES_PER_PAGEPAGE/2)/ENTRIES_PER_PAGEPAGE;
		while (stage <= idx)
			stage += ENTRIES_PER_PAGEPAGE;
		middir = *dir;
		if (*dir) {
			diroff = ((idx - ENTRIES_PER_PAGEPAGE/2) %
				ENTRIES_PER_PAGEPAGE) / ENTRIES_PER_PAGE;
			if (!diroff && !offset && upper_limit >= stage) {
				if (needs_lock) {
					info_lock(needs_lock);
					*dir = NULL;
					info_unlock(needs_lock);
					needs_lock = NULL;
				} else
					*dir = NULL;
				nr_pages_to_free++;
				list_add(&middir->lru, &pages_to_free);
			}
			shmem_dir_unmap(dir);
			dir = shmem_dir_map(middir);
		} else {
			diroff = 0;
			offset = 0;
			idx = stage;
		}
	}

	for (; idx < limit; idx += ENTRIES_PER_PAGE, diroff++) {
		if (unlikely(idx == stage)) {
			shmem_dir_unmap(dir);
			dir = shmem_dir_map(topdir) +
			    ENTRIES_PER_PAGE/2 + idx/ENTRIES_PER_PAGEPAGE;
			while (!*dir) {
				dir++;
				idx += ENTRIES_PER_PAGEPAGE;
				if (idx >= limit)
					goto done1;
			}
			stage = idx + ENTRIES_PER_PAGEPAGE;
			middir = *dir;
			if (punch_hole)
				needs_lock = info;
			if (upper_limit >= stage) {
				if (needs_lock) {
					info_lock(needs_lock);
					*dir = NULL;
					info_unlock(needs_lock);
					needs_lock = NULL;
				} else
					*dir = NULL;
				nr_pages_to_free++;
				list_add(&middir->lru, &pages_to_free);
			}
			shmem_dir_unmap(dir);
			cond_resched();
			dir = shmem_dir_map(middir);
			diroff = 0;
		}
		punch_lock = needs_lock;
		subdir = dir[diroff];
		if (subdir && !offset && upper_limit-idx >= ENTRIES_PER_PAGE) {
			if (needs_lock) {
				info_lock(needs_lock);
				dir[diroff] = NULL;
				info_unlock(needs_lock);
				punch_lock = NULL;
			} else
				dir[diroff] = NULL;
			nr_pages_to_free++;
			list_add(&subdir->lru, &pages_to_free);
		}
		if (subdir && page_private(subdir) /* has swap entries */) {
			size = limit - idx;
			if (size > ENTRIES_PER_PAGE)
				size = ENTRIES_PER_PAGE;
			freed = shmem_map_and_free_swp(subdir,
					offset, size, &dir, punch_lock);
			if (!dir)
				dir = shmem_dir_map(middir);
			nr_swaps_freed += freed;
			if (offset || punch_lock) {
				info_lock(info);
				set_page_private(subdir,
					page_private(subdir) - freed);
				info_unlock(info);
			} else
				BUG_ON(page_private(subdir) != freed);
		}
		offset = 0;
	}
done1:
	shmem_dir_unmap(dir);
done2:
	if (inode->i_mapping->nrpages && (_info->flags & SHMEM_PAGEIN)) {
		/*
		 * Call truncate_inode_pages again: racing shmem_unuse_inode
		 * may have swizzled a page in from swap since vmtruncate or
		 * generic_delete_inode did it, before we lowered next_index.
		 * Also, though shmem_getpage checks i_size before adding to
		 * cache, no recheck after: so fix the narrow window there too.
		 *
		 * Recalling truncate_inode_pages_range and unmap_mapping_range
		 * every time for punch_hole (which never got a chance to clear
		 * SHMEM_PAGEIN at the start of vmtruncate_range) is expensive,
		 * yet hardly ever necessary: try to optimize them out later.
		 */
		/* DEP: Not buffered properly */
		truncate_inode_pages_range(inode->i_mapping, start, end);
		if (punch_hole)
			unmap_mapping_range(inode->i_mapping, start,
					    end - start, 1);
	}

	info_lock(info);
	_info->flags &= ~SHMEM_TRUNCATE;
	_info->swapped -= nr_swaps_freed;
	if (nr_pages_to_free)
		shmem_free_blocks(inode, nr_pages_to_free);
	shmem_recalc_inode(inode);
	info_unlock(info);

	/*
	 * Empty swap vector directory pages to be freed?
	 */
	if (!list_empty(&pages_to_free)) {
		pages_to_free.prev->next = NULL;
		shmem_free_pages(pages_to_free.next);
	}
}

static void shmem_truncate(struct _inode *inode)
{
	shmem_truncate_range(inode, inode->i_size, (loff_t)-1);
}

static int shmem_notify_change(struct dentry *dentry, struct iattr *attr)
{
	struct _inode *inode = dentry_get_inode(dentry);
	struct page *page = NULL;
	int error;

	if (S_ISREG(inode->i_mode) && (attr->ia_valid & ATTR_SIZE)) {
		if (attr->ia_size < inode->i_size) {
			/*
			 * If truncating down to a partial page, then
			 * if that page is already allocated, hold it
			 * in memory until the truncation is over, so
			 * truncate_partial_page cannnot miss it were
			 * it assigned to swap.
			 */
			if (attr->ia_size & (PAGE_CACHE_SIZE-1)) {
				(void) shmem_getpage(parent(inode),
					attr->ia_size>>PAGE_CACHE_SHIFT,
						&page, SGP_READ, NULL);
			}
			/*
			 * Reset SHMEM_PAGEIN flag so that shmem_truncate can
			 * detect if any pages might have been added to cache
			 * after truncate_inode_pages.  But we needn't bother
			 * if it's being fully truncated to zero-length: the
			 * nrpages check is efficient enough in that case.
			 */
			if (attr->ia_size) {
				struct shmem_inode_info *info = SHMEM_I(parent(inode));
				struct _shmem_inode_info *_info = _SHMEM_I(inode);
				info_lock(info);
				_info->flags &= ~SHMEM_PAGEIN;
				info_unlock(info);
			}
		}
	}

	error = inode_change_ok(inode, attr);
	if (!error)
		error = inode_setattr(inode, attr);
#ifdef CONFIG_TMPFS_POSIX_ACL
	if (!error && (attr->ia_valid & ATTR_MODE))
		error = generic_acl_chmod(inode, &shmem_acl_ops);
#endif
	if (page)
		page_cache_release(page);
	return error;
}

static void shmem_delete_inode(struct _inode *inode)
{
	struct shmem_sb_info *sbinfo = SHMEM_SB(i_get_sb(inode));
	struct _shmem_inode_info *_info = _SHMEM_I(inode);

	if (inode->i_op->truncate == shmem_truncate) {
		truncate_inode_pages(inode->i_mapping, 0);
		shmem_unacct_size(_info->flags, inode->i_size);
		inode->i_size = 0;
		shmem_truncate(inode);
		if (!tx_list_empty(&_info->swaplist)) {
			lock_swaplist();
			tx_list_del_init(&_info->swaplist);
			unlock_swaplist();
		}
	}
	BUG_ON(parent(inode)->i_blocks);
	if (sbinfo->max_inodes) {
		spin_lock(&sbinfo->stat_lock);
		sbinfo->free_inodes++;
		spin_unlock(&sbinfo->stat_lock);
	}
	clear_inode(parent(inode));
}

static inline int shmem_find_swp(swp_entry_t entry, swp_entry_t *dir, swp_entry_t *edir)
{
	swp_entry_t *ptr;

	for (ptr = dir; ptr < edir; ptr++) {
		if (ptr->val == entry.val)
			return ptr - dir;
	}
	return -1;
}

static int shmem_unuse_inode(struct _shmem_inode_info *_info, swp_entry_t entry, struct page *page)
{
	struct shmem_inode_info *info = parent(_info);
	struct _inode *inode;
	unsigned long idx;
	unsigned long size;
	unsigned long limit;
	unsigned long stage;
	struct page **dir;
	struct page *subdir;
	swp_entry_t *ptr;
	int offset;

	idx = 0;
	ptr = _info->i_direct;
	info_lock(info);
	limit = _info->next_index;
	size = limit;
	if (size > SHMEM_NR_DIRECT)
		size = SHMEM_NR_DIRECT;
	offset = shmem_find_swp(entry, ptr, ptr+size);
	if (offset >= 0) {
		shmem_swp_balance_unmap();
		goto found;
	}
	if (!_info->i_indirect)
		goto lost2;

	dir = shmem_dir_map(_info->i_indirect);
	stage = SHMEM_NR_DIRECT + ENTRIES_PER_PAGEPAGE/2;

	for (idx = SHMEM_NR_DIRECT; idx < limit; idx += ENTRIES_PER_PAGE, dir++) {
		if (unlikely(idx == stage)) {
			shmem_dir_unmap(dir-1);
			dir = shmem_dir_map(_info->i_indirect) +
			    ENTRIES_PER_PAGE/2 + idx/ENTRIES_PER_PAGEPAGE;
			while (!*dir) {
				dir++;
				idx += ENTRIES_PER_PAGEPAGE;
				if (idx >= limit)
					goto lost1;
			}
			stage = idx + ENTRIES_PER_PAGEPAGE;
			subdir = *dir;
			shmem_dir_unmap(dir);
			dir = shmem_dir_map(subdir);
		}
		subdir = *dir;
		if (subdir && page_private(subdir)) {
			ptr = shmem_swp_map(subdir);
			size = limit - idx;
			if (size > ENTRIES_PER_PAGE)
				size = ENTRIES_PER_PAGE;
			offset = shmem_find_swp(entry, ptr, ptr+size);
			if (offset >= 0) {
				shmem_dir_unmap(dir);
				goto found;
			}
			shmem_swp_unmap(ptr);
		}
	}
lost1:
	shmem_dir_unmap(dir-1);
lost2:
	info_unlock(info);
	return 0;
found:
	idx += offset;
	inode = &_info->_vfs_inode;
	if (move_from_swap_cache(page, idx, inode->i_mapping) == 0) {
		_info->flags |= SHMEM_PAGEIN;
		shmem_swp_set(_info, ptr + offset, 0);
	}
	shmem_swp_unmap(ptr);
	info_unlock(info);
	/*
	 * Decrement swap count even when the entry is left behind:
	 * try_to_unuse will skip over mms, then reincrement count.
	 */
	swap_free(entry);
	return 1;
}

/*
 * shmem_unuse() search for an eventually swapped out shmem page.
 */
int shmem_unuse(swp_entry_t entry, struct page *page)
{
	struct tx_list_head *p, *next;
	struct _shmem_inode_info *info;
	int found = 0;
	struct tx_list_head *swaplist;

	lock_swaplist();
	swaplist = get_swaplist();
	tx_list_for_each_safe(p, next, swaplist, ACCESS_RW) {
		info = tx_list_entry(p, struct _shmem_inode_info, swaplist);
		if (!info->swapped)
			tx_list_del_init(&info->swaplist);
		else if (shmem_unuse_inode(info, entry, page)) {
			/* move head to start search for next from here */
			tx_list_move_tail(swaplist, &info->swaplist);
			found = 1;
			break;
		}
	}
	unlock_swaplist();
	return found;
}

/*
 * Move the page from the page cache to the swap cache.
 */
static int shmem_writepage(struct page *page, struct writeback_control *wbc)
{
	struct shmem_inode_info *info;
	struct _shmem_inode_info *_info;
	swp_entry_t *entry, swap;
	struct address_space *mapping;
	unsigned long index;
	struct inode *inode;
	struct _inode *_inode;

	BUG_ON(!PageLocked(page));
	BUG_ON(page_mapped(page));

	mapping = page->mapping;
	index = page->index;
	inode = mapping->host;
	_inode = tx_cache_get_inode(inode);
	info = SHMEM_I(inode);
	_info = _SHMEM_I(_inode);
	if (_info->flags & VM_LOCKED)
		goto redirty;
	swap = get_swap_page();
	if (!swap.val)
		goto redirty;

	info_lock(info);
	shmem_recalc_inode(_inode);
	if (index >= _info->next_index) {
		BUG_ON(!(_info->flags & SHMEM_TRUNCATE));
		goto unlock;
	}
	entry = shmem_swp_entry(_info, index, NULL);
	BUG_ON(!entry);
	BUG_ON(entry->val);

	if (move_to_swap_cache(page, swap) == 0) {
		shmem_swp_set(_info, entry, swap.val);
		shmem_swp_unmap(entry);
		info_unlock(info);
		if (tx_list_empty(&_info->swaplist)) {
			lock_swaplist();
			/* move instead of add in case we're racing */
			tx_list_move_tail(&_info->swaplist, get_swaplist());
			unlock_swaplist();
		}
		unlock_page(page);
		return 0;
	}

	shmem_swp_unmap(entry);
unlock:
	info_unlock(info);
	swap_free(swap);
redirty:
	set_page_dirty(page);
	return AOP_WRITEPAGE_ACTIVATE;	/* Return with the page locked */
}

#ifdef CONFIG_NUMA
static inline int shmem_parse_mpol(char *value, int *policy, nodemask_t *policy_nodes)
{
	char *nodelist = strchr(value, ':');
	int err = 1;

	if (nodelist) {
		/* NUL-terminate policy string */
		*nodelist++ = '\0';
		if (nodelist_parse(nodelist, *policy_nodes))
			goto out;
		if (!nodes_subset(*policy_nodes, node_online_map))
			goto out;
	}
	if (!strcmp(value, "default")) {
		*policy = MPOL_DEFAULT;
		/* Don't allow a nodelist */
		if (!nodelist)
			err = 0;
	} else if (!strcmp(value, "prefer")) {
		*policy = MPOL_PREFERRED;
		/* Insist on a nodelist of one node only */
		if (nodelist) {
			char *rest = nodelist;
			while (isdigit(*rest))
				rest++;
			if (!*rest)
				err = 0;
		}
	} else if (!strcmp(value, "bind")) {
		*policy = MPOL_BIND;
		/* Insist on a nodelist */
		if (nodelist)
			err = 0;
	} else if (!strcmp(value, "interleave")) {
		*policy = MPOL_INTERLEAVE;
		/* Default to nodes online if no nodelist */
		if (!nodelist)
			*policy_nodes = node_online_map;
		err = 0;
	}
out:
	/* Restore string for error message */
	if (nodelist)
		*--nodelist = ':';
	return err;
}

static struct page *shmem_swapin_async(struct shared_policy *p,
				       swp_entry_t entry, unsigned long idx)
{
	struct page *page;
	struct vm_area_struct pvma;

	/* Create a pseudo vma that just contains the policy */
	memset(&pvma, 0, sizeof(struct vm_area_struct));
	pvma.vm_end = PAGE_SIZE;
	pvma.vm_pgoff = idx;
	pvma.vm_policy = mpol_shared_policy_lookup(p, idx);
	page = read_swap_cache_async(entry, &pvma, 0);
	mpol_free(pvma.vm_policy);
	return page;
}

struct page *shmem_swapin(struct shmem_inode_info *info, swp_entry_t entry,
			  unsigned long idx)
{
	struct shared_policy *p = &info->policy;
	int i, num;
	struct page *page;
	unsigned long offset;

	num = valid_swaphandles(entry, &offset);
	for (i = 0; i < num; offset++, i++) {
		page = shmem_swapin_async(p,
				swp_entry(swp_type(entry), offset), idx);
		if (!page)
			break;
		page_cache_release(page);
	}
	lru_add_drain();	/* Push any new pages onto the LRU now */
	return shmem_swapin_async(p, entry, idx);
}

static struct page *
shmem_alloc_page(gfp_t gfp, struct shmem_inode_info *info,
		 unsigned long idx)
{
	struct vm_area_struct pvma;
	struct page *page;

	memset(&pvma, 0, sizeof(struct vm_area_struct));
	pvma.vm_policy = mpol_shared_policy_lookup(&info->policy, idx);
	pvma.vm_pgoff = idx;
	pvma.vm_end = PAGE_SIZE;
	page = alloc_page_vma(gfp | __GFP_ZERO, &pvma, 0);
	mpol_free(pvma.vm_policy);
	return page;
}
#else
static inline int shmem_parse_mpol(char *value, int *policy, nodemask_t *policy_nodes)
{
	return 1;
}

static inline struct page *
shmem_swapin(struct shmem_inode_info *info,swp_entry_t entry,unsigned long idx)
{
	swapin_readahead(entry, 0, NULL);
	return read_swap_cache_async(entry, NULL, 0);
}

static inline struct page *
shmem_alloc_page(gfp_t gfp,struct shmem_inode_info *info, unsigned long idx)
{
	return alloc_page(gfp | __GFP_ZERO);
}
#endif

/*
 * shmem_getpage - either get the page from swap or allocate a new one
 *
 * If we allocate a new one we do not mark it dirty. That's up to the
 * vm. If we swap it in we mark it dirty since we also free the swap
 * entry since a page cannot live in both the swap and page cache
 */
static int shmem_getpage(struct inode *inode, unsigned long idx,
			struct page **pagep, enum sgp_type sgp, int *type)
{
	struct _inode *_inode = tx_cache_get_inode(inode);
	struct address_space *mapping = _inode->i_mapping;
	struct shmem_inode_info *info = SHMEM_I(inode);
	struct _shmem_inode_info *_info = _SHMEM_I(_inode);
	struct shmem_sb_info *sbinfo;
	struct page *filepage = *pagep;
	struct page *swappage;
	swp_entry_t *entry;
	swp_entry_t swap;
	int error;

	if (idx >= SHMEM_MAX_INDEX)
		return -EFBIG;
	/*
	 * Normally, filepage is NULL on entry, and either found
	 * uptodate immediately, or allocated and zeroed, or read
	 * in under swappage, which is then assigned to filepage.
	 * But shmem_prepare_write passes in a locked filepage,
	 * which may be found not uptodate by other callers too,
	 * and may need to be copied from the swappage read in.
	 */
repeat:
	if (!filepage)
		filepage = find_lock_page(mapping, idx);
	if (filepage && PageUptodate(filepage))
		goto done;
	error = 0;
	if (sgp == SGP_QUICK)
		goto failed;

	info_lock(info);
	shmem_recalc_inode(_inode);
	entry = shmem_swp_alloc(info, idx, sgp);
	if (IS_ERR(entry)) {
		info_unlock(info);
		error = PTR_ERR(entry);
		goto failed;
	}
	swap = *entry;

	if (swap.val) {
		/* Look it up and read it in.. */
		swappage = lookup_swap_cache(swap);
		if (!swappage) {
			shmem_swp_unmap(entry);
			/* here we actually do the io */
			if (type && *type == VM_FAULT_MINOR) {
				__count_vm_event(PGMAJFAULT);
				*type = VM_FAULT_MAJOR;
			}
			info_unlock(info);
			swappage = shmem_swapin(info, swap, idx);
			if (!swappage) {
				info_lock(info);
				entry = shmem_swp_alloc(info, idx, sgp);
				if (IS_ERR(entry))
					error = PTR_ERR(entry);
				else {
					if (entry->val == swap.val)
						error = -ENOMEM;
					shmem_swp_unmap(entry);
				}
				info_unlock(info);
				if (error)
					goto failed;
				goto repeat;
			}
			wait_on_page_locked(swappage);
			page_cache_release(swappage);
			goto repeat;
		}

		/* We have to do this with page locked to prevent races */
		if (TestSetPageLocked(swappage)) {
			shmem_swp_unmap(entry);
			info_unlock(info);
			wait_on_page_locked(swappage);
			page_cache_release(swappage);
			goto repeat;
		}
		if (PageWriteback(swappage)) {
			shmem_swp_unmap(entry);
			info_unlock(info);
			wait_on_page_writeback(swappage);
			unlock_page(swappage);
			page_cache_release(swappage);
			goto repeat;
		}
		if (!PageUptodate(swappage)) {
			shmem_swp_unmap(entry);
			info_unlock(info);
			unlock_page(swappage);
			page_cache_release(swappage);
			error = -EIO;
			goto failed;
		}

		if (filepage) {
			shmem_swp_set(_info, entry, 0);
			shmem_swp_unmap(entry);
			delete_from_swap_cache(swappage);
			info_unlock(info);
			copy_highpage(filepage, swappage);
			unlock_page(swappage);
			page_cache_release(swappage);
			flush_dcache_page(filepage);
			SetPageUptodate(filepage);
			set_page_dirty(filepage);
			swap_free(swap);
		} else if (!(error = move_from_swap_cache(
				swappage, idx, mapping))) {
			_info->flags |= SHMEM_PAGEIN;
			shmem_swp_set(_info, entry, 0);
			shmem_swp_unmap(entry);
			info_unlock(info);
			filepage = swappage;
			swap_free(swap);
		} else {
			shmem_swp_unmap(entry);
			info_unlock(info);
			unlock_page(swappage);
			page_cache_release(swappage);
			if (error == -ENOMEM) {
				/* let kswapd refresh zone for GFP_ATOMICs */
				congestion_wait(WRITE, HZ/50);
			}
			goto repeat;
		}
	} else if (sgp == SGP_READ && !filepage) {
		shmem_swp_unmap(entry);
		filepage = find_get_page(mapping, idx);
		if (filepage &&
		    (!PageUptodate(filepage) || TestSetPageLocked(filepage))) {
			info_unlock(info);
			wait_on_page_locked(filepage);
			page_cache_release(filepage);
			filepage = NULL;
			goto repeat;
		}
		info_unlock(info);
	} else {
		shmem_swp_unmap(entry);
		sbinfo = SHMEM_SB(i_get_sb(_inode));
		if (sbinfo->max_blocks) {
			spin_lock(&sbinfo->stat_lock);
			if (sbinfo->free_blocks == 0 ||
			    shmem_acct_block(_info->flags)) {
				spin_unlock(&sbinfo->stat_lock);
				info_unlock(info);
				error = -ENOSPC;
				goto failed;
			}
			sbinfo->free_blocks--;
			inode->i_blocks += BLOCKS_PER_PAGE;
			spin_unlock(&sbinfo->stat_lock);
		} else if (shmem_acct_block(_info->flags)) {
			info_unlock(info);
			error = -ENOSPC;
			goto failed;
		}

		if (!filepage) {
			info_unlock(info);
			filepage = shmem_alloc_page(mapping_gfp_mask(mapping),
						    info,
						    idx);
			if (!filepage) {
				shmem_unacct_blocks(_info->flags, 1);
				shmem_free_blocks(_inode, 1);
				error = -ENOMEM;
				goto failed;
			}

			info_lock(info);
			entry = shmem_swp_alloc(info, idx, sgp);
			if (IS_ERR(entry))
				error = PTR_ERR(entry);
			else {
				swap = *entry;
				shmem_swp_unmap(entry);
			}
			if (error || swap.val || 0 != add_to_page_cache_lru(
					filepage, mapping, idx, GFP_ATOMIC)) {
				info_unlock(info);
				page_cache_release(filepage);
				shmem_unacct_blocks(_info->flags, 1);
				shmem_free_blocks(_inode, 1);
				filepage = NULL;
				if (error)
					goto failed;
				goto repeat;
			}
			_info->flags |= SHMEM_PAGEIN;
		}

		_info->alloced++;
		info_unlock(info);
		flush_dcache_page(filepage);
		SetPageUptodate(filepage);
	}
done:
	if (*pagep != filepage) {
		unlock_page(filepage);
		*pagep = filepage;
	}
	return 0;

failed:
	if (*pagep != filepage) {
		unlock_page(filepage);
		page_cache_release(filepage);
	}
	return error;
}

static struct page *shmem_nopage(struct vm_area_struct *vma,
				 unsigned long address, int *type)
{
	struct inode *inode = file_get_dentry(vma->vm_file)->d_inode;
	const struct _inode *_inode = tx_cache_get_inode_ro(inode);
	struct page *page = NULL;
	unsigned long idx;
	int error;

	idx = (address - vma->vm_start) >> PAGE_SHIFT;
	idx += vma->vm_pgoff;
	idx >>= PAGE_CACHE_SHIFT - PAGE_SHIFT;
	if (((loff_t) idx << PAGE_CACHE_SHIFT) >= i_size_read(_inode))
		return NOPAGE_SIGBUS;

	error = shmem_getpage(inode, idx, &page, SGP_CACHE, type);
	if (error)
		return (error == -ENOMEM)? NOPAGE_OOM: NOPAGE_SIGBUS;

	mark_page_accessed(page);
	return page;
}

static int shmem_populate(struct vm_area_struct *vma,
	unsigned long addr, unsigned long len,
	pgprot_t prot, unsigned long pgoff, int nonblock)
{
	struct inode *inode = file_get_dentry(vma->vm_file)->d_inode;
	const struct _inode *_inode = tx_cache_get_inode_ro(inode);
	struct mm_struct *mm = vma->vm_mm;
	enum sgp_type sgp = nonblock? SGP_QUICK: SGP_CACHE;
	unsigned long size;

	size = (i_size_read(_inode) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (pgoff >= size || pgoff + (len >> PAGE_SHIFT) > size)
		return -EINVAL;

	while ((long) len > 0) {
		struct page *page = NULL;
		int err;
		/*
		 * Will need changing if PAGE_CACHE_SIZE != PAGE_SIZE
		 */
		err = shmem_getpage(inode, pgoff, &page, sgp, NULL);
		if (err)
			return err;
		/* Page may still be null, but only if nonblock was set. */
		if (page) {
			mark_page_accessed(page);
			err = install_page(mm, vma, addr, page, prot);
			if (err) {
				page_cache_release(page);
				return err;
			}
		} else if (vma->vm_flags & VM_NONLINEAR) {
			/* No page was found just because we can't read it in
			 * now (being here implies nonblock != 0), but the page
			 * may exist, so set the PTE to fault it in later. */
    			err = install_file_pte(mm, vma, addr, pgoff, prot);
			if (err)
	    			return err;
		}

		len -= PAGE_SIZE;
		addr += PAGE_SIZE;
		pgoff++;
	}
	return 0;
}

#ifdef CONFIG_NUMA
int shmem_set_policy(struct vm_area_struct *vma, struct mempolicy *new)
{
	struct inode *i = vma->vm_file->f_path.dentry->d_inode;
	return mpol_set_shared_policy(&SHMEM_I(i)->policy, vma, new);
}

struct mempolicy *
shmem_get_policy(struct vm_area_struct *vma, unsigned long addr)
{
	struct inode *i = vma->vm_file->f_path.dentry->d_inode;
	unsigned long idx;

	idx = ((addr - vma->vm_start) >> PAGE_SHIFT) + vma->vm_pgoff;
	return mpol_shared_policy_lookup(&SHMEM_I(i)->policy, idx);
}
#endif

int shmem_lock(struct file *file, int lock, struct user_struct *user)
{
	struct _inode *inode = d_get_inode(file_get_dentry(file));
	struct _shmem_inode_info *_info = _SHMEM_I(inode);
	struct shmem_inode_info *info = parent(_info);
	int retval = -ENOMEM;

	info_lock(info);
	if (lock && !(_info->flags & VM_LOCKED)) {
		if (!user_shm_lock(inode->i_size, user))
			goto out_nomem;
		_info->flags |= VM_LOCKED;
	}
	if (!lock && (_info->flags & VM_LOCKED) && user) {
		user_shm_unlock(inode->i_size, user);
		_info->flags &= ~VM_LOCKED;
	}
	retval = 0;
out_nomem:
	info_unlock(info);
	return retval;
}

static int shmem_mmap(struct file *file, struct vm_area_struct *vma)
{
	file_accessed(tx_cache_get_file_ro(file));
	vma->vm_ops = &shmem_vm_ops;
	return 0;
}

static struct inode *
shmem_get_inode(struct super_block *sb, int mode, dev_t dev)
{
	struct inode *inode = NULL;
	struct shmem_inode_info *info = NULL;
	struct _inode *_inode = NULL;
	struct _shmem_inode_info *_info = NULL;
	struct shmem_sb_info *sbinfo = SHMEM_SB(tx_cache_get_super(sb));

	if (sbinfo->max_inodes) {
		spin_lock(&sbinfo->stat_lock);
		if (!sbinfo->free_inodes) {
			spin_unlock(&sbinfo->stat_lock);
			return NULL;
		}
		sbinfo->free_inodes--;
		spin_unlock(&sbinfo->stat_lock);
	}

	inode = new_inode(sb);
	info = SHMEM_I(inode);

	_inode = tx_cache_get_inode(inode);
	_info = _SHMEM_I(_inode);

	if (inode) {
		/* Most of init now in alloc, thank Goodness */
		_inode->i_mode = mode;
		_inode->i_mapping->a_ops = &shmem_aops;
		_inode->i_mapping->backing_dev_info = &shmem_backing_dev_info;
		switch (mode & S_IFMT) {
		default:
			_inode->i_op = &shmem_special_inode_operations;
			init_special_inode(_inode, mode, dev);
			break;
		case S_IFREG:
			_inode->i_op = &shmem_inode_operations;
			_inode->i_fop = &shmem_file_operations;
			mpol_shared_policy_init(&info->policy, sbinfo->policy,
						&sbinfo->policy_nodes);
			break;
		case S_IFDIR:
			inc_nlink(_inode);
			/* Some things misbehave if size == 0 on a directory */
			_inode->i_size = 2 * BOGO_DIRENT_SIZE;
			_inode->i_op = &shmem_dir_inode_operations;
			_inode->i_fop = &simple_dir_operations;
			break;
		case S_IFLNK:
			/*
			 * Must not load anything in the rbtree,
			 * mpol_free_shared_policy will not be called.
			 */
			mpol_shared_policy_init(&info->policy, MPOL_DEFAULT,
						NULL);

			break;
		}
	} else if (sbinfo->max_inodes) {
		spin_lock(&sbinfo->stat_lock);
		sbinfo->free_inodes++;
		spin_unlock(&sbinfo->stat_lock);
	}
	return inode;
}

#ifdef CONFIG_TMPFS
static const struct inode_operations shmem_symlink_inode_operations;
static const struct inode_operations shmem_symlink_inline_operations;

/*
 * Normally tmpfs makes no use of shmem_prepare_write, but it
 * lets a tmpfs file be used read-write below the loop driver.
 */
static int
shmem_prepare_write(struct file *file, struct page *page, unsigned offset, unsigned to)
{
	struct inode *inode = page->mapping->host;
	return shmem_getpage(inode, page->index, &page, SGP_WRITE, NULL);
}

static ssize_t
shmem_file_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct _inode	*_inode = d_get_inode(file_get_dentry(file));
	struct inode    *inode = parent(_inode);
	loff_t		pos;
	unsigned long	written;
	ssize_t		err;
	struct _file    *_file = tx_cache_get_file_ro(file);

	if ((ssize_t) count < 0)
		return -EINVAL;

	if (!access_ok(VERIFY_READ, buf, count))
		return -EFAULT;

	imutex_lock(inode);

	pos = *ppos;
	written = 0;

	err = generic_write_checks(_file, &pos, &count, 0);
	if (err || !count)
		goto out;

	err = remove_suid(f_get_dentry(_file));
	if (err)
		goto out;

	_inode->i_ctime = _inode->i_mtime = CURRENT_TIME;

	do {
		struct page *page = NULL;
		unsigned long bytes, index, offset;
		char *kaddr;
		int left;

		offset = (pos & (PAGE_CACHE_SIZE -1)); /* Within page */
		index = pos >> PAGE_CACHE_SHIFT;
		bytes = PAGE_CACHE_SIZE - offset;
		if (bytes > count)
			bytes = count;

		/*
		 * We don't hold page lock across copy from user -
		 * what would it guard against? - so no deadlock here.
		 * But it still may be a good idea to prefault below.
		 */

		err = shmem_getpage(inode, index, &page, SGP_WRITE, NULL);
		if (err)
			break;

		left = bytes;
		if (PageHighMem(page)) {
			volatile unsigned char dummy;
			__get_user(dummy, buf);
			__get_user(dummy, buf + bytes - 1);

			kaddr = kmap_atomic(page, KM_USER0);
			left = __copy_from_user_inatomic(kaddr + offset,
							buf, bytes);
			kunmap_atomic(kaddr, KM_USER0);
		}
		if (left) {
			kaddr = kmap(page);
			left = __copy_from_user(kaddr + offset, buf, bytes);
			kunmap(page);
		}

		written += bytes;
		count -= bytes;
		pos += bytes;
		buf += bytes;
		if (pos > _inode->i_size)
			i_size_write(_inode, pos);

		flush_dcache_page(page);
		set_page_dirty(page);
		mark_page_accessed(page);
		page_cache_release(page);

		if (left) {
			pos -= left;
			written -= left;
			err = -EFAULT;
			break;
		}

		/*
		 * Our dirty pages are not counted in nr_dirty,
		 * and we do not attempt to balance dirty pages.
		 */

		cond_resched();
	} while (count);

	*ppos = pos;
	if (written)
		err = written;
out:
	imutex_unlock(inode);
	return err;
}

static void do_shmem_file_read(struct file *filp, loff_t *ppos, read_descriptor_t *desc, read_actor_t actor)
{
	struct _file *_filp = tx_cache_get_file_ro(filp);
	struct _inode *_inode = d_get_inode(f_get_dentry(_filp));
	struct inode *inode = parent(_inode);
	struct address_space *mapping = _inode->i_mapping;
	unsigned long index, offset;

	index = *ppos >> PAGE_CACHE_SHIFT;
	offset = *ppos & ~PAGE_CACHE_MASK;

	for (;;) {
		struct page *page = NULL;
		unsigned long end_index, nr, ret;
		loff_t i_size = i_size_read(_inode);

		end_index = i_size >> PAGE_CACHE_SHIFT;
		if (index > end_index)
			break;
		if (index == end_index) {
			nr = i_size & ~PAGE_CACHE_MASK;
			if (nr <= offset)
				break;
		}

		desc->error = shmem_getpage(inode, index, &page, SGP_READ, NULL);
		if (desc->error) {
			if (desc->error == -EINVAL)
				desc->error = 0;
			break;
		}

		/*
		 * We must evaluate after, since reads (unlike writes)
		 * are called without i_mutex protection against truncate
		 */
		nr = PAGE_CACHE_SIZE;
		i_size = i_size_read(_inode);
		end_index = i_size >> PAGE_CACHE_SHIFT;
		if (index == end_index) {
			nr = i_size & ~PAGE_CACHE_MASK;
			if (nr <= offset) {
				if (page)
					page_cache_release(page);
				break;
			}
		}
		nr -= offset;

		if (page) {
			/*
			 * If users can be writing to this page using arbitrary
			 * virtual addresses, take care about potential aliasing
			 * before reading the page on the kernel side.
			 */
			if (mapping_writably_mapped(mapping))
				flush_dcache_page(page);
			/*
			 * Mark the page accessed if we read the beginning.
			 */
			if (!offset)
				mark_page_accessed(page);
		} else {
			page = ZERO_PAGE(0);
			page_cache_get(page);
		}

		/*
		 * Ok, we have the page, and it's up-to-date, so
		 * now we can copy it to user space...
		 *
		 * The actor routine returns how many bytes were actually used..
		 * NOTE! This may not be the same as how much of a user buffer
		 * we filled up (we may be padding etc), so we can only update
		 * "pos" here (the actor routine has to update the user buffer
		 * pointers and the remaining count).
		 */
		ret = actor(desc, page, offset, nr);
		offset += ret;
		index += offset >> PAGE_CACHE_SHIFT;
		offset &= ~PAGE_CACHE_MASK;

		page_cache_release(page);
		if (ret != nr || !desc->count)
			break;

		cond_resched();
	}

	*ppos = ((loff_t) index << PAGE_CACHE_SHIFT) + offset;
	file_accessed(_filp);
}

static ssize_t shmem_file_read(struct file *filp, char __user *buf, size_t count, loff_t *ppos)
{
	read_descriptor_t desc;

	if ((ssize_t) count < 0)
		return -EINVAL;
	if (!access_ok(VERIFY_WRITE, buf, count))
		return -EFAULT;
	if (!count)
		return 0;

	desc.written = 0;
	desc.count = count;
	desc.arg.buf = buf;
	desc.error = 0;

	do_shmem_file_read(filp, ppos, &desc, file_read_actor);
	if (desc.written)
		return desc.written;
	return desc.error;
}

static ssize_t shmem_file_sendfile(struct file *in_file, loff_t *ppos,
			 size_t count, read_actor_t actor, void *target)
{
	read_descriptor_t desc;

	if (!count)
		return 0;

	desc.written = 0;
	desc.count = count;
	desc.arg.data = target;
	desc.error = 0;

	do_shmem_file_read(in_file, ppos, &desc, actor);
	if (desc.written)
		return desc.written;
	return desc.error;
}

static int shmem_statfs(const struct dentry *dentry, struct kstatfs *buf)
{
	struct shmem_sb_info *sbinfo = SHMEM_SB(tx_cache_get_super(dentry->d_sb));

	buf->f_type = TMPFS_MAGIC;
	buf->f_bsize = PAGE_CACHE_SIZE;
	buf->f_namelen = NAME_MAX;
	spin_lock(&sbinfo->stat_lock);
	if (sbinfo->max_blocks) {
		buf->f_blocks = sbinfo->max_blocks;
		buf->f_bavail = buf->f_bfree = sbinfo->free_blocks;
	}
	if (sbinfo->max_inodes) {
		buf->f_files = sbinfo->max_inodes;
		buf->f_ffree = sbinfo->free_inodes;
	}
	/* else leave those fields 0 like simple_statfs */
	spin_unlock(&sbinfo->stat_lock);
	return 0;
}

/*
 * File creation. Allocate an inode, and we're done..
 */
static int
shmem_mknod(struct _inode *dir, struct _dentry *dentry, int mode, dev_t dev)
{
	struct inode *inode = shmem_get_inode(dir->i_sb, mode, dev);
	struct _inode *_inode = tx_cache_get_inode(inode);

	int error = -ENOSPC;

	if (inode) {
		error = security_inode_init_security(inode, parent(dir), NULL, NULL,
						     NULL);
		if (error) {
			if (error != -EOPNOTSUPP) {
				iput(inode);
				return error;
			}
		}
		error = shmem_acl_init(inode, parent(dir));
		if (error) {
			iput(inode);
			return error;
		}
		if (dir->i_mode & S_ISGID) {
			_inode->i_gid = dir->i_gid;
			if (S_ISDIR(mode))
				_inode->i_mode |= S_ISGID;
		}
		dir->i_size += BOGO_DIRENT_SIZE;
		dir->i_ctime = dir->i_mtime = CURRENT_TIME;
		d_instantiate(dentry, _inode);
		dget(parent(dentry)); /* Extra count - pin the dentry in core */
	}
	return error;
}

static int shmem_mkdir(struct _inode *dir, struct _dentry *dentry, int mode)
{
	int error;

	if ((error = shmem_mknod(dir, dentry, mode | S_IFDIR, 0)))
		return error;
	inc_nlink(dir);
	return 0;
}

static int shmem_create(struct _inode *dir, struct _dentry *dentry, int mode,
			struct nameidata *nd)
{
	return shmem_mknod(dir, dentry, mode | S_IFREG, 0);
}

/*
 * Link a file..
 */
static int shmem_link(struct _dentry *old_dentry, struct _inode *dir, struct _dentry *dentry)
{
	struct _inode *_inode = d_get_inode(old_dentry);
	struct inode *inode = parent(_inode);
	struct shmem_sb_info *sbinfo = SHMEM_SB(i_get_sb(_inode));

	/*
	 * No ordinary (disk based) filesystem counts links as inodes;
	 * but each new link needs a new dentry, pinning lowmem, and
	 * tmpfs dentries cannot be pruned until they are unlinked.
	 */
	if (sbinfo->max_inodes) {
		spin_lock(&sbinfo->stat_lock);
		if (!sbinfo->free_inodes) {
			spin_unlock(&sbinfo->stat_lock);
			return -ENOSPC;
		}
		sbinfo->free_inodes--;
		spin_unlock(&sbinfo->stat_lock);
	}

	dir->i_size += BOGO_DIRENT_SIZE;
	_inode->i_ctime = dir->i_ctime = dir->i_mtime = CURRENT_TIME;
	inc_nlink(_inode);
	/* DEP 4/4/10:  Don't double-compensate for this increment during abort */
	tx_atomic_inc_nolog(&inode->i_count);	/* New dentry reference */
	dget(parent(dentry));		/* Extra pinning count for the created dentry */
	d_instantiate(dentry, _inode);
	return 0;
}

static int shmem_unlink(struct _inode *dir, struct _dentry *dentry)
{
	struct _inode *inode = d_get_inode(dentry);

	if (inode->i_nlink > 1 && !S_ISDIR(inode->i_mode)) {
		struct shmem_sb_info *sbinfo = SHMEM_SB(i_get_sb(inode));
		if (sbinfo->max_inodes) {
			spin_lock(&sbinfo->stat_lock);
			sbinfo->free_inodes++;
			spin_unlock(&sbinfo->stat_lock);
		}
	}

	dir->i_size -= BOGO_DIRENT_SIZE;
	inode->i_ctime = dir->i_ctime = dir->i_mtime = CURRENT_TIME;
	drop_nlink(inode);
	dput(parent(dentry));	/* Undo the count from "create" - this does all the work */
	return 0;
}

static int shmem_rmdir(struct _inode *dir, struct _dentry *dentry)
{
	struct _inode *inode;
	if (!simple_empty(parent(dentry)))
		return -ENOTEMPTY;

	inode = d_get_inode(dentry);

	drop_nlink(inode);
	drop_nlink(dir);
	return shmem_unlink(dir, dentry);
}

/*
 * The VFS layer already does all the dentry stuff for rename,
 * we just have to decrement the usage count for the target if
 * it exists so that the VFS layer correctly free's it when it
 * gets overwritten.
 */
static int shmem_rename(struct _inode *old_dir, struct _dentry *old_dentry,
			struct _inode *new_dir, struct _dentry *new_dentry)
{
	struct _inode *inode = d_get_inode(old_dentry);
	int they_are_dirs = S_ISDIR(inode->i_mode);

	if (!simple_empty(parent(new_dentry)))
		return -ENOTEMPTY;

	if (new_dentry->d_inode) {
		(void) shmem_unlink(new_dir, new_dentry);
		if (they_are_dirs)
			drop_nlink(old_dir);
	} else if (they_are_dirs) {
		drop_nlink(old_dir);
		inc_nlink(new_dir);
	}

	old_dir->i_size -= BOGO_DIRENT_SIZE;
	new_dir->i_size += BOGO_DIRENT_SIZE;
	old_dir->i_ctime = old_dir->i_mtime =
	new_dir->i_ctime = new_dir->i_mtime =
	inode->i_ctime = CURRENT_TIME;
	return 0;
}

static int shmem_symlink(struct _inode *dir, struct _dentry *dentry, const char *symname)
{
	int error;
	int len;
	struct inode *inode;
	struct _inode *_inode;
	struct page *page = NULL;
	char *kaddr;
	struct shmem_inode_info *info;

	if(unlikely(IS_ERR(dir)))
		return PTR_ERR(dir);

	len = strlen(symname) + 1;
	if (len > PAGE_CACHE_SIZE)
		return -ENAMETOOLONG;

	inode = shmem_get_inode(dir->i_sb, S_IFLNK|S_IRWXUGO, 0);
	if (!inode)
		return -ENOSPC;

	error = security_inode_init_security(inode, parent(dir), NULL, NULL,
					     NULL);
	if (error) {
		if (error != -EOPNOTSUPP) {
			iput(inode);
			return error;
		}
		error = 0;
	}

	_inode = tx_cache_get_inode(inode);
	info = SHMEM_I(inode);
	_inode->i_size = len-1;
	if (len <= (char *)inode - (char *)info) {
		/* do it inline */
		memcpy(info, symname, len);
		_inode->i_op = &shmem_symlink_inline_operations;
	} else {
		error = shmem_getpage(inode, 0, &page, SGP_WRITE, NULL);
		if (error) {
			iput(inode);
			return error;
		}
		_inode->i_op = &shmem_symlink_inode_operations;
		kaddr = kmap_atomic(page, KM_USER0);
		memcpy(kaddr, symname, len);
		kunmap_atomic(kaddr, KM_USER0);
		set_page_dirty(page);
		page_cache_release(page);
	}
	if (dir->i_mode & S_ISGID)
		_inode->i_gid = dir->i_gid;
	dir->i_size += BOGO_DIRENT_SIZE;
	dir->i_ctime = dir->i_mtime = CURRENT_TIME;
	d_instantiate(dentry, _inode);
	dget(parent(dentry));
	return 0;
}

static void *shmem_follow_link_inline(struct _dentry *dentry, struct nameidata *nd)
{
	nd_set_link(nd, (char *)SHMEM_I(dentry->d_inode));
	return NULL;
}

static void *shmem_follow_link(struct _dentry *dentry, struct nameidata *nd)
{
	struct page *page = NULL;
	int res = shmem_getpage(dentry->d_inode, 0, &page, SGP_READ, NULL);
	nd_set_link(nd, res ? ERR_PTR(res) : kmap(page));
	return page;
}

static void shmem_put_link(struct _dentry *dentry, struct nameidata *nd, void *cookie)
{
	if (!IS_ERR(nd_get_link(nd))) {
		struct page *page = cookie;
		kunmap(page);
		mark_page_accessed(page);
		page_cache_release(page);
	}
}

#ifdef CONFIG_TX_KSTM

void shmem_validate_inode(struct _inode *inode, struct _inode *checkpoint_inode,
			  struct _inode *shadow_inode, enum access_mode mode)
{
	struct _shmem_inode_info *ei   = _SHMEM_I(inode);
	struct _shmem_inode_info *c_ei = _SHMEM_I(checkpoint_inode);
	struct _shmem_inode_info *s_ei = _SHMEM_I(shadow_inode);
	int i;

	TX_VALIDATE(ei, c_ei, flags);
	TX_VALIDATE(ei, c_ei, alloced);
	TX_VALIDATE(ei, c_ei, next_index);
	TX_VALIDATE(ei, c_ei, i_indirect);
	/* Don't mess with policy */
	for(i = 0; i < SHMEM_NR_DIRECT; i++){
		TX_VALIDATE(ei, c_ei, i_direct[i].val); /* Unpack */
	}

	list_validate_tx(&ei->swaplist, &c_ei->swaplist);
		
#ifdef CONFIG_TMPFS_POSIX_ACL
	TX_VALIDATE(ei, c_ei, i_acl);
	TX_VALIDATE(ei, c_ei, i_default_acl);
#endif

	if(mode == ACCESS_R){

		TX_VALIDATE(ei, s_ei, flags);
		TX_VALIDATE(ei, s_ei, alloced);
		TX_VALIDATE(ei, s_ei, next_index);
		TX_VALIDATE(ei, s_ei, i_indirect);
		/* Don't mess with policy */
		for(i = 0; i < SHMEM_NR_DIRECT; i++){
			TX_VALIDATE(ei, s_ei, i_direct[i].val); /* Unpack */
		}

		list_validate_tx_ro(&ei->swaplist, &s_ei->swaplist);
		
#ifdef CONFIG_TMPFS_POSIX_ACL
		TX_VALIDATE(ei, s_ei, i_acl);
		TX_VALIDATE(ei, s_ei, i_default_acl);
#endif		
	}
}

void shmem_commit_inode(struct _inode *shadow_inode, enum access_mode mode,
		int write_data)
{

	struct _shmem_inode_info *s_ei = _SHMEM_I(shadow_inode);

	if(mode == ACCESS_RW)
		list_commit_tx(&s_ei->swaplist, 1);
}

void shmem_lock_inode(struct inode *inode, int blocking){
	if(!blocking) {
		struct shmem_inode_info *ei = SHMEM_I(inode);
		info_lock(ei);
	}
}

void shmem_unlock_inode(struct inode *inode, int blocking){
	if(!blocking) {
		struct shmem_inode_info *ei = SHMEM_I(inode);
		info_unlock(ei);
	}
}

void shmem_init_tx_inode(struct _inode *inode, enum access_mode mode){
	struct _shmem_inode_info *s_ei = _SHMEM_I(inode);
	list_init_tx(&s_ei->swaplist, mode);
}

#endif // TX_KSTM

static const struct inode_operations shmem_symlink_inline_operations = {
	.readlink	= generic_readlink,
	.follow_link	= shmem_follow_link_inline,
#ifdef CONFIG_TX_KSTM
	.commit         = shmem_commit_inode,
	.validate       = shmem_validate_inode,
	.lock           = shmem_lock_inode,
	.unlock         = shmem_unlock_inode,
	.init_tx        = shmem_init_tx_inode,
#endif

};

static const struct inode_operations shmem_symlink_inode_operations = {
	.truncate	= shmem_truncate,
	.readlink	= generic_readlink,
	.follow_link	= shmem_follow_link,
	.put_link	= shmem_put_link,
#ifdef CONFIG_TX_KSTM
	.commit         = shmem_commit_inode,
	.validate       = shmem_validate_inode,
	.lock           = shmem_lock_inode,
	.unlock         = shmem_unlock_inode,
	.init_tx        = shmem_init_tx_inode,
#endif
};

#ifdef CONFIG_TMPFS_POSIX_ACL
/**
 * Superblocks without xattr inode operations will get security.* xattr
 * support from the VFS "for free". As soon as we have any other xattrs
 * like ACLs, we also need to implement the security.* handlers at
 * filesystem level, though.
 */

static size_t shmem_xattr_security_list(struct inode *inode, char *list,
					size_t list_len, const char *name,
					size_t name_len)
{
	return security_inode_listsecurity(inode, list, list_len);
}

static int shmem_xattr_security_get(struct inode *inode, const char *name,
				    void *buffer, size_t size)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	return security_inode_getsecurity(inode, name, buffer, size,
					  -EOPNOTSUPP);
}

static int shmem_xattr_security_set(struct inode *inode, const char *name,
				    const void *value, size_t size, int flags)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	return security_inode_setsecurity(inode, name, value, size, flags);
}

static struct xattr_handler shmem_xattr_security_handler = {
	.prefix = XATTR_SECURITY_PREFIX,
	.list   = shmem_xattr_security_list,
	.get    = shmem_xattr_security_get,
	.set    = shmem_xattr_security_set,
};

static struct xattr_handler *shmem_xattr_handlers[] = {
	&shmem_xattr_acl_access_handler,
	&shmem_xattr_acl_default_handler,
	&shmem_xattr_security_handler,
	NULL
};
#endif

static struct dentry *shmem_get_parent(struct _dentry *child)
{
	return ERR_PTR(-ESTALE);
}

static int shmem_match(struct inode *ino, void *vfh)
{
	struct _inode *_ino = tx_cache_get_inode_ro(ino);
	__u32 *fh = vfh;
	__u64 inum = fh[2];
	inum = (inum << 32) | fh[1];
	return _ino->i_ino == inum && fh[0] == ino->i_generation;
}

static struct _dentry *shmem_get_dentry(struct super_block *sb, void *vfh)
{
	struct _dentry *de = NULL;
	struct inode *inode;
	__u32 *fh = vfh;
	__u64 inum = fh[2];
	inum = (inum << 32) | fh[1];

	inode = ilookup5(sb, (unsigned long)(inum+fh[0]), shmem_match, vfh);
	if (inode) {
		de = d_find_alias(tx_cache_get_inode(inode));
		iput(inode);
	}

	return de? de: ERR_PTR(-ESTALE);
}

static struct dentry *shmem_decode_fh(struct super_block *sb, __u32 *fh,
		int len, int type,
		int (*acceptable)(void *context, struct dentry *de),
		void *context)
{
	if (len < 3)
		return ERR_PTR(-ESTALE);

	return sb->s_export_op->find_exported_dentry(sb, fh, NULL, acceptable,
							context);
}

static int shmem_encode_fh(struct dentry *dentry, __u32 *fh, int *len,
				int connectable)
{
	struct _inode *_inode = dentry_get_inode(dentry);
	struct inode *inode = parent(_inode);

	if (*len < 3)
		return 255;

	if (hlist_unhashed(&inode->i_hash)) {
		/* Unfortunately insert_inode_hash is not idempotent,
		 * so as we hash inodes here rather than at creation
		 * time, we need a lock to ensure we only try
		 * to do it once
		 */
		static DEFINE_SPINLOCK(lock);
		spin_lock(&lock);
		if (hlist_unhashed(&inode->i_hash))
			__insert_inode_hash(_inode,
					    _inode->i_ino + inode->i_generation);
		spin_unlock(&lock);
	}

	fh[0] = inode->i_generation;
	fh[1] = _inode->i_ino;
	fh[2] = ((__u64)_inode->i_ino) >> 32;

	*len = 3;
	return 1;
}

static struct export_operations shmem_export_ops = {
	.get_parent     = shmem_get_parent,
	.get_dentry     = shmem_get_dentry,
	.encode_fh      = shmem_encode_fh,
	.decode_fh      = shmem_decode_fh,
};

static int shmem_parse_options(char *options, int *mode, uid_t *uid,
	gid_t *gid, unsigned long *blocks, unsigned long *inodes,
	int *policy, nodemask_t *policy_nodes)
{
	char *this_char, *value, *rest;

	while (options != NULL) {
		this_char = options;
		for (;;) {
			/*
			 * NUL-terminate this option: unfortunately,
			 * mount options form a comma-separated list,
			 * but mpol's nodelist may also contain commas.
			 */
			options = strchr(options, ',');
			if (options == NULL)
				break;
			options++;
			if (!isdigit(*options)) {
				options[-1] = '\0';
				break;
			}
		}
		if (!*this_char)
			continue;
		if ((value = strchr(this_char,'=')) != NULL) {
			*value++ = 0;
		} else {
			printk(KERN_ERR
			    "tmpfs: No value for mount option '%s'\n",
			    this_char);
			return 1;
		}

		if (!strcmp(this_char,"size")) {
			unsigned long long size;
			size = memparse(value,&rest);
			if (*rest == '%') {
				size <<= PAGE_SHIFT;
				size *= totalram_pages;
				do_div(size, 100);
				rest++;
			}
			if (*rest)
				goto bad_val;
			*blocks = size >> PAGE_CACHE_SHIFT;
		} else if (!strcmp(this_char,"nr_blocks")) {
			*blocks = memparse(value,&rest);
			if (*rest)
				goto bad_val;
		} else if (!strcmp(this_char,"nr_inodes")) {
			*inodes = memparse(value,&rest);
			if (*rest)
				goto bad_val;
		} else if (!strcmp(this_char,"mode")) {
			if (!mode)
				continue;
			*mode = simple_strtoul(value,&rest,8);
			if (*rest)
				goto bad_val;
		} else if (!strcmp(this_char,"uid")) {
			if (!uid)
				continue;
			*uid = simple_strtoul(value,&rest,0);
			if (*rest)
				goto bad_val;
		} else if (!strcmp(this_char,"gid")) {
			if (!gid)
				continue;
			*gid = simple_strtoul(value,&rest,0);
			if (*rest)
				goto bad_val;
		} else if (!strcmp(this_char,"mpol")) {
			if (shmem_parse_mpol(value,policy,policy_nodes))
				goto bad_val;
		} else {
			printk(KERN_ERR "tmpfs: Bad mount option %s\n",
			       this_char);
			return 1;
		}
	}
	return 0;

bad_val:
	printk(KERN_ERR "tmpfs: Bad value '%s' for mount option '%s'\n",
	       value, this_char);
	return 1;

}

static int shmem_remount_fs(struct super_block *sb, int *flags, char *data)
{
	struct shmem_sb_info *sbinfo = SHMEM_SB(tx_cache_get_super(sb));
	unsigned long max_blocks = sbinfo->max_blocks;
	unsigned long max_inodes = sbinfo->max_inodes;
	int policy = sbinfo->policy;
	nodemask_t policy_nodes = sbinfo->policy_nodes;
	unsigned long blocks;
	unsigned long inodes;
	int error = -EINVAL;

	if (shmem_parse_options(data, NULL, NULL, NULL, &max_blocks,
				&max_inodes, &policy, &policy_nodes))
		return error;

	spin_lock(&sbinfo->stat_lock);
	blocks = sbinfo->max_blocks - sbinfo->free_blocks;
	inodes = sbinfo->max_inodes - sbinfo->free_inodes;
	if (max_blocks < blocks)
		goto out;
	if (max_inodes < inodes)
		goto out;
	/*
	 * Those tests also disallow limited->unlimited while any are in
	 * use, so i_blocks will always be zero when max_blocks is zero;
	 * but we must separately disallow unlimited->limited, because
	 * in that case we have no record of how much is already in use.
	 */
	if (max_blocks && !sbinfo->max_blocks)
		goto out;
	if (max_inodes && !sbinfo->max_inodes)
		goto out;

	error = 0;
	sbinfo->max_blocks  = max_blocks;
	sbinfo->free_blocks = max_blocks - blocks;
	sbinfo->max_inodes  = max_inodes;
	sbinfo->free_inodes = max_inodes - inodes;
	sbinfo->policy = policy;
	sbinfo->policy_nodes = policy_nodes;
out:
	spin_unlock(&sbinfo->stat_lock);
	return error;
}
#endif

static void shmem_put_super(struct super_block *sb)
{
	struct _super_block *_sb = tx_cache_get_super(sb);
	kfree(_sb->s_fs_info);
	_sb->s_fs_info = NULL;
}

static int shmem_fill_super(struct super_block *sb,
			    void *data, int silent)
{
	struct inode *inode;
	struct _inode *_inode;
	struct dentry *root;
	int mode   = S_IRWXUGO | S_ISVTX;
	uid_t uid = current->fsuid;
	gid_t gid = current->fsgid;
	int err = -ENOMEM;
	struct shmem_sb_info *sbinfo;
	unsigned long blocks = 0;
	unsigned long inodes = 0;
	int policy = MPOL_DEFAULT;
	nodemask_t policy_nodes = node_online_map;
	struct _super_block *_sb = tx_cache_get_super(sb);

#ifdef CONFIG_TMPFS
	/*
	 * Per default we only allow half of the physical ram per
	 * tmpfs instance, limiting inodes to one per page of lowmem;
	 * but the internal instance is left unlimited.
	 */
	if (!(_sb->s_flags & MS_NOUSER)) {
		blocks = totalram_pages / 2;
		inodes = totalram_pages - totalhigh_pages;
		if (inodes > blocks)
			inodes = blocks;
		if (shmem_parse_options(data, &mode, &uid, &gid, &blocks,
					&inodes, &policy, &policy_nodes))
			return -EINVAL;
	}
	sb->s_export_op = &shmem_export_ops;
#else
	sb->s_flags |= MS_NOUSER;
#endif

	/* Round up to L1_CACHE_BYTES to resist false sharing */
	sbinfo = kmalloc(max((int)sizeof(struct shmem_sb_info),
				L1_CACHE_BYTES), GFP_KERNEL);
	if (!sbinfo)
		return -ENOMEM;

	spin_lock_init(&sbinfo->stat_lock);
	sbinfo->max_blocks = blocks;
	sbinfo->free_blocks = blocks;
	sbinfo->max_inodes = inodes;
	sbinfo->free_inodes = inodes;
	sbinfo->policy = policy;
	sbinfo->policy_nodes = policy_nodes;

	_sb->s_fs_info = sbinfo;
	sb->s_maxbytes = SHMEM_MAX_BYTES;
	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = TMPFS_MAGIC;
	sb->s_op = &shmem_ops;
	sb->s_time_gran = 1;
#ifdef CONFIG_TMPFS_POSIX_ACL
	sb->s_xattr = shmem_xattr_handlers;
	sb->s_flags |= MS_POSIXACL;
#endif

	inode = shmem_get_inode(sb, S_IFDIR | mode, 0);
	if (!inode)
		goto failed;
	_inode = tx_cache_get_inode(inode);
	
	_inode->i_uid = uid;
	_inode->i_gid = gid;
	root = d_alloc_root(_inode);
	if (!root)
		goto failed_iput;
	sb->s_root = root;
	return 0;

failed_iput:
	iput(inode);
failed:
	shmem_put_super(sb);
	return err;
}

static struct kmem_cache *shmem_inode_cachep;
static struct kmem_cache *_shmem_inode_cachep;

static struct inode *shmem_alloc_inode(struct super_block *sb)
{
	struct shmem_inode_info *info;
	struct _shmem_inode_info *_info;
	struct inode *inode;
	struct _inode *_inode;
	info = (struct shmem_inode_info *)kmem_cache_alloc(shmem_inode_cachep, GFP_KERNEL);
	if (!info)
		return NULL;

	_info = (struct _shmem_inode_info *)kmem_cache_alloc(_shmem_inode_cachep, GFP_KERNEL);
	if (!_info){
		kmem_cache_free(shmem_inode_cachep, info);
		return NULL;
	}

	/* Do the initialization before we go speculative, for heaven's sake */
	inode = &info->vfs_inode;
	_inode = &_info->_vfs_inode;
	memset(info, 0, (char *)inode - (char *)info);
	memset(_info, 0, (char *)_inode - (char *)_info);
	_inode->i_uid = current->fsuid;
	_inode->i_gid = current->fsgid;
	inode->i_blocks = 0;
	_inode->i_atime = _inode->i_mtime = _inode->i_ctime = CURRENT_TIME;
	inode->i_generation = get_seconds();
	spin_lock_init(&info->lock);
	INIT_TX_LIST(&_info->swaplist, tx_cache_get_inode_void, _inode, &inode->xobj);

	_inode->source = _shmem_inode_cachep;
	inode->i_contents = _inode;
	_inode->parent = inode;
	_info->parent = info;

#ifdef CONFIG_TX_KSTM	
	_inode->i_parent = _info;
	_inode->i_parent_size = sizeof(struct _shmem_inode_info);
	_inode->shadow = NULL;
	atomic_set(&_inode->tx_refcount, 0);
#endif
	return inode;
}

static void shmem_destroy_inode(struct inode *inode)
{
	struct _inode *_inode = tx_cache_get_inode(inode);
	if ((_inode->i_mode & S_IFMT) == S_IFREG) {
		/* only struct inode is valid if it's an inline symlink */
		mpol_free_shared_policy(&SHMEM_I(inode)->policy);
	}
	shmem_acl_destroy_inode(inode);
	kmem_cache_free(shmem_inode_cachep, SHMEM_I(inode));
	kmem_cache_free(_shmem_inode_cachep, _SHMEM_I(_inode));
}

static void init_once(void *foo, struct kmem_cache *cachep,
		      unsigned long flags)
{
	struct shmem_inode_info *p = (struct shmem_inode_info *) foo;

	inode_init_once(&p->vfs_inode);
}

static void _init_once(void *foo, struct kmem_cache *cachep,
		       unsigned long flags)
{
	struct _shmem_inode_info *p = (struct _shmem_inode_info *) foo;

	_inode_init_once(&p->_vfs_inode);
#ifdef CONFIG_TMPFS_POSIX_ACL
	p->i_acl = NULL;
	p->i_default_acl = NULL;
#endif
}


static int init_inodecache(void)
{
	shmem_inode_cachep = kmem_cache_create("shmem_inode_cache",
				sizeof(struct shmem_inode_info),
				0, 0, init_once, NULL);
	if (shmem_inode_cachep == NULL)
		return -ENOMEM;

	_shmem_inode_cachep = kmem_cache_create("_shmem_inode_cache",
				sizeof(struct _shmem_inode_info),
				0, 0, _init_once, NULL);
	if (_shmem_inode_cachep == NULL)
		return -ENOMEM;


	return 0;
}

static void destroy_inodecache(void)
{
	kmem_cache_destroy(shmem_inode_cachep);
	kmem_cache_destroy(_shmem_inode_cachep);
}

static const struct address_space_operations shmem_aops = {
	.writepage	= shmem_writepage,
	.set_page_dirty	= __set_page_dirty_no_writeback,
#ifdef CONFIG_TMPFS
	.prepare_write	= shmem_prepare_write,
	.commit_write	= simple_commit_write,
#endif
	.migratepage	= migrate_page,
};

static const struct file_operations shmem_file_operations = {
	.mmap		= shmem_mmap,
#ifdef CONFIG_TMPFS
	.llseek		= generic_file_llseek,
	.read		= shmem_file_read,
	.write		= shmem_file_write,
	.fsync		= simple_sync_file,
	.sendfile	= shmem_file_sendfile,
#endif
};

static const struct inode_operations shmem_inode_operations = {
	.truncate	= shmem_truncate,
	.setattr	= shmem_notify_change,
	.truncate_range	= shmem_truncate_range,
#ifdef CONFIG_TMPFS_POSIX_ACL
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= generic_listxattr,
	.removexattr	= generic_removexattr,
	.permission	= shmem_permission,
#endif
#ifdef CONFIG_TX_KSTM
	.commit         = shmem_commit_inode,
	.validate       = shmem_validate_inode,
	.lock           = shmem_lock_inode,
	.unlock         = shmem_unlock_inode,
	.init_tx        = shmem_init_tx_inode,
#endif

};

static const struct inode_operations shmem_dir_inode_operations = {
#ifdef CONFIG_TMPFS
	.create		= shmem_create,
	.lookup		= simple_lookup,
	.link		= shmem_link,
	.unlink		= shmem_unlink,
	.symlink	= shmem_symlink,
	.mkdir		= shmem_mkdir,
	.rmdir		= shmem_rmdir,
	.mknod		= shmem_mknod,
	.rename		= shmem_rename,
#endif
#ifdef CONFIG_TMPFS_POSIX_ACL
	.setattr	= shmem_notify_change,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= generic_listxattr,
	.removexattr	= generic_removexattr,
	.permission	= shmem_permission,
#endif
#ifdef CONFIG_TX_KSTM
	.commit         = shmem_commit_inode,
	.validate       = shmem_validate_inode,
	.lock           = shmem_lock_inode,
	.unlock         = shmem_unlock_inode,
	.init_tx        = shmem_init_tx_inode,
#endif

};

static const struct inode_operations shmem_special_inode_operations = {
#ifdef CONFIG_TMPFS_POSIX_ACL
	.setattr	= shmem_notify_change,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= generic_listxattr,
	.removexattr	= generic_removexattr,
	.permission	= shmem_permission,
#endif
#ifdef CONFIG_TX_KSTM
	.commit         = shmem_commit_inode,
	.validate       = shmem_validate_inode,
	.lock           = shmem_lock_inode,
	.unlock         = shmem_unlock_inode,
	.init_tx        = shmem_init_tx_inode,
#endif

};

static const struct super_operations shmem_ops = {
	.alloc_inode	= shmem_alloc_inode,
	.destroy_inode	= shmem_destroy_inode,
#ifdef CONFIG_TMPFS
	.statfs		= shmem_statfs,
	.remount_fs	= shmem_remount_fs,
#endif
	.delete_inode	= shmem_delete_inode,
	.drop_inode	= generic_delete_inode,
	.put_super	= shmem_put_super,
};

static struct vm_operations_struct shmem_vm_ops = {
	.nopage		= shmem_nopage,
	.populate	= shmem_populate,
#ifdef CONFIG_NUMA
	.set_policy     = shmem_set_policy,
	.get_policy     = shmem_get_policy,
#endif
};


static int shmem_get_sb(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data, struct vfsmount *mnt)
{
	return get_sb_nodev(fs_type, flags, data, shmem_fill_super, mnt);
}

static struct file_system_type tmpfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "tmpfs",
	.get_sb		= shmem_get_sb,
	.kill_sb	= kill_litter_super,
};
static struct vfsmount *shm_mnt;

static int __init init_tmpfs(void)
{
	int error;

	error = init_inodecache();
	if (error)
		goto out3;

	error = register_filesystem(&tmpfs_fs_type);
	if (error) {
		printk(KERN_ERR "Could not register tmpfs\n");
		goto out2;
	}

	shm_mnt = vfs_kern_mount(&tmpfs_fs_type, MS_NOUSER,
				tmpfs_fs_type.name, NULL);
	if (IS_ERR(shm_mnt)) {
		error = PTR_ERR(shm_mnt);
		printk(KERN_ERR "Could not kern_mount tmpfs\n");
		goto out1;
	}
	return 0;

out1:
	unregister_filesystem(&tmpfs_fs_type);
out2:
	destroy_inodecache();
out3:
	shm_mnt = ERR_PTR(error);
	return error;
}
module_init(init_tmpfs)

/*
 * shmem_file_setup - get an unlinked file living in tmpfs
 *
 * @name: name for dentry (to be seen in /proc/<pid>/maps
 * @size: size to be set for the file
 *
 */
struct file *shmem_file_setup(char *name, loff_t size, unsigned long flags)
{
	int error;
	struct file *file;
	struct _file *_file;
	struct inode *inode;
	struct _inode *_inode;
	struct dentry *dentry;
	struct _dentry *root;
	struct qstr this;

	if (IS_ERR(shm_mnt))
		return (void *)shm_mnt;

	if (size < 0 || size > SHMEM_MAX_BYTES)
		return ERR_PTR(-EINVAL);

	if (shmem_acct_size(flags, size))
		return ERR_PTR(-ENOMEM);

	error = -ENOMEM;
	this.name = name;
	this.len = strlen(name);
	this.hash = 0; /* will go */
	root = tx_cache_get_dentry(shm_mnt->mnt_root);
	dentry = d_alloc(root, &this);
	if (!dentry)
		goto put_memory;

	error = -ENFILE;
	file = get_empty_filp();
	if (!file)
		goto put_dentry;

	error = -ENOSPC;
	inode = shmem_get_inode(parent(root)->d_sb, S_IFREG | S_IRWXUGO, 0);
	if (!inode)
		goto close_file;
	_inode = tx_cache_get_inode(inode);

	_SHMEM_I(_inode)->flags = flags & VM_ACCOUNT;
	d_instantiate(tx_cache_get_dentry(dentry), _inode);
	_inode->i_size = size;
	_inode->i_nlink = 0;	/* It is unlinked */
	_file = tx_cache_get_file(file);
	_file->f_path.mnt = mntget(shm_mnt);
	_file->f_path.dentry = dentry;
	file->f_mapping = _inode->i_mapping;
	file->f_op = &shmem_file_operations;
	_file->f_mode = FMODE_WRITE | FMODE_READ;
	return file;

close_file:
	put_filp(file);
put_dentry:
	dput(dentry);
put_memory:
	shmem_unacct_size(flags, size);
	return ERR_PTR(error);
}

/*
 * shmem_zero_setup - setup a shared anonymous mapping
 *
 * @vma: the vma to be mmapped is prepared by do_mmap_pgoff
 */
int shmem_zero_setup(struct vm_area_struct *vma)
{
	struct file *file;
	loff_t size = vma->vm_end - vma->vm_start;

	file = shmem_file_setup("dev/zero", size, vma->vm_flags);
	if (IS_ERR(file))
		return PTR_ERR(file);

	if (vma->vm_file)
		fput(vma->vm_file);
	vma->vm_file = file;
	vma->vm_ops = &shmem_vm_ops;
	return 0;
}
