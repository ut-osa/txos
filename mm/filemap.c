/*
 *	linux/mm/filemap.c
 *
 * Copyright (C) 1994-1999  Linus Torvalds
 */

/*
 * This file handles the generic file mmap semantics used by
 * most "normal" filesystems (but you don't /have/ to use this:
 * the NFS filesystem used to do this differently, for example)
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/compiler.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/aio.h>
#include <linux/capability.h>
#include <linux/kernel_stat.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/hash.h>
#include <linux/writeback.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/cpuset.h>
#include "filemap.h"
#include "internal.h"
#include <linux/tx_inodes.h>
#include <linux/tx_dentry.h>
#include <linux/tx_file.h>
#include <linux/tx_super.h>
#include <linux/rmap.h>
#include <linux/debugtx.h>

/*
 * FIXME: remove all knowledge of the buffer layer from the core VM
 */
#include <linux/buffer_head.h> /* for generic_osync_inode */

#include <asm/mman.h>

static ssize_t
generic_file_direct_IO(int rw, struct kiocb *iocb, const struct iovec *iov,
	loff_t offset, unsigned long nr_segs);

/*
 * Shared mappings implemented 30.11.1994. It's not fully working yet,
 * though.
 *
 * Shared mappings now work. 15.8.1995  Bruno.
 *
 * finished 'unifying' the page and buffer cache and SMP-threaded the
 * page-cache, 21.05.1999, Ingo Molnar <mingo@redhat.com>
 *
 * SMP-threaded pagemap-LRU 1999, Andrea Arcangeli <andrea@suse.de>
 */

/*
 * Lock ordering:
 *
 *  ->i_mmap_lock		(vmtruncate)
 *    ->private_lock		(__free_pte->__set_page_dirty_buffers)
 *      ->swap_lock		(exclusive_swap_page, others)
 *        ->mapping->tree_lock
 *
 *  ->i_mutex
 *    ->i_mmap_lock		(truncate->unmap_mapping_range)
 *
 *  ->mmap_sem
 *    ->i_mmap_lock
 *      ->page_table_lock or pte_lock	(various, mainly in memory.c)
 *        ->mapping->tree_lock	(arch-dependent flush_dcache_mmap_lock)
 *
 *  ->mmap_sem
 *    ->lock_page		(access_process_vm)
 *
 *  ->i_mutex			(generic_file_buffered_write)
 *    ->mmap_sem		(fault_in_pages_readable->do_page_fault)
 *
 *  ->i_mutex
 *    ->i_alloc_sem             (various)
 *
 *  ->inode_lock
 *    ->sb_lock			(fs/fs-writeback.c)
 *    ->mapping->tree_lock	(__sync_single_inode)
 *
 *  ->i_mmap_lock
 *    ->anon_vma.lock		(vma_adjust)
 *
 *  ->anon_vma.lock
 *    ->page_table_lock or pte_lock	(anon_vma_prepare and various)
 *
 *  ->page_table_lock or pte_lock
 *    ->swap_lock		(try_to_unmap_one)
 *    ->private_lock		(try_to_unmap_one)
 *    ->tree_lock		(try_to_unmap_one)
 *    ->zone.lru_lock		(follow_page->mark_page_accessed)
 *    ->zone.lru_lock		(check_pte_range->isolate_lru_page)
 *    ->private_lock		(page_remove_rmap->set_page_dirty)
 *    ->tree_lock		(page_remove_rmap->set_page_dirty)
 *    ->inode_lock		(page_remove_rmap->set_page_dirty)
 *    ->inode_lock		(zap_pte_range->set_page_dirty)
 *    ->private_lock		(zap_pte_range->__set_page_dirty_buffers)
 *
 *  ->task->proc_lock
 *    ->dcache_lock		(proc_pid_lookup)
 */

/*
 * Remove a page from the page cache and free it. Caller has to make
 * sure the page is locked and that nobody else uses it - or that usage
 * is safe.  The caller must hold a write_lock on the mapping's tree_lock.
 */
void __remove_from_page_cache(struct page *page)
{
	struct address_space *mapping = page->mapping;

	radix_tree_delete(&mapping->page_tree, page->index);
	page->mapping = NULL;
	mapping->nrpages--;
	__dec_zone_page_state(page, NR_FILE_PAGES);
}

void remove_from_page_cache(struct page *page)
{
	struct address_space *mapping = page->mapping;

	BUG_ON(!PageLocked(page));

	write_lock_irq(&mapping->tree_lock);
	__remove_from_page_cache(page);
	write_unlock_irq(&mapping->tree_lock);
}

static int sync_page(void *word)
{
	struct address_space *mapping;
	struct page *page;

	page = container_of((unsigned long *)word, struct page, flags);

	/*
	 * page_mapping() is being called without PG_locked held.
	 * Some knowledge of the state and use of the page is used to
	 * reduce the requirements down to a memory barrier.
	 * The danger here is of a stale page_mapping() return value
	 * indicating a struct address_space different from the one it's
	 * associated with when it is associated with one.
	 * After smp_mb(), it's either the correct page_mapping() for
	 * the page, or an old page_mapping() and the page's own
	 * page_mapping() has gone NULL.
	 * The ->sync_page() address_space operation must tolerate
	 * page_mapping() going NULL. By an amazing coincidence,
	 * this comes about because none of the users of the page
	 * in the ->sync_page() methods make essential use of the
	 * page_mapping(), merely passing the page down to the backing
	 * device's unplug functions when it's non-NULL, which in turn
	 * ignore it for all cases but swap, where only page_private(page) is
	 * of interest. When page_mapping() does go NULL, the entire
	 * call stack gracefully ignores the page and returns.
	 * -- wli
	 */
	smp_mb();
	mapping = page_mapping(page);
	if (mapping && mapping->a_ops && mapping->a_ops->sync_page)
		mapping->a_ops->sync_page(page);
	io_schedule();
	return 0;
}

/**
 * __filemap_fdatawrite_range - start writeback on mapping dirty pages in range
 * @mapping:	address space structure to write
 * @start:	offset in bytes where the range starts
 * @end:	offset in bytes where the range ends (inclusive)
 * @sync_mode:	enable synchronous operation
 *
 * Start writeback against all of a mapping's dirty pages that lie
 * within the byte offsets <start, end> inclusive.
 *
 * If sync_mode is WB_SYNC_ALL then this is a "data integrity" operation, as
 * opposed to a regular memory cleansing writeback.  The difference between
 * these two operations is that if a dirty page/buffer is encountered, it must
 * be waited upon, and not just skipped over.
 */
int __filemap_fdatawrite_range(struct address_space *mapping, loff_t start,
				loff_t end, int sync_mode)
{
	int ret;
	struct writeback_control wbc = {
		.sync_mode = sync_mode,
		.nr_to_write = mapping->nrpages * 2,
		.range_start = start,
		.range_end = end,
	};

	if (!mapping_cap_writeback_dirty(mapping))
		return 0;

	ret = do_writepages(mapping, &wbc);
	return ret;
}

static inline int __filemap_fdatawrite(struct address_space *mapping,
	int sync_mode)
{
	return __filemap_fdatawrite_range(mapping, 0, LLONG_MAX, sync_mode);
}

int filemap_fdatawrite(struct address_space *mapping)
{
	return __filemap_fdatawrite(mapping, WB_SYNC_ALL);
}
EXPORT_SYMBOL(filemap_fdatawrite);

static int filemap_fdatawrite_range(struct address_space *mapping, loff_t start,
				loff_t end)
{
	return __filemap_fdatawrite_range(mapping, start, end, WB_SYNC_ALL);
}

/**
 * filemap_flush - mostly a non-blocking flush
 * @mapping:	target address_space
 *
 * This is a mostly non-blocking flush.  Not suitable for data-integrity
 * purposes - I/O may not be started against all dirty pages.
 */
int filemap_flush(struct address_space *mapping)
{
	return __filemap_fdatawrite(mapping, WB_SYNC_NONE);
}
EXPORT_SYMBOL(filemap_flush);

/**
 * wait_on_page_writeback_range - wait for writeback to complete
 * @mapping:	target address_space
 * @start:	beginning page index
 * @end:	ending page index
 *
 * Wait for writeback to complete against pages indexed by start->end
 * inclusive
 */
int wait_on_page_writeback_range(struct address_space *mapping,
				pgoff_t start, pgoff_t end)
{
	struct pagevec pvec;
	int nr_pages;
	int ret = 0;
	pgoff_t index;

	if (end < start)
		return 0;

	pagevec_init(&pvec, 0);
	index = start;
	while ((index <= end) &&
			(nr_pages = pagevec_lookup_tag(&pvec, mapping, &index,
			PAGECACHE_TAG_WRITEBACK,
			min(end - index, (pgoff_t)PAGEVEC_SIZE-1) + 1)) != 0) {
		unsigned i;

		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];

			/* until radix tree lookup accepts end_index */
			if (page->index > end)
				continue;

			wait_on_page_writeback(page);
			if (PageError(page))
				ret = -EIO;
		}
		pagevec_release(&pvec);
		cond_resched();
	}

	/* Check for outstanding write errors */
	if (test_and_clear_bit(AS_ENOSPC, &mapping->flags))
		ret = -ENOSPC;
	if (test_and_clear_bit(AS_EIO, &mapping->flags))
		ret = -EIO;

	return ret;
}

/**
 * sync_page_range - write and wait on all pages in the passed range
 * @inode:	target inode
 * @mapping:	target address_space
 * @pos:	beginning offset in pages to write
 * @count:	number of bytes to write
 *
 * Write and wait upon all the pages in the passed range.  This is a "data
 * integrity" operation.  It waits upon in-flight writeout before starting and
 * waiting upon new writeout.  If there was an IO error, return it.
 *
 * We need to re-take i_mutex during the generic_osync_inode list walk because
 * it is otherwise livelockable.
 */
int sync_page_range(struct inode *inode, struct address_space *mapping,
			loff_t pos, loff_t count)
{
	pgoff_t start = pos >> PAGE_CACHE_SHIFT;
	pgoff_t end = (pos + count - 1) >> PAGE_CACHE_SHIFT;
	int ret;

	if (!mapping_cap_writeback_dirty(mapping) || !count)
		return 0;
	ret = filemap_fdatawrite_range(mapping, pos, pos + count - 1);
	if (ret == 0) {
		if(!committing_transaction())
			mutex_lock(&inode->i_mutex);
		ret = generic_osync_inode(inode, mapping, OSYNC_METADATA);
		if(!committing_transaction())
			mutex_unlock(&inode->i_mutex);
	}
	if (ret == 0)
		ret = wait_on_page_writeback_range(mapping, start, end);
	return ret;
}
EXPORT_SYMBOL(sync_page_range);

/**
 * sync_page_range_nolock
 * @inode:	target inode
 * @mapping:	target address_space
 * @pos:	beginning offset in pages to write
 * @count:	number of bytes to write
 *
 * Note: Holding i_mutex across sync_page_range_nolock() is not a good idea
 * as it forces O_SYNC writers to different parts of the same file
 * to be serialised right until io completion.
 */
int sync_page_range_nolock(struct inode *inode, struct address_space *mapping,
			   loff_t pos, loff_t count)
{
	pgoff_t start = pos >> PAGE_CACHE_SHIFT;
	pgoff_t end = (pos + count - 1) >> PAGE_CACHE_SHIFT;
	int ret;

	if (!mapping_cap_writeback_dirty(mapping) || !count)
		return 0;
	ret = filemap_fdatawrite_range(mapping, pos, pos + count - 1);
	if (ret == 0)
		ret = generic_osync_inode(inode, mapping, OSYNC_METADATA);
	if (ret == 0)
		ret = wait_on_page_writeback_range(mapping, start, end);
	return ret;
}
EXPORT_SYMBOL(sync_page_range_nolock);

/**
 * filemap_fdatawait - wait for all under-writeback pages to complete
 * @mapping: address space structure to wait for
 *
 * Walk the list of under-writeback pages of the given address space
 * and wait for all of them.
 */
int filemap_fdatawait(struct address_space *mapping)
{
	struct _inode *inode = tx_cache_get_inode_ro(mapping->host);
	loff_t i_size = i_size_read(inode);

	if (i_size == 0)
		return 0;

	return wait_on_page_writeback_range(mapping, 0,
				(i_size - 1) >> PAGE_CACHE_SHIFT);
}
EXPORT_SYMBOL(filemap_fdatawait);

int filemap_write_and_wait(struct address_space *mapping)
{
	int err = 0;

	if (mapping->nrpages) {
		err = filemap_fdatawrite(mapping);
		/*
		 * Even if the above returned error, the pages may be
		 * written partially (e.g. -ENOSPC), so we wait for it.
		 * But the -EIO is special case, it may indicate the worst
		 * thing (e.g. bug) happened, so we avoid waiting for it.
		 */
		if (err != -EIO) {
			int err2 = filemap_fdatawait(mapping);
			if (!err)
				err = err2;
		}
	}
	return err;
}
EXPORT_SYMBOL(filemap_write_and_wait);

/**
 * filemap_write_and_wait_range - write out & wait on a file range
 * @mapping:	the address_space for the pages
 * @lstart:	offset in bytes where the range starts
 * @lend:	offset in bytes where the range ends (inclusive)
 *
 * Write out and wait upon file offsets lstart->lend, inclusive.
 *
 * Note that `lend' is inclusive (describes the last byte to be written) so
 * that this function can be used to write to the very end-of-file (end = -1).
 */
int filemap_write_and_wait_range(struct address_space *mapping,
				 loff_t lstart, loff_t lend)
{
	int err = 0;

	if (mapping->nrpages) {
		err = __filemap_fdatawrite_range(mapping, lstart, lend,
						 WB_SYNC_ALL);
		/* See comment of filemap_write_and_wait() */
		if (err != -EIO) {
			int err2 = wait_on_page_writeback_range(mapping,
						lstart >> PAGE_CACHE_SHIFT,
						lend >> PAGE_CACHE_SHIFT);
			if (!err)
				err = err2;
		}
	}
	return err;
}

/**
 * add_to_page_cache - add newly allocated pagecache pages
 * @page:	page to add
 * @mapping:	the page's address_space
 * @offset:	page index
 * @gfp_mask:	page allocation mode
 *
 * This function is used to add newly allocated pagecache pages;
 * the page is new, so we can just run SetPageLocked() against it.
 * The other page state flags were set by rmqueue().
 *
 * This function does not add the page to the LRU.  The caller must do that.
 */
int add_to_page_cache(struct page *page, struct address_space *mapping,
		pgoff_t offset, gfp_t gfp_mask)
{
	int error = radix_tree_preload(gfp_mask & ~__GFP_HIGHMEM);

	if (error == 0) {
		write_lock_irq(&mapping->tree_lock);
		error = radix_tree_insert(&mapping->page_tree, offset, page);
		if (!error) {
			page_cache_get(page);
			SetPageLocked(page);
			page->mapping = mapping;
			page->index = offset;
			mapping->nrpages++;
			__inc_zone_page_state(page, NR_FILE_PAGES);
		}
		write_unlock_irq(&mapping->tree_lock);
		radix_tree_preload_end();
	}
	return error;
}
EXPORT_SYMBOL(add_to_page_cache);

int add_to_page_cache_lru(struct page *page, struct address_space *mapping,
				pgoff_t offset, gfp_t gfp_mask)
{
	int ret = add_to_page_cache(page, mapping, offset, gfp_mask);
	if (ret == 0)
		lru_cache_add(page);
	return ret;
}

#ifdef CONFIG_NUMA
struct page *__page_cache_alloc(gfp_t gfp)
{
	if (cpuset_do_page_mem_spread()) {
		int n = cpuset_mem_spread_node();
		return alloc_pages_node(n, gfp, 0);
	}
	return alloc_pages(gfp, 0);
}
EXPORT_SYMBOL(__page_cache_alloc);
#endif

static int __sleep_on_page_lock(void *word)
{
	io_schedule();
	return 0;
}

/*
 * In order to wait for pages to become available there must be
 * waitqueues associated with pages. By using a hash table of
 * waitqueues where the bucket discipline is to maintain all
 * waiters on the same queue and wake all when any of the pages
 * become available, and for the woken contexts to check to be
 * sure the appropriate page became available, this saves space
 * at a cost of "thundering herd" phenomena during rare hash
 * collisions.
 */
static wait_queue_head_t *page_waitqueue(struct page *page)
{
	const struct zone *zone = page_zone(page);

	return &zone->wait_table[hash_ptr(page, zone->wait_table_bits)];
}

static inline void wake_up_page(struct page *page, int bit)
{
	__wake_up_bit(page_waitqueue(page), &page->flags, bit);
}

void fastcall wait_on_page_bit(struct page *page, int bit_nr)
{
	DEFINE_WAIT_BIT(wait, &page->flags, bit_nr);

	if (test_bit(bit_nr, &page->flags))
		__wait_on_bit(page_waitqueue(page), &wait, sync_page,
							TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(wait_on_page_bit);

/**
 * unlock_page - unlock a locked page
 * @page: the page
 *
 * Unlocks the page and wakes up sleepers in ___wait_on_page_locked().
 * Also wakes sleepers in wait_on_page_writeback() because the wakeup
 * mechananism between PageLocked pages and PageWriteback pages is shared.
 * But that's OK - sleepers in wait_on_page_writeback() just go back to sleep.
 *
 * The first mb is necessary to safely close the critical section opened by the
 * TestSetPageLocked(), the second mb is necessary to enforce ordering between
 * the clear_bit and the read of the waitqueue (to avoid SMP races with a
 * parallel wait_on_page_locked()).
 */
void fastcall unlock_page(struct page *page)
{
	smp_mb__before_clear_bit();
	if (!TestClearPageLocked(page))
		BUG();
	smp_mb__after_clear_bit(); 
	wake_up_page(page, PG_locked);
}
EXPORT_SYMBOL(unlock_page);

/**
 * end_page_writeback - end writeback against a page
 * @page: the page
 */
void end_page_writeback(struct page *page)
{
	if (!TestClearPageReclaim(page) || rotate_reclaimable_page(page)) {
		if (!test_clear_page_writeback(page))
			BUG();
	}
	smp_mb__after_clear_bit();
	wake_up_page(page, PG_writeback);
}
EXPORT_SYMBOL(end_page_writeback);

/**
 * __lock_page - get a lock on the page, assuming we need to sleep to get it
 * @page: the page to lock
 *
 * Ugly. Running sync_page() in state TASK_UNINTERRUPTIBLE is scary.  If some
 * random driver's requestfn sets TASK_RUNNING, we could busywait.  However
 * chances are that on the second loop, the block layer's plug list is empty,
 * so sync_page() will then return in state TASK_UNINTERRUPTIBLE.
 */
void fastcall __lock_page(struct page *page)
{
	DEFINE_WAIT_BIT(wait, &page->flags, PG_locked);

	__wait_on_bit_lock(page_waitqueue(page), &wait, sync_page,
							TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(__lock_page);

/*
 * Variant of lock_page that does not require the caller to hold a reference
 * on the page's mapping.
 */
void fastcall __lock_page_nosync(struct page *page)
{
	DEFINE_WAIT_BIT(wait, &page->flags, PG_locked);
	__wait_on_bit_lock(page_waitqueue(page), &wait, __sleep_on_page_lock,
							TASK_UNINTERRUPTIBLE);
}

/**
 * find_get_page - find and get a page reference
 * @mapping: the address_space to search
 * @offset: the page index
 *
 * Is there a pagecache struct page at the given (mapping, offset) tuple?
 * If yes, increment its refcount and return it; if no, return NULL.
 */
struct page * find_get_page(struct address_space *mapping, unsigned long offset)
{
	struct page *page;

	read_lock_irq(&mapping->tree_lock);
	page = radix_tree_lookup(&mapping->page_tree, offset);
	if (page)
		page_cache_get(page);
	read_unlock_irq(&mapping->tree_lock);
	return page;
}
EXPORT_SYMBOL(find_get_page);

/**
 * find_lock_page - locate, pin and lock a pagecache page
 * @mapping: the address_space to search
 * @offset: the page index
 *
 * Locates the desired pagecache page, locks it, increments its reference
 * count and returns its address.
 *
 * Returns zero if the page was not present. find_lock_page() may sleep.
 */
struct page *find_lock_page(struct address_space *mapping,
				unsigned long offset)
{
	struct page *page;

	read_lock_irq(&mapping->tree_lock);
repeat:
	page = radix_tree_lookup(&mapping->page_tree, offset);
	if (page) {
		page_cache_get(page);
		if (TestSetPageLocked(page)) {
			read_unlock_irq(&mapping->tree_lock);
			__lock_page(page);
			read_lock_irq(&mapping->tree_lock);

			/* Has the page been truncated while we slept? */
			if (unlikely(page->mapping != mapping ||
				     page->index != offset)) {
				unlock_page(page);
				page_cache_release(page);
				goto repeat;
			}
		}
	}
	read_unlock_irq(&mapping->tree_lock);
	return page;
}
EXPORT_SYMBOL(find_lock_page);

/**
 * find_or_create_page - locate or add a pagecache page
 * @mapping: the page's address_space
 * @index: the page's index into the mapping
 * @gfp_mask: page allocation mode
 *
 * Locates a page in the pagecache.  If the page is not present, a new page
 * is allocated using @gfp_mask and is added to the pagecache and to the VM's
 * LRU list.  The returned page is locked and has its reference count
 * incremented.
 *
 * find_or_create_page() may sleep, even if @gfp_flags specifies an atomic
 * allocation!
 *
 * find_or_create_page() returns the desired page's address, or zero on
 * memory exhaustion.
 */
struct page *find_or_create_page(struct address_space *mapping,
		unsigned long index, gfp_t gfp_mask)
{
	struct page *page, *cached_page = NULL;
	int err;
repeat:
	page = find_lock_page(mapping, index);
	if (!page) {
		if (!cached_page) {
			cached_page =
				__page_cache_alloc(gfp_mask);
			if (!cached_page)
				return NULL;
		}
		err = add_to_page_cache_lru(cached_page, mapping,
					index, gfp_mask);
		if (!err) {
			page = cached_page;
			cached_page = NULL;
		} else if (err == -EEXIST)
			goto repeat;
	}
	if (cached_page)
		page_cache_release(cached_page);
	return page;
}
EXPORT_SYMBOL(find_or_create_page);

/**
 * find_get_pages - gang pagecache lookup
 * @mapping:	The address_space to search
 * @start:	The starting page index
 * @nr_pages:	The maximum number of pages
 * @pages:	Where the resulting pages are placed
 *
 * find_get_pages() will search for and return a group of up to
 * @nr_pages pages in the mapping.  The pages are placed at @pages.
 * find_get_pages() takes a reference against the returned pages.
 *
 * The search returns a group of mapping-contiguous pages with ascending
 * indexes.  There may be holes in the indices due to not-present pages.
 *
 * find_get_pages() returns the number of pages which were found.
 */
unsigned find_get_pages(struct address_space *mapping, pgoff_t start,
			    unsigned int nr_pages, struct page **pages)
{
	unsigned int i;
	unsigned int ret;

	read_lock_irq(&mapping->tree_lock);
	ret = radix_tree_gang_lookup(&mapping->page_tree,
				(void **)pages, start, nr_pages);
	for (i = 0; i < ret; i++)
		page_cache_get(pages[i]);
	read_unlock_irq(&mapping->tree_lock);
	return ret;
}

/**
 * find_get_pages_contig - gang contiguous pagecache lookup
 * @mapping:	The address_space to search
 * @index:	The starting page index
 * @nr_pages:	The maximum number of pages
 * @pages:	Where the resulting pages are placed
 *
 * find_get_pages_contig() works exactly like find_get_pages(), except
 * that the returned number of pages are guaranteed to be contiguous.
 *
 * find_get_pages_contig() returns the number of pages which were found.
 */
unsigned find_get_pages_contig(struct address_space *mapping, pgoff_t index,
			       unsigned int nr_pages, struct page **pages)
{
	unsigned int i;
	unsigned int ret;

	read_lock_irq(&mapping->tree_lock);
	ret = radix_tree_gang_lookup(&mapping->page_tree,
				(void **)pages, index, nr_pages);
	for (i = 0; i < ret; i++) {
		if (pages[i]->mapping == NULL || pages[i]->index != index)
			break;

		page_cache_get(pages[i]);
		index++;
	}
	read_unlock_irq(&mapping->tree_lock);
	return i;
}
EXPORT_SYMBOL(find_get_pages_contig);

/**
 * find_get_pages_tag - find and return pages that match @tag
 * @mapping:	the address_space to search
 * @index:	the starting page index
 * @tag:	the tag index
 * @nr_pages:	the maximum number of pages
 * @pages:	where the resulting pages are placed
 *
 * Like find_get_pages, except we only return pages which are tagged with
 * @tag.   We update @index to index the next page for the traversal.
 */
unsigned find_get_pages_tag(struct address_space *mapping, pgoff_t *index,
			int tag, unsigned int nr_pages, struct page **pages)
{
	unsigned int i;
	unsigned int ret;

	read_lock_irq(&mapping->tree_lock);
	ret = radix_tree_gang_lookup_tag(&mapping->page_tree,
				(void **)pages, *index, nr_pages, tag);
	for (i = 0; i < ret; i++)
		page_cache_get(pages[i]);
	if (ret)
		*index = pages[ret - 1]->index + 1;
	read_unlock_irq(&mapping->tree_lock);
	return ret;
}
EXPORT_SYMBOL(find_get_pages_tag);

/**
 * grab_cache_page_nowait - returns locked page at given index in given cache
 * @mapping: target address_space
 * @index: the page index
 *
 * Same as grab_cache_page(), but do not wait if the page is unavailable.
 * This is intended for speculative data generators, where the data can
 * be regenerated if the page couldn't be grabbed.  This routine should
 * be safe to call while holding the lock for another page.
 *
 * Clear __GFP_FS when allocating the page to avoid recursion into the fs
 * and deadlock against the caller's locked page.
 */
struct page *
grab_cache_page_nowait(struct address_space *mapping, unsigned long index)
{
	struct page *page = find_get_page(mapping, index);

	if (page) {
		if (!TestSetPageLocked(page))
			return page;
		page_cache_release(page);
		return NULL;
	}
	page = __page_cache_alloc(mapping_gfp_mask(mapping) & ~__GFP_FS);
	if (page && add_to_page_cache_lru(page, mapping, index, GFP_KERNEL)) {
		page_cache_release(page);
		page = NULL;
	}
	return page;
}
EXPORT_SYMBOL(grab_cache_page_nowait);

/*
 * CD/DVDs are error prone. When a medium error occurs, the driver may fail
 * a _large_ part of the i/o request. Imagine the worst scenario:
 *
 *      ---R__________________________________________B__________
 *         ^ reading here                             ^ bad block(assume 4k)
 *
 * read(R) => miss => readahead(R...B) => media error => frustrating retries
 * => failing the whole request => read(R) => read(R+1) =>
 * readahead(R+1...B+1) => bang => read(R+2) => read(R+3) =>
 * readahead(R+3...B+2) => bang => read(R+3) => read(R+4) =>
 * readahead(R+4...B+3) => bang => read(R+4) => read(R+5) => ......
 *
 * It is going insane. Fix it by quickly scaling down the readahead size.
 */
static void shrink_readahead_size_eio(struct file *filp,
					struct file_ra_state *ra)
{
	if (!ra->ra_pages)
		return;

	ra->ra_pages /= 4;
}


# define alloc_range_lock()	kmem_cache_alloc(range_lock_cachep, GFP_ATOMIC)
# define free_range_lock(tsk)	kmem_cache_free(range_lock_cachep, (tsk))
struct kmem_cache *range_lock_cachep;

static inline int range_intersection(loff_t start1, loff_t end1,
				     loff_t start2, loff_t end2){
	return (start1 < end2 && start2 < end1);
}


/* Returns true if the two ranges intersect or have no empty space between */
static inline int range_adjacent(loff_t start1, loff_t end1,
				 loff_t start2, loff_t end2){
	return (start1 <= end2 && start2 <= end1);
}

//allows for overlapping ranges
static inline void insert_range_lock_uninit_r(struct range_lock *lock,
					      struct list_head *st_after,
					      struct skiplist_head *end_head,
					      struct skiplist_head *end_after) {
	INIT_LIST_HEAD(&lock->list_st);
	INIT_SKIPLIST_HEAD(&lock->list_end);
	list_add(&lock->list_st, st_after);
	insert_skiplist_at(&lock->list_end, end_head, end_after);
}

//rw locks only!
static inline void insert_range_lock_uninit_rw(struct range_lock *lock,
					       struct skiplist_head *head,
					       struct skiplist_head *after) {
	INIT_LIST_HEAD(&lock->list_st);
	INIT_SKIPLIST_HEAD(&lock->list_end);
	insert_skiplist_at(&lock->list_end, head, after);
}


#define SKIPLIST_WALK_INT_MODE_INCL 0
#define SKIPLIST_WALK_INT_MODE_EXCL 1
#define SKIPLIST_WALK_INT_MODE_NOT  2
#define SKIPLIST_WALK_INT_MODE_NOFR 3

/* __walk_intersection_range
 * general purpose function for walking all elements that intersect
 * with the range [start..end]. Some notes:
 * - Each range_lock is in a skiplist sorted by endpoint
 * - Read range_locks may overlap with one another, so endpoint is not
 *   enough to find all range_locks that overlap with a region.
 *   * In light of this, read range_locks are in a separate linked list
 *     sorted by startpoint
 * Preconditions:
 * - elem is the first range lock that intersects with the specified 
 *   range
 * - satisfiesCondition is a function that identifies what to do with
 *   each entry that overlaps in that range.
 * Returns:
 *   either a count of the overlapping entries that satisfy the condition
 *   specified by satisfiesCondition, or -1 if the search should be retried
 *   because something about the skiplist was changed (e.g. abort of 
 *   contending tx).
 */
static int __walk_intersection_range(struct list_head *st_head,
				     struct skiplist_head *end_head,
				     struct range_lock *elem,
				     loff_t start, loff_t end,
				     enum access_mode mode,
				     struct transaction *tx,
				     struct transaction **victim,
				     int (*satisfiesCondition)(
					     struct range_lock *,
					     enum access_mode ,
					     struct transaction *,
					     struct range_lock *),
				     struct range_lock *to_compare) {
	struct skiplist_head *next_sl;
	struct list_head *next_st_list = elem->list_st.next;
	struct range_lock *next;
	int count = 0;
	int retval;

	if (!range_adjacent(start, end, elem->start, elem->end))
		return 0;
	
	//first, walk end skiplist until elem->end falls off the
	//end of the query range, or we are in a situation where
	//the range_locks do not overlap (rw locks) and the elem
	//no longer intersects
	while (elem->end <= end ||
	       (st_head == NULL && range_adjacent(start, end,
						  elem->start, 
						  elem->end))) {
		next_sl = elem->list_end.next[0];
		next_st_list = elem->list_st.next;
		retval = (*satisfiesCondition)(elem, mode, tx, to_compare);
		if (retval > 0)
			count ++;
		else if (retval == -1) {
			*victim = elem->tx;
			return -1;
		} else if (retval == -2) {
			abortTransaction(elem->tx);
			if (elem->list_st.next != &elem->list_st)
				list_del(&elem->list_st);
			skiplist_del(&elem->list_end);
			free_range_lock(elem);
		} else if (retval == -3) {
			if (elem->start < to_compare->start)
				to_compare->start = elem->start;
			if (elem->end > to_compare->end)
				to_compare->end = elem->end;
			if (elem->mapped)
				to_compare->mapped = elem->mapped;
			if (elem->list_st.next != &elem->list_st)
				list_del(&elem->list_st);
			skiplist_del(&elem->list_end);
			free_range_lock(elem);
		} else if (retval == -4) {
			abortTransaction(elem->tx);
			if (elem->list_st.next != &elem->list_st)
				list_del(&elem->list_st);
			skiplist_del(&elem->list_end);
			free_range_lock(elem);
		}
		if (next_sl == end_head)
			break;
		next = sl_rl_entry_end(next_sl);
		if (st_head != NULL && next->end >= end)
			break;
		elem = next;
	}
	
	if (st_head == NULL || next_st_list == st_head ||
		next_st_list == next_st_list->next)
		return count; //for rw list with no overlap

	//next, walk start skiplist until elem->start falls off the end of
	//the query range
	
	elem = rl_entry_st(next_st_list);
	while (elem->start <= end) {
		next_st_list = elem->list_st.next;
		if (range_adjacent(start, end,elem->start,elem->end)) {
			retval = (*satisfiesCondition)(elem, mode, tx, 
						       to_compare);
			if (retval > 0)
				count ++;
			else if (retval == -1) {
				*victim = elem->tx;
				return -1;
			} else if (retval == -2) {
				abortTransaction(elem->tx);
				list_del(&elem->list_st);
				skiplist_del(&elem->list_end);
				free_range_lock(elem);
			} else if (retval == -3) {
				if (elem->start < to_compare->start)
					to_compare->start = elem->start;
				if (elem->end > to_compare->end)
					to_compare->end = elem->end;
				if (elem->mapped)
					to_compare->mapped = elem->mapped;
				list_del(&elem->list_st);
				skiplist_del(&elem->list_end);
				free_range_lock(elem);
			} else if (retval == -4) {
				abortTransaction(elem->tx);
				list_del(&elem->list_st);
				skiplist_del(&elem->list_end);
				free_range_lock(elem);
			}
		}
		if (elem->list_st.next == st_head)
			break;
		next = rl_entry_st(next_st_list);
		elem = next;
	}
	return count;
}

static int satisfies_not(struct range_lock *elem, enum access_mode mode,
			 struct transaction *tx, 
			 struct range_lock *to_compare){
	return (elem != to_compare);
}

static inline int walk_int_range_not(struct list_head *st_head,
				     struct skiplist_head *end_head,
				     struct range_lock *elem,
				     loff_t start, loff_t end,
				     struct range_lock *to_compare) {
	struct transaction *dummy;

	return __walk_intersection_range(st_head, end_head, elem,
					 start, end, to_compare->mode,
					 to_compare->tx, &dummy,
					 &satisfies_not,
					 to_compare);
}

static int satisfies_incl(struct range_lock *elem, enum access_mode mode,
			  struct transaction *tx, 
			  struct range_lock *to_compare){
	if(to_compare && elem
	   && range_intersection(elem->start, elem->end, 
				 to_compare->start, to_compare->end)
	   && (((mode == ACCESS_R && elem->mode == ACCESS_RW) ||
		mode == ACCESS_RW) && elem->tx != tx)) {
		return -1;
	} else if (elem->tx == tx && elem->mode == mode)
		return 1;
	return 0;
}

static inline int walk_int_range_noabort(struct list_head *st_head,
					 struct skiplist_head *end_head,
					 struct range_lock *elem,
					 loff_t start, loff_t end,
					 enum access_mode mode,
					 struct transaction *tx) {
	struct transaction *dummy;
	return __walk_intersection_range(st_head, end_head, elem,
					 start, end, mode, tx, &dummy,
					 &satisfies_incl, NULL);
}

static inline int walk_int_range_abort(struct address_space *mapping,
				       struct list_head *st_head,
				       struct skiplist_head *end_head,
				       struct range_lock *elem,
				       loff_t start, loff_t end,
				       enum access_mode mode,
				       struct transaction *tx) {
	struct transaction *victim;
	int retval;
	struct range_lock to_compare;
	to_compare.start = start;
	to_compare.end = end;
	retval = __walk_intersection_range(st_head, end_head,
					   elem, start, end, mode, 
					   tx, &victim, 
					   &satisfies_incl, &to_compare);

	if (retval == -1) {
		if(contentionManager(tx, victim, NULL)){
			abortTransaction(victim);
			abort_tx_rw(mapping, victim);
			return -1;
		} else {
			abort_tx_rw(mapping, tx);
			mutex_unlock(&mapping->host->i_mutex);
			abort_self(victim, 0);
			return 0;
		}
	}

	return retval;


}

static int satisfies_excl(struct range_lock *elem, enum access_mode mode,
			  struct transaction *tx, 
			  struct range_lock *to_compare){
	if (elem->tx != tx)
		return 1;
	return 0;
}

static inline int walk_int_range_excl(struct list_head *st_head,
				      struct skiplist_head *end_head,
				      struct range_lock *elem,
				      loff_t start, loff_t end,
				      struct transaction *tx) {
	struct transaction *dummy;
	return __walk_intersection_range(st_head, end_head, elem,
					 start, end, 0, tx, &dummy,
					 &satisfies_excl, NULL);
}

static int satisfies_mergeable(struct range_lock *elem, enum access_mode mode,
			  struct transaction *tx, 
			  struct range_lock *to_compare){
	if (elem != to_compare && elem->mode == mode && elem->tx == tx)
		return -3;
	return 0;
}

static inline void merge_colliding_ranges(struct list_head *st_head,
					  struct skiplist_head *end_head,
					  struct range_lock *entry) {
	struct transaction *dummy;
	__walk_intersection_range(st_head, end_head, entry,
				  entry->start-1, entry->end+1, 
				  entry->mode, entry->tx, &dummy,
				  &satisfies_mergeable, entry);
}

static int satisfies_unfair(struct range_lock *elem, enum access_mode mode,
			  struct transaction *tx, 
			  struct range_lock *to_compare){
	if (((mode == ACCESS_R && elem->mode == ACCESS_RW) ||
	     mode == ACCESS_RW) && elem->tx != tx) {
		return -4;
	}
	return 0;
}

static inline int walk_int_range_nofair(struct list_head *st_head,
					struct skiplist_head *end_head,
					struct range_lock *elem,
					loff_t start, loff_t end,
					enum access_mode mode) {

	struct transaction *dummy;
	return __walk_intersection_range(st_head, end_head, elem,
					 start, end, mode, NULL, &dummy,
					 &satisfies_unfair, NULL);
}

static int satisfies_sametx(struct range_lock *elem, enum access_mode mode,
		struct transaction *tx, struct range_lock *to_compare) {
	if(elem->tx == tx)
		return -1;
	return 0;
}

static inline int walk_int_range_sametx(struct skiplist_head *end_head,
		struct transaction *tx, struct range_lock *elem,
		loff_t start, loff_t end) {
	struct transaction *dummy;
	return __walk_intersection_range(NULL, end_head, elem, start, end, ACCESS_RW,
				tx, &dummy, &satisfies_sametx, NULL) < 0;
}

/* search_for_nearest_pt 
 *
 * If there is an intersection in the skiplist, returns the first
 * range_lock that intersects with or is adjacent to the specified
 * range. This is identical to the range_lock whose endpoint is the
 * smallest of those range_locks intersecting with the query. If not,
 * it returns the range_lock whose endpoint is the last of all
 * range_locks before the query range.  Note that before inserting,
 * one must walk the startpoint list to reach the point of insertion
 * for that list.  Does this in O(log(n)) time.
 */
static inline struct range_lock *search_for_nearest_pt(loff_t start,
						       loff_t end,
						       struct skiplist_head
						       *head) {
	struct skiplist_head *next, *ptr = head;
	struct range_lock *entry = NULL, *last;
	int level = head->level - 1;

	/* Find highest non-empty level of the skiplist *
	 * that doesn't end past start                  */
	do {
		next = ptr->next[level];
		if (next == head)
			level--;
		else {
			entry = sl_rl_entry_end(next);
			if (entry->end >= start) {
				level--;
			} else {
				ptr = next;
			}
		}
	} while (ptr == head && level >= 0);

	/* If ptr is still head, one of three situations has occurred:
	 * 1. The skiplist is empty
	 * 2. The first entry lies after the range
	 * 3. The first entry intersects with the range
	 */
	if (ptr == head) {
		if (next!=head && range_adjacent(entry->start,
						 entry->end,
						 start, end)) {
			return entry;
		} else {
			//failed to find nearest pt
			//special case -- it's at beginning
			return NULL;
		}
	}

	/* Find the first entry with an end past start */
	do {
		next = ptr->next[level];
		if (next == head)
			level--;
		else {
			entry = sl_rl_entry_end(next);
			if (entry->end >= start) {
				level--;
			} else {
				ptr = next;
			}
		}
	} while (ptr != head && (level >= 0));
	
	KSTM_BUG_ON(ptr == head); // should never be set to head at this pt
	
	/* ptr is pointing to the last element whose end range is before start. */
	/* Check whether ptr is adjacent; if so, return ptr's entry */
	entry = sl_rl_entry_end(ptr);
	if (range_adjacent(entry->start, entry->end, start, end))
		return entry;
	else {
		/* If ptr's not adjacent, next entry may be */
		next = ptr->next[0];
		if (next == head)
			return entry;
		last = entry;
		entry = sl_rl_entry_end(next);
		/* dp: Will this ever be true? */
		/* ab: Yes. If ptr is to the left of range, ptr's next entry
		 * may intersect. */
		if (range_adjacent(entry->start, entry->end, start, end)){
			return entry;
		} else {
			//the next entry was to the right of range. Go back
			return last;
		}
	}
}

static inline struct list_head *search_from_st(struct list_head *from,
					       loff_t start,
					       struct list_head *head) {
	struct list_head *loc, *next;
	struct range_lock *entry;
	loc = from;
	next = from->next;
	while (next != head) {
		entry = rl_entry_st(next);
		if (entry->start >= start)
			break;
		loc = next;
		next = loc->next;
	}
	return loc;
}


static inline struct list_head *search_for_first_st(loff_t start,
						    struct list_head *head) {
	return search_from_st(head, start, head);
}

/* keep this around for future debugging */
/*
static void print_lock_list_structure(struct skiplist_head *head) {
	int level, i;
	struct skiplist_head *ls;
	
	BUG_ON(verify_skiplist_structure(head));

	printk(KERN_ERR "Printing skiplist structure with lock details:\n");

	level = head->level; //head is always at the max level of the skiplist
	ls = head;
	do {
		struct range_lock *entry;
		printk(KERN_ERR "<%lx>", (unsigned long)ls);
		for (i=0; i<ls->level; i++)
			printk(KERN_ERR "-");
		for (i=ls->level; i<head->level; i++)
			printk(KERN_ERR "|");
		entry = sl_rl_entry_end(ls);
		printk(KERN_ERR "srt=%lld end=%lld\n",entry->start, entry->end);
		ls = ls->next[0];
	} while (ls != head);
}
*/

static void drop_buffered_write(struct address_space *mapping,
				struct range_lock *range){
	/* For each page spanned by this write, we need to: 
	 *
	 *  1) Check how many other tx's have a write on this page.
	 *     If more than one, we need to copy the stable contents
	 *     over the written range in the shadow page.  If only
	 *     one, free the shadow page.
	 *  2) If only one writer, unmark the stable page as spec.
	 */
	loff_t off = range->start;
	loff_t start = off & PAGE_CACHE_MASK;
	struct transaction *tx = current->transaction;
	while(start < range->end){
		int rcount = 0, wcount = 1;
		int ret;
		loff_t end = start + PAGE_CACHE_SIZE;
		struct page *page = NULL, *page2;
		struct range_lock *first_hit;

		//first do rcount
		first_hit = search_for_nearest_pt(start+1, end-1,
						  &mapping->range_locks_r_end);
		if (first_hit != NULL && range_intersection(first_hit->start,
							    first_hit->end,
							    start, end)) {
			ret = walk_int_range_excl(
				&mapping->range_locks_r_st,
				&mapping->range_locks_r_end, first_hit,
				start+1, end-1, tx);
			KSTM_BUG_ON(ret < 0);
			rcount = ret;
		}

		//next do wcount
		first_hit = search_for_nearest_pt(start+1, end-1,
						  &mapping->range_locks_rw);
		if (first_hit != NULL && range_intersection(first_hit->start,
							    first_hit->end,
							    start, end)) {
			ret = walk_int_range_excl(
				NULL, &mapping->range_locks_rw, first_hit,
				start+1, end-1, tx);
			KSTM_BUG_ON(ret < 0);
			wcount = ret+1;
		}

		/*
		list_for_each_entry(entry, &mapping->range_locks, list){
			if(entry->tx != range->tx
			   && range_intersection(entry->start, entry->end,
						 start, end)){
				if(entry->mode == ACCESS_RW){
					wcount++;
				} else {
					rcount++;
				}
			}
		} 
		*/

		if(wcount == 1){
			/* Just drop the page */
			write_lock_irq(&mapping->tree_lock);
			page2 = radix_tree_lookup(&mapping->shadow_tree, start >> PAGE_CACHE_SHIFT);
			
			if(!page2){
				write_unlock_irq(&mapping->tree_lock);

				printk(KERN_ERR "WTF - missing page\n");
				DEBUG_BREAKPOINT();

				start += PAGE_CACHE_SIZE;
				continue;
			}

			radix_tree_delete(&mapping->shadow_tree, page2->index);
			write_unlock_irq(&mapping->tree_lock);
		} else {
			/* We need to re-copy the relevant range */
			char *addr, *addr2;
			loff_t copy_start = start < range->start ? range->start : start;
			loff_t copy_end = end > range->end ? range->end : end;
			int offset = copy_start % PAGE_SIZE;
			int copy_size = copy_end - copy_start;
			read_lock_irq(&mapping->tree_lock);
			page2 = radix_tree_lookup(&mapping->shadow_tree, start >> PAGE_CACHE_SHIFT );
			page = radix_tree_lookup(&mapping->page_tree, start >> PAGE_CACHE_SHIFT);
			read_unlock_irq(&mapping->tree_lock);
			addr = kmap_atomic(page, KM_TM0);
			addr2 = kmap_atomic(page2, KM_TM1);
			memcpy(addr2 + offset, addr + offset, copy_size);
			kunmap_atomic(addr2, KM_TM1);
			kunmap_atomic(addr, KM_TM0);
		}

		/* If this page was mapped, shoot it down */
		if(range->mapped && page_mapped(page2)){
			int rv;
			BUG_ON(wcount != 1);
			__lock_page_nosync(page2);
			rv = try_to_unmap(page2, 1);
			unlock_page(page2);
			BUG_ON(rv != SWAP_SUCCESS);
		}

		if(wcount == 1){
			page2->mapping = NULL;
			page_cache_release(page2);
			mapping->nrpages--;

			if(rcount == 0){
				if(!page){
					read_lock_irq(&mapping->tree_lock);
					page = radix_tree_lookup(&mapping->page_tree, start >> PAGE_CACHE_SHIFT);
					read_unlock_irq(&mapping->tree_lock);
				}
				if(page)
					ClearPageSpec(page);
			}
		}

		start += PAGE_CACHE_SIZE;
	}
}

static void commit_buffered_write(struct address_space *mapping,
				  struct range_lock *range){
	/* For each page spanned by this write, we need to: 
	 *
	 *  1) Check how many other tx's have a write on this page.
	 *     If more than one, we need to copy the stable contents
	 *     to the stable page.  If only one, replace the shadow
	 *     page with the stable one.
	 *  2) If only one writer, unmark the stable page as spec.
	 */
	loff_t start = range->start & PAGE_CACHE_MASK;
	long		status = 0;
	while(start < range->end){
		int wcount = 1, rcount = 0, ret;
		loff_t copy_start = start < range->start ? range->start : start;
		loff_t end = ((copy_start + PAGE_SIZE) & PAGE_CACHE_MASK);
		loff_t copy_end = end > range->end ? range->end : end;
		unsigned int offset = copy_start % PAGE_SIZE;
		unsigned int copy_size = copy_end - copy_start;
		unsigned int to = offset + copy_size;
		char *addr, *addr2;
		loff_t index = start >> PAGE_CACHE_SHIFT;

		struct page *page = NULL, *page2;
		int lock_page = 1;
		struct range_lock *first_hit;

		KSTM_BUG_ON((start & PAGE_MASK) != ((end - 1) & PAGE_MASK));

		/* The page writeback interfaces are a real CF of
		 * off-by-one errors waiting to happen.  Some want the
		 * end to include the last byte, some want one
		 * past. And on top of that, some of our range locking
		 * intersection code has this assumption baked in far
		 * enough down in the layers of interface that the
		 * only sane way to get adjacency v intersection is to
		 * otherwise inexplicably subtract another byte.  
		 */

		//first do rcount
		first_hit = search_for_nearest_pt(start+1, end - 1,
						  &mapping->range_locks_r_end);
		if (first_hit != NULL) {
			ret = walk_int_range_not(
				&mapping->range_locks_r_st,
				&mapping->range_locks_r_end, first_hit,
				start+1, end-2, range);
			KSTM_BUG_ON(ret < 0);
			rcount = ret;
		}
		
		//next do wcount
		first_hit = search_for_nearest_pt(start+1, end - 1,
						  &mapping->range_locks_rw);
		if (first_hit != NULL) {
			ret = walk_int_range_not(
				NULL, &mapping->range_locks_rw, first_hit,
				start+1, end - 1, range);
			KSTM_BUG_ON(ret < 0);
			wcount = ret+1;
		}

		read_lock_irq(&mapping->tree_lock);
		page = radix_tree_lookup(&mapping->page_tree, index);
		if(!page){
			int error;
			read_unlock_irq(&mapping->tree_lock);
			page = page_cache_alloc_cold(mapping);
			BUG_ON(!page);
			error = add_to_page_cache_lru(page, mapping, index, GFP_KERNEL);
			read_lock_irq(&mapping->tree_lock);
			BUG_ON(error);
			lock_page = 0;
		}
		page2 = radix_tree_lookup(&mapping->shadow_tree, index);

		read_unlock_irq(&mapping->tree_lock);
		if(!page2){

			printk(KERN_ERR "WTF - mapping %p missing page index %llu.  start %llu, end %llu, range start, end = (%llu, %llu)\n", mapping, index, start, end, range->start, range->end);
			DEBUG_BREAKPOINT();

			start += PAGE_CACHE_SIZE;
			continue;
		}
		//BUG_ON(!page2);

		/* Make sure this stuff gets flushed to disk */
		if(lock_page)
			__lock_page(page);
		
		status = mapping->a_ops->prepare_write(range->file, page,
						       offset, 
						       to);
		
		if(unlikely(status))
			printk(KERN_ERR "Bad status: %ld\n", status);
		KSTM_BUG_ON(status);
		
		/* DEP 2/10/09 : I think we have to do a memcpy like
		 * this to work with prepare/commit write.  Even if it
		 * is the whole block.
		 */
		addr = kmap_atomic(page, KM_TM0);
		addr2 = kmap_atomic(page2, KM_TM1);
		memcpy(addr + offset, addr2 + offset, copy_size);
		kunmap_atomic(addr2, KM_TM1);
		kunmap_atomic(addr, KM_TM0);
		
		status = mapping->a_ops->commit_write(range->file, page, 
						      offset,
						      to);
		
		if(unlikely(status))
			printk(KERN_ERR "Bad status: %ld\n", status);

		/* There are a few edge cases where
		 * mark_paged_accessed won't do anything, so let's
		 * just do this twice.
		 */
		if(!(PageReferenced(page) && PageActive(page))){
			mark_page_accessed(page);
			mark_page_accessed(page);
		}
		
		/* If this page was mapped, shoot it down */
		if(range->mapped && page_mapped(page2)){
			int rv;
			BUG_ON(wcount != 1);
			/* So we don't actually want a migration of 1,
			 * except that the vm is locked and migration
			 * is a noop otherwise.  Whatever.
			 */
			__lock_page_nosync(page2);
			rv = try_to_unmap(page2, 1);
			unlock_page(page2);
			BUG_ON(rv != SWAP_SUCCESS);
		}
		
		unlock_page(page);

		if(wcount == 1){
			write_lock_irq(&mapping->tree_lock);
			radix_tree_delete(&mapping->shadow_tree, page2->index);
			write_unlock_irq(&mapping->tree_lock);
			page2->mapping = NULL;
			page_cache_release(page2);
			mapping->nrpages--;
		}

		if(wcount == 1 && rcount == 0)
			ClearPageSpec(page);
		
		start += PAGE_CACHE_SIZE;
		start &= PAGE_CACHE_MASK;
	}
}


/* Dump the speculative reads and writes for a tx */
int abort_tx_rw(struct address_space *mapping, struct transaction *tx){
	int rv = 0;
	struct range_lock *entry, *n;
	
	skiplist_for_each_entry_safe(entry, n, &mapping->range_locks_rw, list_end){
		if(entry->tx == tx){
			drop_buffered_write(mapping, entry);
			skiplist_del(&entry->list_end);
			free_range_lock(entry);
		} else 
			rv = 1;
	}

	list_for_each_entry_safe(entry, n, &mapping->range_locks_r_st, list_st){
		if(entry->tx == tx){
			list_del(&entry->list_st);
			skiplist_del(&entry->list_end);
			free_range_lock(entry);
		} else 
			rv = 1;
	}
	
	return rv;
}

int commit_tx_rw(struct address_space *mapping, struct transaction *tx){
	int rv = 0;
	struct range_lock *entry, *n;
	skiplist_for_each_entry_safe(entry, n, &mapping->range_locks_rw, list_end){
		if(entry->tx == tx){
			commit_buffered_write(mapping, entry);
			skiplist_del(&entry->list_end);
			free_range_lock(entry);
		} else
			rv = 1;
	}
	list_for_each_entry_safe(entry, n, &mapping->range_locks_r_st, list_st){
		if(entry->tx == tx){
			list_del(&entry->list_st);
			skiplist_del(&entry->list_end);
			free_range_lock(entry);
		} else
			rv = 1;
	}
	return rv;
}

static int allocate_range_lock(struct address_space *mapping,
				struct file *file,
				loff_t start,
				size_t count,
				enum access_mode mode, 
				int mapped){
	struct transaction *tx = current->transaction;
	struct range_lock *first_hit, *r_hit, *rw_hit;
	loff_t end = start + count;
	int same_page = 0;
	int ret, isect_flag;
	struct skiplist_head *sl_head;
	
	if(mode == ACCESS_RW)
		mark_inode_data_rw(mapping->host);
	else
		mark_inode_data_r(mapping->host);

restart:
	isect_flag = 0;
	//readers first
	sl_head = &mapping->range_locks_r_end;
	r_hit = first_hit = search_for_nearest_pt(start, end, sl_head);
	if (first_hit != NULL) {
		ret = walk_int_range_abort(
			mapping, &mapping->range_locks_r_st,
			sl_head, first_hit, start, end, mode, tx);
		if (ret == -1)
			goto restart;
		else if (ret > 0) {
			//range intersection found!
			isect_flag = 1;
			if (first_hit->start > start)
				first_hit->start = start;
			
			if (first_hit->end < end)
				first_hit->end = end;
			
			if (mapped)
				first_hit->mapped = mapped;
			
			merge_colliding_ranges(&mapping->range_locks_r_st, 
					       sl_head, first_hit);
		}
	}

	//then writers
	sl_head = &mapping->range_locks_rw;
	rw_hit = first_hit = search_for_nearest_pt(start, end, sl_head);
	if (first_hit != NULL) {

		/* If the found element actually intersects the
		 * desired range, or if that element or its successor
		 * reside on the same page as the desired range, then
		 * that page has already been written to. Note that
		 * this requires that all write lock allocations are
		 * smaller than a page and do not cross a boundary */
		if(mode == ACCESS_RW) {
			loff_t start_page = (start & PAGE_MASK) + 2;
			loff_t end_page = ((start + PAGE_SIZE) & PAGE_MASK) - 2;
			struct range_lock *sametx_hit = search_for_nearest_pt(start_page, end_page, sl_head);
			if(sametx_hit){
				KSTM_BUG_ON((start & PAGE_MASK) != ((end-1) & PAGE_MASK));
				same_page = walk_int_range_sametx(sl_head, tx, sametx_hit, start_page, end_page);
			}
		}

		ret = walk_int_range_abort(mapping, NULL,
								   sl_head, first_hit, start, end, mode, tx);
		if (ret == -1)
			goto restart;
		else if (ret > 0) {
			//range intersection found!
			isect_flag = 1;

			if (first_hit->start > start)
				first_hit->start = start;
			
			if (first_hit->end < end)
				first_hit->end = end;
			
			if (mapped)
				first_hit->mapped = mapped;
			
			merge_colliding_ranges(NULL, sl_head, first_hit);
		}
	}
	

	if (isect_flag == 0) {
		//intersection not found!
		struct range_lock *new_entry = alloc_range_lock();
		new_entry->start = start;
		new_entry->end   = end;
		new_entry->tx    = tx;
		new_entry->mode  = mode;
		new_entry->file  = file;
		new_entry->mapped = mapped;
		if (mode == ACCESS_R) {
			struct list_head *start_ins_loc;
			struct skiplist_head *end_ins_loc;
			if (r_hit == NULL) {
				end_ins_loc = &mapping->range_locks_r_end;
				start_ins_loc = search_for_first_st(
					start, &mapping->range_locks_r_st);
			} else {
				end_ins_loc = &r_hit->list_end;
				start_ins_loc = search_from_st(
					&r_hit->list_st,start,
					&mapping->range_locks_r_st);
			}
			insert_range_lock_uninit_r(new_entry, start_ins_loc,
						   &mapping->range_locks_r_end,
						   end_ins_loc);
		} else {
			struct skiplist_head *rwlist;
			if (rw_hit == NULL)
				rwlist = &mapping->range_locks_rw;
			else 
				rwlist = &rw_hit->list_end;

			insert_range_lock_uninit_rw(new_entry,
						    &mapping->range_locks_rw,
						    rwlist);
		}
	}

	return !same_page;
}

/* DEP 1/31/09: For now, we are going to ruthlessly abort transactions
 * with no fairness, since we don't expect a lot of asymmetric write
 * conflicts.  This may need revision down the line.
 */
static void check_asymmetric_page_conflicts(struct address_space *mapping, 
					    struct page *page, 
					    enum access_mode mode){
	
	loff_t start = page->index << PAGE_CACHE_SHIFT;
	loff_t end   = start + PAGE_CACHE_SIZE;
	struct range_lock *first_hit;
	int ret;
	
	first_hit = search_for_nearest_pt(start+1, end-1, 
					  &mapping->range_locks_rw);
	if (first_hit != NULL) {
		ret = walk_int_range_nofair(NULL, &mapping->range_locks_rw, 
					    first_hit, start+1, end-1, mode);
		KSTM_BUG_ON(ret != 0);
	}

	if (mode == ACCESS_RW) {
		first_hit = search_for_nearest_pt(start+1, end-1,
						  &mapping->range_locks_r_end);
		if (first_hit != NULL) {
			ret = walk_int_range_nofair(&mapping->range_locks_r_st, 
						    &mapping->range_locks_r_end,
						    first_hit, start+1, end-1, 
						    mode);
			KSTM_BUG_ON(ret != 0);
		}
	}

	if(mode == ACCESS_RW)
		ClearPageSpec(page);
}

/**
 * do_generic_mapping_read - generic file read routine
 * @mapping:	address_space to be read
 * @_ra:	file's readahead state
 * @filp:	the file to read
 * @ppos:	current file position
 * @desc:	read_descriptor
 * @actor:	read method
 *
 * This is a generic file read routine, and uses the
 * mapping->a_ops->readpage() function for the actual low-level stuff.
 *
 * This is really ugly. But the goto's actually try to clarify some
 * of the logic when it comes to error handling etc.
 *
 * Note the struct file* is only passed for the use of readpage.
 * It may be NULL.
 */
void do_generic_mapping_read(struct address_space *mapping,
			     struct file_ra_state *_ra,
			     struct file *filp,
			     loff_t *ppos,
			     read_descriptor_t *desc,
			     read_actor_t actor)
{
	struct _inode *inode = tx_cache_get_inode_ro(mapping->host);
	unsigned long index;
	unsigned long end_index;
	unsigned long offset;
	unsigned long last_index;
	unsigned long next_index;
	unsigned long prev_index;
	unsigned int prev_offset;
	loff_t isize;
	struct page *cached_page;
	int error;
	struct file_ra_state ra = *_ra;
	int free_page = 1;

	cached_page = NULL;
	index = *ppos >> PAGE_CACHE_SHIFT;
	next_index = index;
	prev_index = ra.prev_index;
	prev_offset = ra.prev_offset;
	last_index = (*ppos + desc->count + PAGE_CACHE_SIZE-1) >> PAGE_CACHE_SHIFT;
	offset = *ppos & ~PAGE_CACHE_MASK;

	isize = i_size_read(inode);
	if (!isize)
		goto out;

	if(live_transaction()){
		mutex_lock(&mapping->host->i_mutex);
		allocate_range_lock(mapping, filp, *ppos, desc->count, ACCESS_R, 0);
		mutex_unlock(&mapping->host->i_mutex);
	}

	end_index = (isize - 1) >> PAGE_CACHE_SHIFT;
	for (;;) {
		struct page *page;
		unsigned long nr, ret;

		/* nr is the maximum number of bytes to copy from this page */
		nr = PAGE_CACHE_SIZE;
		if (index >= end_index) {
			if (index > end_index)
				goto out;
			nr = ((isize - 1) & ~PAGE_CACHE_MASK) + 1;
			if (nr <= offset) {
				goto out;
			}
		}
		nr = nr - offset;

		cond_resched();
		if (index == next_index)
			next_index = page_cache_readahead(mapping, &ra, filp,
					index, last_index - index);

find_page:
		/* Service pages from the shadow tree first */
		if(unlikely(live_transaction())){
			read_lock_irq(&mapping->tree_lock);
			page = radix_tree_lookup(&mapping->shadow_tree, index);
			read_unlock_irq(&mapping->tree_lock);
			if(page){
				free_page = 0; /* Hack-zilla to avoid a ref counting issue */
				goto page_ok;
			}
		}

		page = find_get_page(mapping, index);
		if (unlikely(page == NULL)) {
			handle_ra_miss(mapping, &ra, index);
			goto no_cached_page;
		}

		if (!PageUptodate(page))
			goto page_not_up_to_date;
page_ok:

		/* If users can be writing to this page using arbitrary
		 * virtual addresses, take care about potential aliasing
		 * before reading the page on the kernel side.
		 */
		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		/*
		 * When a sequential read accesses a page several times,
		 * only mark it as accessed the first time.
		 */
		if (prev_index != index || offset != prev_offset)
			mark_page_accessed(page);
		prev_index = index;

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
		prev_offset = offset;
		ra.prev_offset = offset;
		
		if(free_page)
			page_cache_release(page);
		if (ret == nr && desc->count)
			continue;
		goto out;

page_not_up_to_date:
		/* Get exclusive access to the page ... */
		lock_page(page);

		/* Did it get truncated before we got the lock? */
		if (!page->mapping) {
			unlock_page(page);
			page_cache_release(page);
			continue;
		}

		/* Did somebody else fill it already? */
		if (PageUptodate(page)) {
			unlock_page(page);
			goto page_ok;
		}

readpage:
		/* Start the actual read. The read will unlock the page. */
		error = mapping->a_ops->readpage(filp, page);

		if (unlikely(error)) {
			if (error == AOP_TRUNCATED_PAGE) {
				page_cache_release(page);
				goto find_page;
			}
			goto readpage_error;
		}

		if (!PageUptodate(page)) {
			lock_page(page);
			if (!PageUptodate(page)) {
				if (page->mapping == NULL) {
					/*
					 * invalidate_inode_pages got it
					 */
					unlock_page(page);
					page_cache_release(page);
					goto find_page;
				}
				unlock_page(page);
				error = -EIO;
				shrink_readahead_size_eio(filp, &ra);
				goto readpage_error;
			}
			unlock_page(page);
		}

		/*
		 * i_size must be checked after we have done ->readpage.
		 *
		 * Checking i_size after the readpage allows us to calculate
		 * the correct value for "nr", which means the zero-filled
		 * part of the page is not copied back to userspace (unless
		 * another truncate extends the file - this is desired though).
		 */
		isize = i_size_read(inode);
		end_index = (isize - 1) >> PAGE_CACHE_SHIFT;
		if (unlikely(!isize || index > end_index)) {
			page_cache_release(page);
			goto out;
		}

		/* nr is the maximum number of bytes to copy from this page */
		nr = PAGE_CACHE_SIZE;
		if (index == end_index) {
			nr = ((isize - 1) & ~PAGE_CACHE_MASK) + 1;
			if (nr <= offset) {
				page_cache_release(page);
				goto out;
			}
		}
		nr = nr - offset;
		goto page_ok;

readpage_error:
		/* UHHUH! A synchronous read error occurred. Report it */
		desc->error = error;
		page_cache_release(page);
		goto out;

no_cached_page:
		/*
		 * Ok, it wasn't cached, so we need to create a new
		 * page..
		 */
		if (!cached_page) {
			cached_page = page_cache_alloc_cold(mapping);
			if (!cached_page) {
				desc->error = -ENOMEM;
				goto out;
			}
		}
		error = add_to_page_cache_lru(cached_page, mapping,
						index, GFP_KERNEL);
		if (error) {
			if (error == -EEXIST)
				goto find_page;
			desc->error = error;
			goto out;
		}
		page = cached_page;
		cached_page = NULL;
		goto readpage;
	}

out:
	*_ra = ra;

	*ppos = ((loff_t) index << PAGE_CACHE_SHIFT) + offset;
	if (cached_page)
		page_cache_release(cached_page);
	if (filp)
		file_accessed(tx_cache_get_file_ro(filp));
}
EXPORT_SYMBOL(do_generic_mapping_read);

int file_read_actor(read_descriptor_t *desc, struct page *page,
			unsigned long offset, unsigned long size)
{
	char *kaddr;
	unsigned long left, count = desc->count;

	if (size > count)
		size = count;

	/*
	 * Faults on the destination of a read are common, so do it before
	 * taking the kmap.
	 */
	if (!fault_in_pages_writeable(desc->arg.buf, size)) {
		kaddr = kmap_atomic(page, KM_USER0);
		left = __copy_to_user_inatomic(desc->arg.buf,
						kaddr + offset, size);
		kunmap_atomic(kaddr, KM_USER0);
		if (left == 0)
			goto success;
	}

	/* Do it the slow way */
	kaddr = kmap(page);
	left = __copy_to_user(desc->arg.buf, kaddr + offset, size);
	kunmap(page);

	if (left) {
		size -= left;
		desc->error = -EFAULT;
	}
success:
	desc->count = count - size;
	desc->written += size;
	desc->arg.buf += size;
	return size;
}

/*
 * Performs necessary checks before doing a write
 * @iov:	io vector request
 * @nr_segs:	number of segments in the iovec
 * @count:	number of bytes to write
 * @access_flags: type of access: %VERIFY_READ or %VERIFY_WRITE
 *
 * Adjust number of segments and amount of bytes to write (nr_segs should be
 * properly initialized first). Returns appropriate error code that caller
 * should return or zero in case that write should be allowed.
 */
int generic_segment_checks(const struct iovec *iov,
			unsigned long *nr_segs, size_t *count, int access_flags)
{
	unsigned long   seg;
	size_t cnt = 0;
	for (seg = 0; seg < *nr_segs; seg++) {
		const struct iovec *iv = &iov[seg];

		/*
		 * If any segment has a negative length, or the cumulative
		 * length ever wraps negative then return -EINVAL.
		 */
		cnt += iv->iov_len;
		if (unlikely((ssize_t)(cnt|iv->iov_len) < 0))
			return -EINVAL;
		if (access_ok(access_flags, iv->iov_base, iv->iov_len))
			continue;
		if (seg == 0)
			return -EFAULT;
		*nr_segs = seg;
		cnt -= iv->iov_len;	/* This segment is no good */
		break;
	}
	*count = cnt;
	return 0;
}
EXPORT_SYMBOL(generic_segment_checks);

/**
 * generic_file_aio_read - generic filesystem read routine
 * @iocb:	kernel I/O control block
 * @iov:	io vector request
 * @nr_segs:	number of segments in the iovec
 * @pos:	current file position
 *
 * This is the "read()" routine for all filesystems
 * that can use the page cache directly.
 */
ssize_t
generic_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos)
{
	struct file *filp = iocb->ki_filp;
	struct _file *_filp = tx_cache_get_file(filp);
	ssize_t retval;
	unsigned long seg;
	size_t count;
	loff_t *ppos = &iocb->ki_pos;

	count = 0;
	retval = generic_segment_checks(iov, &nr_segs, &count, VERIFY_WRITE);
	if (retval)
		return retval;

	/* coalesce the iovecs and go direct-to-BIO for O_DIRECT */
	if (_filp->f_flags & O_DIRECT) {
		loff_t size;
		struct address_space *mapping;
		struct _inode *inode;

		mapping = filp->f_mapping;
		inode = tx_cache_get_inode_ro(mapping->host);
		retval = 0;
		if (!count)
			goto out; /* skip atime */
		size = i_size_read(inode);
		if (pos < size) {
			retval = generic_file_direct_IO(READ, iocb,
						iov, pos, nr_segs);
			if (retval > 0)
				*ppos = pos + retval;
		}
		if (likely(retval != 0)) {
			file_accessed(_filp);
			goto out;
		}
	}

	retval = 0;
	if (count) {
		for (seg = 0; seg < nr_segs; seg++) {
			read_descriptor_t desc;

			desc.written = 0;
			desc.arg.buf = iov[seg].iov_base;
			desc.count = iov[seg].iov_len;
			if (desc.count == 0)
				continue;
			desc.error = 0;
			do_generic_file_read(filp,ppos,&desc,file_read_actor);
			retval += desc.written;
			if (desc.error) {
				retval = retval ?: desc.error;
				break;
			}
		}
	}
out:
	return retval;
}
EXPORT_SYMBOL(generic_file_aio_read);

int file_send_actor(read_descriptor_t * desc, struct page *page, unsigned long offset, unsigned long size)
{
	ssize_t written;
	unsigned long count = desc->count;
	struct file *file = desc->arg.data;

	if (size > count)
		size = count;

	written = file->f_op->sendpage(file, page, offset,
				       size, &tx_cache_get_file_ro(file)->f_pos, size<count);
	if (written < 0) {
		desc->error = written;
		written = 0;
	}
	desc->count = count - written;
	desc->written += written;
	return written;
}

ssize_t generic_file_sendfile(struct file *in_file, loff_t *ppos,
			 size_t count, read_actor_t actor, void *target)
{
	read_descriptor_t desc;

	if (!count)
		return 0;

	desc.written = 0;
	desc.count = count;
	desc.arg.data = target;
	desc.error = 0;

	do_generic_file_read(in_file, ppos, &desc, actor);
	if (desc.written)
		return desc.written;
	return desc.error;
}
EXPORT_SYMBOL(generic_file_sendfile);

static ssize_t
do_readahead(struct address_space *mapping, struct file *filp,
	     unsigned long index, unsigned long nr)
{
	if (!mapping || !mapping->a_ops || !mapping->a_ops->readpage)
		return -EINVAL;

	force_page_cache_readahead(mapping, filp, index,
					max_sane_readahead(nr));
	return 0;
}

asmlinkage ssize_t sys_readahead(int fd, loff_t offset, size_t count)
{
	ssize_t ret;
	struct file *file;

	ret = -EBADF;
	file = fget(fd);
	if (file) {
		if (tx_cache_get_file_ro(file)->f_mode & FMODE_READ) {
			struct address_space *mapping = file->f_mapping;
			unsigned long start = offset >> PAGE_CACHE_SHIFT;
			unsigned long end = (offset + count - 1) >> PAGE_CACHE_SHIFT;
			unsigned long len = end - start + 1;
			ret = do_readahead(mapping, file, start, len);
		}
		fput(file);
	}
	return ret;
}

#ifdef CONFIG_MMU
static int FASTCALL(page_cache_read(struct file * file, unsigned long offset));
/**
 * page_cache_read - adds requested page to the page cache if not already there
 * @file:	file to read
 * @offset:	page index
 *
 * This adds the requested page to the page cache if it isn't already there,
 * and schedules an I/O to read in its contents from disk.
 */
static int fastcall page_cache_read(struct file * file, unsigned long offset)
{
	struct address_space *mapping = file->f_mapping;
	struct page *page; 
	int ret;

	do {
		page = page_cache_alloc_cold(mapping);
		if (!page)
			return -ENOMEM;

		ret = add_to_page_cache_lru(page, mapping, offset, GFP_KERNEL);
		if (ret == 0)
			ret = mapping->a_ops->readpage(file, page);
		else if (ret == -EEXIST)
			ret = 0; /* losing race to add is OK */

		page_cache_release(page);

	} while (ret == AOP_TRUNCATED_PAGE);
		
	return ret;
}

static struct page * shadow_tree_add(struct page * page, 
					    struct address_space *mapping, 
					    unsigned long index){
	int error;
	void *addr, *addr2;
	struct page *page2;

	/* Tag page as transactional*/
	SetPageSpec(page);
	/* Allocate a new page and put it in the shadow tree  */
	page2 = alloc_page(GFP_HIGHUSER);

	SetPageUptodate(page2);
				
	write_lock_irq(&mapping->tree_lock);
	error = radix_tree_insert(&mapping->shadow_tree, index, page2);
	if(!error) {
		SetPageLocked(page);
		page2->mapping = mapping;
		page2->index = index;
		mapping->nrpages++;
		__inc_zone_page_state(page2, NR_FILE_PAGES);
	}
	write_unlock_irq(&mapping->tree_lock);

	/* Copy in the contents.  This could
	 * be optimized to avoid the hole that
	 * will be written 
	 */
	addr = kmap(page);
	addr2 = kmap(page2);
	memcpy(addr2, addr, PAGE_SIZE);
	kunmap(page2);
	kunmap(page);
	unlock_page(page);

	return page2;
}

#define MMAP_LOTSAMISS  (100)

/**
 * filemap_nopage - read in file data for page fault handling
 * @area:	the applicable vm_area
 * @address:	target address to read in
 * @type:	returned with VM_FAULT_{MINOR,MAJOR} if not %NULL
 *
 * filemap_nopage() is invoked via the vma operations vector for a
 * mapped memory region to read in file data during a page fault.
 *
 * The goto's are kind of ugly, but this streamlines the normal case of having
 * it in the page cache, and handles the special cases reasonably without
 * having a lot of duplicated code.
 */
struct page *filemap_nopage(struct vm_area_struct *area,
				unsigned long address, int *type)
{
	int error;
	struct file *file = area->vm_file;
	struct address_space *mapping = file->f_mapping;
	struct file_ra_state *ra = &file->f_ra;
	struct inode *inode = mapping->host;
	struct page *page;
	unsigned long i_size, size, pgoff;
	int did_readaround = 0, majmin = VM_FAULT_MINOR;
	enum access_mode mode = (area->vm_flags & VM_WRITE) ? ACCESS_RW : ACCESS_R;
	int need_checkpoint = 0;

	pgoff = ((address-area->vm_start) >> PAGE_CACHE_SHIFT) + area->vm_pgoff;

retry_all:
	i_size = i_size_read_pf(inode);
	size = (i_size + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	if (pgoff >= size)
		goto outside_data_content;

	/* If we don't want any read-ahead, don't bother */
	if (VM_RandomReadHint(area))
		goto no_cached_page;

	/*
	 * The readahead code wants to be told about each and every page
	 * so it can build and shrink its windows appropriately
	 *
	 * For sequential accesses, we use the generic readahead logic.
	 */
	if (VM_SequentialReadHint(area))
		page_cache_readahead(mapping, ra, file, pgoff, 1);

	/*
	 * Do we have something in the page cache already?
	 */
retry_find:
	/* For starters, let's just get the page out of the
	 * shadow tree if it exists.  This needs more, like
	 * contending for range locks, etc */
	if(unlikely(live_transaction())){
		read_lock_irq(&mapping->tree_lock);
		page = radix_tree_lookup(&mapping->shadow_tree, pgoff);
		if(page){
			page_cache_get(page);
			read_unlock_irq(&mapping->tree_lock);
		} else {
			read_unlock_irq(&mapping->tree_lock);
			if(mode == ACCESS_RW)
				need_checkpoint = 1;
			page = find_get_page(mapping, pgoff);
		}
	} else
		page = find_get_page(mapping, pgoff);
	if (!page) {
		unsigned long ra_pages;

		if (VM_SequentialReadHint(area)) {
			handle_ra_miss(mapping, ra, pgoff);
			goto no_cached_page;
		}
		ra->mmap_miss++;

		/*
		 * Do we miss much more than hit in this file? If so,
		 * stop bothering with read-ahead. It will only hurt.
		 */
		if (ra->mmap_miss > ra->mmap_hit + MMAP_LOTSAMISS)
			goto no_cached_page;

		/*
		 * To keep the pgmajfault counter straight, we need to
		 * check did_readaround, as this is an inner loop.
		 */
		if (!did_readaround) {
			majmin = VM_FAULT_MAJOR;
			count_vm_event(PGMAJFAULT);
		}
		did_readaround = 1;
		ra_pages = max_sane_readahead(file->f_ra.ra_pages);
		if (ra_pages) {
			pgoff_t start = 0;

			if (pgoff > ra_pages / 2)
				start = pgoff - ra_pages / 2;
			do_page_cache_readahead(mapping, file, start, ra_pages);
		}
		page = find_get_page(mapping, pgoff);
		if (!page)
			goto no_cached_page;
	}

	if (!did_readaround)
		ra->mmap_hit++;

	/*
	 * Ok, found a page in the page cache, now we need to check
	 * that it's up-to-date.
	 */
	if (!PageUptodate(page))
		goto page_not_uptodate;

success:
	/*
	 * Found the page and have a reference on it.
	 */
	mark_page_accessed(page);

	if(unlikely(live_transaction())){
		unsigned long pg_begin = pgoff * PAGE_SIZE;
		unsigned long pg_count =
			pg_begin + PAGE_SIZE > i_size ? i_size - pg_begin : PAGE_SIZE;
		tx_cache_get_inode_ro(mapping->host); //so we have the host inode in our ws
		mutex_lock(&mapping->host->i_mutex);
		allocate_range_lock(mapping, file, pg_begin, pg_count, mode, 1);
		mutex_unlock(&mapping->host->i_mutex);
		if(need_checkpoint){
			struct page *page2 = page;
			lock_page(page);
			page = shadow_tree_add(page, mapping, pgoff);
			page_cache_release(page2);
			page_cache_get(page);
		}
	}

	if (type)
		*type = majmin;
	return page;

outside_data_content:
	/*
	 * An external ptracer can access pages that normally aren't
	 * accessible..
	 */
	if (area->vm_mm == current->mm)
		return NOPAGE_SIGBUS;
	/* Fall through to the non-read-ahead case */
no_cached_page:
	/*
	 * We're only likely to ever get here if MADV_RANDOM is in
	 * effect.
	 */
	error = page_cache_read(file, pgoff);

	/*
	 * The page we want has now been added to the page cache.
	 * In the unlikely event that someone removed it in the
	 * meantime, we'll just come back here and read it again.
	 */
	if (error >= 0)
		goto retry_find;

	/*
	 * An error return from page_cache_read can result if the
	 * system is low on memory, or a problem occurs while trying
	 * to schedule I/O.
	 */
	if (error == -ENOMEM)
		return NOPAGE_OOM;
	return NOPAGE_SIGBUS;

page_not_uptodate:
	if (!did_readaround) {
		majmin = VM_FAULT_MAJOR;
		count_vm_event(PGMAJFAULT);
	}

	/*
	 * Umm, take care of errors if the page isn't up-to-date.
	 * Try to re-read it _once_. We do this synchronously,
	 * because there really aren't any performance issues here
	 * and we need to check for errors.
	 */
	lock_page(page);

	/* Somebody truncated the page on us? */
	if (!page->mapping) {
		unlock_page(page);
		page_cache_release(page);
		goto retry_all;
	}

	/* Somebody else successfully read it in? */
	if (PageUptodate(page)) {
		unlock_page(page);
		goto success;
	}
	ClearPageError(page);
	error = mapping->a_ops->readpage(file, page);
	if (!error) {
		wait_on_page_locked(page);
		if (PageUptodate(page))
			goto success;
	} else if (error == AOP_TRUNCATED_PAGE) {
		page_cache_release(page);
		goto retry_find;
	}

	/*
	 * Things didn't work out. Return zero to tell the
	 * mm layer so, possibly freeing the page cache page first.
	 */
	shrink_readahead_size_eio(file, ra);
	page_cache_release(page);
	return NOPAGE_SIGBUS;
}
EXPORT_SYMBOL(filemap_nopage);

static struct page * filemap_getpage(struct file *file, unsigned long pgoff,
					int nonblock)
{
	struct address_space *mapping = file->f_mapping;
	struct page *page;
	int error;

	/*
	 * Do we have something in the page cache already?
	 */
retry_find:
	if(unlikely(live_transaction())){
		read_lock_irq(&mapping->tree_lock);
		page = radix_tree_lookup(&mapping->shadow_tree, pgoff);
		read_unlock_irq(&mapping->tree_lock);
		if(page){
			printk(KERN_ERR "Missed opportunity to pull something out of shadow tree\n");
			OSA_MAGIC(OSA_BREAKSIM);
		}
	}

	page = find_get_page(mapping, pgoff);
	if (!page) {
		if (nonblock)
			return NULL;
		goto no_cached_page;
	}

	/*
	 * Ok, found a page in the page cache, now we need to check
	 * that it's up-to-date.
	 */
	if (!PageUptodate(page)) {
		if (nonblock) {
			page_cache_release(page);
			return NULL;
		}
		goto page_not_uptodate;
	}

success:
	/*
	 * Found the page and have a reference on it.
	 */
	mark_page_accessed(page);
	return page;

no_cached_page:
	error = page_cache_read(file, pgoff);

	/*
	 * The page we want has now been added to the page cache.
	 * In the unlikely event that someone removed it in the
	 * meantime, we'll just come back here and read it again.
	 */
	if (error >= 0)
		goto retry_find;

	/*
	 * An error return from page_cache_read can result if the
	 * system is low on memory, or a problem occurs while trying
	 * to schedule I/O.
	 */
	return NULL;

page_not_uptodate:
	lock_page(page);

	/* Did it get truncated while we waited for it? */
	if (!page->mapping) {
		unlock_page(page);
		goto err;
	}

	/* Did somebody else get it up-to-date? */
	if (PageUptodate(page)) {
		unlock_page(page);
		goto success;
	}

	error = mapping->a_ops->readpage(file, page);
	if (!error) {
		wait_on_page_locked(page);
		if (PageUptodate(page))
			goto success;
	} else if (error == AOP_TRUNCATED_PAGE) {
		page_cache_release(page);
		goto retry_find;
	}

	/*
	 * Umm, take care of errors if the page isn't up-to-date.
	 * Try to re-read it _once_. We do this synchronously,
	 * because there really aren't any performance issues here
	 * and we need to check for errors.
	 */
	lock_page(page);

	/* Somebody truncated the page on us? */
	if (!page->mapping) {
		unlock_page(page);
		goto err;
	}
	/* Somebody else successfully read it in? */
	if (PageUptodate(page)) {
		unlock_page(page);
		goto success;
	}

	ClearPageError(page);
	error = mapping->a_ops->readpage(file, page);
	if (!error) {
		wait_on_page_locked(page);
		if (PageUptodate(page))
			goto success;
	} else if (error == AOP_TRUNCATED_PAGE) {
		page_cache_release(page);
		goto retry_find;
	}

	/*
	 * Things didn't work out. Return zero to tell the
	 * mm layer so, possibly freeing the page cache page first.
	 */
err:
	page_cache_release(page);

	return NULL;
}

int filemap_populate(struct vm_area_struct *vma, unsigned long addr,
		unsigned long len, pgprot_t prot, unsigned long pgoff,
		int nonblock)
{
	struct file *file = vma->vm_file;
	struct address_space *mapping = file->f_mapping;
	struct _inode *inode = tx_cache_get_inode_ro(mapping->host);
	unsigned long size;
	struct mm_struct *mm = vma->vm_mm;
	struct page *page;
	int err;

	if (!nonblock)
		force_page_cache_readahead(mapping, vma->vm_file,
					pgoff, len >> PAGE_CACHE_SHIFT);

repeat:
	size = (i_size_read(inode) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	if (pgoff + (len >> PAGE_CACHE_SHIFT) > size)
		return -EINVAL;

	page = filemap_getpage(file, pgoff, nonblock);

	/* XXX: This is wrong, a filesystem I/O error may have happened. Fix that as
	 * done in shmem_populate calling shmem_getpage */
	if (!page && !nonblock)
		return -ENOMEM;

	if (page) {
		err = install_page(mm, vma, addr, page, prot);
		if (err) {
			page_cache_release(page);
			return err;
		}
	} else if (vma->vm_flags & VM_NONLINEAR) {
		/* No page was found just because we can't read it in now (being
		 * here implies nonblock != 0), but the page may exist, so set
		 * the PTE to fault it in later. */
		err = install_file_pte(mm, vma, addr, pgoff, prot);
		if (err)
			return err;
	}

	len -= PAGE_SIZE;
	addr += PAGE_SIZE;
	pgoff++;
	if (len)
		goto repeat;

	return 0;
}
EXPORT_SYMBOL(filemap_populate);

struct vm_operations_struct generic_file_vm_ops = {
	.nopage		= filemap_nopage,
	.populate	= filemap_populate,
};

/* This is used for a general mmap of a disk file */

int generic_file_mmap(struct file * file, struct vm_area_struct * vma)
{
	struct address_space *mapping = file->f_mapping;

	if (!mapping->a_ops->readpage)
		return -ENOEXEC;
	file_accessed(tx_cache_get_file_ro(file));
	vma->vm_ops = &generic_file_vm_ops;

	return 0;
}

/*
 * This is for filesystems which do not implement ->writepage.
 */
int generic_file_readonly_mmap(struct file *file, struct vm_area_struct *vma)
{
	if ((vma->vm_flags & VM_SHARED) && (vma->vm_flags & VM_MAYWRITE))
		return -EINVAL;
	return generic_file_mmap(file, vma);
}
#else
int generic_file_mmap(struct file * file, struct vm_area_struct * vma)
{
	return -ENOSYS;
}
int generic_file_readonly_mmap(struct file * file, struct vm_area_struct * vma)
{
	return -ENOSYS;
}
#endif /* CONFIG_MMU */

EXPORT_SYMBOL(generic_file_mmap);
EXPORT_SYMBOL(generic_file_readonly_mmap);

static struct page *__read_cache_page(struct address_space *mapping,
				unsigned long index,
				int (*filler)(void *,struct page*),
				void *data)
{
	struct page *page, *cached_page = NULL;
	int err;
repeat:
	if(unlikely(live_transaction())){
		read_lock_irq(&mapping->tree_lock);
		page = radix_tree_lookup(&mapping->shadow_tree, index);
		read_unlock_irq(&mapping->tree_lock);
		if(page){
			printk(KERN_ERR "Missed opportunity to pull something out of shadow tree\n");
			OSA_MAGIC(OSA_BREAKSIM);
		}
	}
	page = find_get_page(mapping, index);
	if (!page) {
		if (!cached_page) {
			cached_page = page_cache_alloc_cold(mapping);
			if (!cached_page)
				return ERR_PTR(-ENOMEM);
		}
		err = add_to_page_cache_lru(cached_page, mapping,
					index, GFP_KERNEL);
		if (err == -EEXIST)
			goto repeat;
		if (err < 0) {
			/* Presumably ENOMEM for radix tree node */
			page_cache_release(cached_page);
			return ERR_PTR(err);
		}
		page = cached_page;
		cached_page = NULL;
		err = filler(data, page);
		if (err < 0) {
			page_cache_release(page);
			page = ERR_PTR(err);
		}
	}
	if (cached_page)
		page_cache_release(cached_page);
	return page;
}

/*
 * Same as read_cache_page, but don't wait for page to become unlocked
 * after submitting it to the filler.
 */
struct page *read_cache_page_async(struct address_space *mapping,
				unsigned long index,
				int (*filler)(void *,struct page*),
				void *data)
{
	struct page *page;
	int err;

retry:
	page = __read_cache_page(mapping, index, filler, data);
	if (IS_ERR(page))
		return page;
	if (PageUptodate(page))
		goto out;

	lock_page(page);
	if (!page->mapping) {
		unlock_page(page);
		page_cache_release(page);
		goto retry;
	}
	if (PageUptodate(page)) {
		unlock_page(page);
		goto out;
	}
	err = filler(data, page);
	if (err < 0) {
		page_cache_release(page);
		return ERR_PTR(err);
	}
out:
	mark_page_accessed(page);
	return page;
}
EXPORT_SYMBOL(read_cache_page_async);

/**
 * read_cache_page - read into page cache, fill it if needed
 * @mapping:	the page's address_space
 * @index:	the page index
 * @filler:	function to perform the read
 * @data:	destination for read data
 *
 * Read into the page cache. If a page already exists, and PageUptodate() is
 * not set, try to fill the page then wait for it to become unlocked.
 *
 * If the page does not get brought uptodate, return -EIO.
 */
struct page *read_cache_page(struct address_space *mapping,
				unsigned long index,
				int (*filler)(void *,struct page*),
				void *data)
{
	struct page *page;

	page = read_cache_page_async(mapping, index, filler, data);
	if (IS_ERR(page))
		goto out;
	wait_on_page_locked(page);
	if (!PageUptodate(page)) {
		page_cache_release(page);
		page = ERR_PTR(-EIO);
	}
 out:
	return page;
}
EXPORT_SYMBOL(read_cache_page);

/*
 * If the page was newly created, increment its refcount and add it to the
 * caller's lru-buffering pagevec.  This function is specifically for
 * generic_file_write().
 */
static inline struct page *
__grab_cache_page(struct address_space *mapping, unsigned long index,
			struct page **cached_page, struct pagevec *lru_pvec)
{
	int err;
	struct page *page;
repeat:
	page = find_lock_page(mapping, index);
	if (!page) {
		if (!*cached_page) {
			*cached_page = page_cache_alloc(mapping);
			if (!*cached_page)
				return NULL;
		}
		err = add_to_page_cache(*cached_page, mapping,
					index, GFP_KERNEL);
		if (err == -EEXIST)
			goto repeat;
		if (err == 0) {
			page = *cached_page;
			page_cache_get(page);
			if (!pagevec_add(lru_pvec, page))
				__pagevec_lru_add(lru_pvec);
			*cached_page = NULL;
		}
	}
	return page;
}

/*
 * The logic we want is
 *
 *	if suid or (sgid and xgrp)
 *		remove privs
 */
int should_remove_suid(const struct _dentry *dentry)
{
	mode_t mode = d_get_inode_ro(dentry)->i_mode;
	int kill = 0;

	/* suid always must be killed */
	if (unlikely(mode & S_ISUID))
		kill = ATTR_KILL_SUID;

	/*
	 * sgid without any exec bits is just a mandatory locking mark; leave
	 * it alone.  If some exec bits are set, it's a real sgid; kill it.
	 */
	if (unlikely((mode & S_ISGID) && (mode & S_IXGRP)))
		kill |= ATTR_KILL_SGID;

	if (unlikely(kill && !capable(CAP_FSETID)))
		return kill;

	return 0;
}
EXPORT_SYMBOL(should_remove_suid);

int __remove_suid(const struct _dentry *dentry, int kill)
{
	struct iattr newattrs;

	newattrs.ia_valid = ATTR_FORCE | kill;
	return notify_change(dentry, &newattrs);
}

int remove_suid(const struct _dentry *dentry)
{
	int kill = should_remove_suid(dentry);

	if (unlikely(kill))
		return __remove_suid(dentry, kill);

	return 0;
}
EXPORT_SYMBOL(remove_suid);

size_t
__filemap_copy_from_user_iovec_inatomic(char *vaddr,
			const struct iovec *iov, size_t base, size_t bytes)
{
	size_t copied = 0, left = 0;

	while (bytes) {
		char __user *buf = iov->iov_base + base;
		int copy = min(bytes, iov->iov_len - base);

		base = 0;
		left = __copy_from_user_inatomic_nocache(vaddr, buf, copy);
		copied += copy;
		bytes -= copy;
		vaddr += copy;
		iov++;

		if (unlikely(left))
			break;
	}
	return copied - left;
}

/*
 * Performs necessary checks before doing a write
 *
 * Can adjust writing position or amount of bytes to write.
 * Returns appropriate error code that caller should return or
 * zero in case that write should be allowed.
 */
inline int generic_write_checks(struct _file *file, loff_t *pos, size_t *count, int isblk)
{
	struct inode *inode = parent(file)->f_mapping->host;
	struct _inode *_inode = tx_cache_get_inode_ro(inode);
	unsigned long limit = current->signal->rlim[RLIMIT_FSIZE].rlim_cur;

        if (unlikely(*pos < 0))
                return -EINVAL;

	if (!isblk) {
		/* FIXME: this is for backwards compatibility with 2.4 */
		if (file->f_flags & O_APPEND)
                        *pos = i_size_read(_inode);

		if (limit != RLIM_INFINITY) {
			if (*pos >= limit) {
				send_sig(SIGXFSZ, current, 0);
				return -EFBIG;
			}
			if (*count > limit - (typeof(limit))*pos) {
				*count = limit - (typeof(limit))*pos;
			}
		}
	}

	/*
	 * LFS rule
	 */
	if (unlikely(*pos + *count > MAX_NON_LFS &&
				!(file->f_flags & O_LARGEFILE))) {
		if (*pos >= MAX_NON_LFS) {
			send_sig(SIGXFSZ, current, 0);
			return -EFBIG;
		}
		if (*count > MAX_NON_LFS - (unsigned long)*pos) {
			*count = MAX_NON_LFS - (unsigned long)*pos;
		}
	}

	/*
	 * Are we about to exceed the fs block limit ?
	 *
	 * If we have written data it becomes a short write.  If we have
	 * exceeded without writing data we send a signal and return EFBIG.
	 * Linus frestrict idea will clean these up nicely..
	 */
	if (likely(!isblk)) {
		if (unlikely(*pos >= _inode->i_sb->s_maxbytes)) {
			if (*count || *pos > _inode->i_sb->s_maxbytes) {
				send_sig(SIGXFSZ, current, 0);
				return -EFBIG;
			}
			/* zero-length writes at ->s_maxbytes are OK */
		}

		if (unlikely(*pos + *count > _inode->i_sb->s_maxbytes))
			*count = _inode->i_sb->s_maxbytes - *pos;
	} else {
#ifdef CONFIG_BLOCK
		loff_t isize;
		if (bdev_read_only(I_BDEV(inode)))
			return -EPERM;
		isize = i_size_read(_inode);
		if (*pos >= isize) {
			if (*count || *pos > isize)
				return -ENOSPC;
		}

		if (*pos + *count > isize)
			*count = isize - *pos;
#else
		return -EPERM;
#endif
	}
	return 0;
}
EXPORT_SYMBOL(generic_write_checks);

ssize_t
generic_file_direct_write(struct kiocb *iocb, const struct iovec *iov,
		unsigned long *nr_segs, loff_t pos, loff_t *ppos,
		size_t count, size_t ocount)
{
	struct file	*file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode	*inode = mapping->host;
	struct _inode	*_inode = tx_cache_get_inode_ro(inode);
	ssize_t		written;

	if (count != ocount)
		*nr_segs = iov_shorten((struct iovec *)iov, *nr_segs, count);

	written = generic_file_direct_IO(WRITE, iocb, iov, pos, *nr_segs);
	if (written > 0) {
		loff_t end = pos + written;
		if (end > i_size_read(_inode) && !S_ISBLK(_inode->i_mode)) {
			if(live_transaction()){
				printk(KERN_ERR "XXX\n");
				OSA_MAGIC(OSA_BREAKSIM);
			}
			_inode = tx_cache_get_inode(inode);
			i_size_write(_inode,  end);
			mark_inode_dirty(inode);
		}
		*ppos = end;
	}

	/*
	 * Sync the fs metadata but not the minor inode changes and
	 * of course not the data as we did direct DMA for the IO.
	 * i_mutex is held, which protects generic_osync_inode() from
	 * livelocking.  AIO O_DIRECT ops attempt to sync metadata here.
	 */
	if ((written >= 0 || written == -EIOCBQUEUED) &&
	    ((tx_cache_get_file_ro(file)->f_flags & O_SYNC) || IS_SYNC(_inode))) {
		int err = generic_osync_inode(inode, mapping, OSYNC_METADATA);
		if (err < 0)
			written = err;
	}
	return written;
}
EXPORT_SYMBOL(generic_file_direct_write);

ssize_t
generic_file_buffered_write(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos, loff_t *ppos,
		size_t count, ssize_t written)
{
	struct file *file = iocb->ki_filp;
	struct address_space * mapping = file->f_mapping;
	const struct address_space_operations *a_ops = mapping->a_ops;
	struct inode 	*inode = mapping->host;
	long		status = 0;
	struct page	*page;
	struct page	*cached_page = NULL;
	size_t		bytes;
	struct pagevec	lru_pvec;
	const struct iovec *cur_iov = iov; /* current iovec */
	size_t		iov_base = 0;	   /* offset in the current iovec */
	char __user	*buf=NULL;

	pagevec_init(&lru_pvec, 0);

	/*
	 * handle partial DIO write.  Adjust cur_iov if needed.
	 */

	if (likely(nr_segs == 1))
		buf = iov->iov_base + written;
	else {
		filemap_set_next_iovec(&cur_iov, &iov_base, written);
		buf = cur_iov->iov_base + iov_base;
	}
	
	do {
		unsigned long index;
		unsigned long offset;
		size_t copied=0;

		offset = (pos & (PAGE_CACHE_SIZE -1)); /* Within page */
		index = pos >> PAGE_CACHE_SHIFT;
		bytes = PAGE_CACHE_SIZE - offset;

		/* Limit the size of the copy to the caller's write size */
		bytes = min(bytes, count);

		/* We only need to worry about prefaulting when writes are from
		 * user-space.  NFSd uses vfs_writev with several non-aligned
		 * segments in the vector, and limiting to one segment a time is
		 * a noticeable performance for re-write
		 */
		if (!segment_eq(get_fs(), KERNEL_DS)) {
			/*
			 * Limit the size of the copy to that of the current
			 * segment, because fault_in_pages_readable() doesn't
			 * know how to walk segments.
			 */
			bytes = min(bytes, cur_iov->iov_len - iov_base);

			/*
			 * Bring in the user page that we will copy from
			 * _first_.  Otherwise there's a nasty deadlock on
			 * copying from the same page as we're writing to,
			 * without it being marked up-to-date.
			 */
			fault_in_pages_readable(buf, bytes);
		}
		page = __grab_cache_page(mapping,index,&cached_page,&lru_pvec);
		if (!page) {
			status = -ENOMEM;
			break;
		}

		if (unlikely(bytes == 0)) {
			status = 0;
			copied = 0;
			goto zero_length_segment;
		}

		/* If we are in a tx:
		 *  1) Allocate a range lock
		 *  2) tag the page as transactional
		 *  3) Get a shadow page, add to the shadow_tree
		 *  4) Do the copy
		 * 
		 * If we are not in a tx, be sure to check the tx bit
		 *  -if the tx bit is set do asymmetric conflict detection
		 */

		if(live_transaction()){
			struct page *page2 = NULL;
			int need_prepare = 0;
			/* Allocate a range lock if we are in a transaction.
			 */
			// We are already holding i_mutex lock here
			need_prepare = allocate_range_lock(mapping, file, pos, bytes, ACCESS_RW, 0);

			/* XXX: How to deal with exceeding isize? */
			if(PageSpec(page)){
				read_lock_irq(&mapping->tree_lock);
				page2 = radix_tree_lookup(&mapping->shadow_tree, index);
				read_unlock_irq(&mapping->tree_lock);
			}

			if(page2)
				unlock_page(page);
			else
				page2 = shadow_tree_add(page, mapping, index);

			KSTM_BUG_ON((pos & PAGE_MASK) != ((pos+bytes-1) & PAGE_MASK));

			/* The filesystem may need to do some bookeeping when we
			 * are dirtying a page in the transaction: e.g. ext3 has
			 * to keep track of the number of blocks to journal */
			if(need_prepare && a_ops->prepare_tx_write)
				a_ops->prepare_tx_write(file, page, offset, offset+bytes);
			
			page_cache_release(page);
			page = page2;

			if (likely(nr_segs == 1))
				copied = filemap_copy_from_user(page, offset,
								buf, bytes);
			else
				copied = filemap_copy_from_user_iovec(page, offset,
								      cur_iov, iov_base, bytes);
			
			{
				struct _inode *_inode = tx_cache_get_inode_ro(inode);
				loff_t isize = i_size_read(_inode);
				if(pos + copied > isize){
					_inode = tx_cache_get_inode(inode);
					i_size_write(_inode, pos + copied);
					mark_inode_dirty(inode);
				}
			}

			status = copied;
			written += copied;
			count -= copied;
			pos += copied;
			buf += copied;
			if (unlikely(nr_segs > 1)) {
				filemap_set_next_iovec(&cur_iov,
						       &iov_base, status);
				if (count)
					buf = cur_iov->iov_base +
						iov_base;
			} else {
				iov_base += status;
			}
		} else {

			if(unlikely(PageSpec(page)))
				check_asymmetric_page_conflicts(mapping, page, ACCESS_RW);

			status = a_ops->prepare_write(file, page, offset, offset+bytes);
			if (unlikely(status)) {
				struct _inode *_inode = tx_cache_get_inode_ro(inode);
				loff_t isize = i_size_read(_inode);

				if (status != AOP_TRUNCATED_PAGE)
					unlock_page(page);
				page_cache_release(page);
				if (status == AOP_TRUNCATED_PAGE)
					continue;
				/*
				 * prepare_write() may have instantiated a few blocks
				 * outside i_size.  Trim these off again.
				 */
				if (pos + bytes > isize){
					_inode = tx_cache_get_inode(inode);
					vmtruncate(_inode, isize);
				}
				break;
			}

			if (likely(nr_segs == 1))
				copied = filemap_copy_from_user(page, offset,
								buf, bytes);
			else
				copied = filemap_copy_from_user_iovec(page, offset,
								      cur_iov, iov_base, bytes);
			flush_dcache_page(page);
			status = a_ops->commit_write(file, page, offset, offset+bytes);
			if (status == AOP_TRUNCATED_PAGE) {
				page_cache_release(page);
				continue;
			}
		zero_length_segment:
			if (likely(copied >= 0)) {
				if (!status)
					status = copied;

				if (status >= 0) {
					written += status;
					count -= status;
					pos += status;
					buf += status;
				  
					if (unlikely(nr_segs > 1)) {
						filemap_set_next_iovec(&cur_iov,
								       &iov_base, status);
						if (count)
							buf = cur_iov->iov_base +
								iov_base;
					} else {
						iov_base += status;
					}
				}
			}
			if (unlikely(copied != bytes))
				if (status >= 0)
					status = -EFAULT;
			unlock_page(page);
			mark_page_accessed(page);
			page_cache_release(page);
			if (status < 0)
				break;
			balance_dirty_pages_ratelimited(mapping);
			cond_resched();
		}
	} while (count);
	*ppos = pos;

	if (cached_page)
		page_cache_release(cached_page);

	/*
	 * For now, when the user asks for O_SYNC, we'll actually give O_DSYNC
	 */
	if (likely(status >= 0)) {
		struct _inode *_inode = tx_cache_get_inode_ro(inode);
		if (unlikely((tx_cache_get_file_ro(file)->f_flags & O_SYNC)
			     || IS_SYNC(_inode))) {
			if (!a_ops->writepage || !is_sync_kiocb(iocb))
				status = generic_osync_inode(inode, mapping,
						OSYNC_METADATA|OSYNC_DATA);
		}
  	}
	
	/*
	 * If we get here for O_DIRECT writes then we must have fallen through
	 * to buffered writes (block instantiation inside i_size).  So we sync
	 * the file data here, to try to honour O_DIRECT expectations.
	 */
	if (unlikely(tx_cache_get_file_ro(file)->f_flags & O_DIRECT) && written)
		status = filemap_write_and_wait(mapping);

	pagevec_lru_add(&lru_pvec);
	return written ? written : status;
}
EXPORT_SYMBOL(generic_file_buffered_write);

static ssize_t
__generic_file_aio_write_nolock(struct kiocb *iocb, const struct iovec *iov,
				unsigned long nr_segs, loff_t *ppos)
{
	struct file *file = iocb->ki_filp;
	struct _file *_file;
	struct address_space * mapping = file->f_mapping;
	size_t ocount;		/* original count */
	size_t count;		/* after file limit checks */
	struct inode 	*inode = mapping->host;
	struct _inode	*_inode = tx_cache_get_inode_ro(inode);
	loff_t		pos;
	ssize_t		written;
	ssize_t		err;

	if(unlikely(inode == NULL)){
		printk(KERN_ERR "Null inode at %p\n", &file->f_mapping);
	}

	ocount = 0;
	err = generic_segment_checks(iov, &nr_segs, &ocount, VERIFY_READ);
	if (err)
		return err;

	count = ocount;
	pos = *ppos;

	vfs_check_frozen(_inode->i_sb, SB_FREEZE_WRITE);

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = mapping->backing_dev_info;
	written = 0;

	_file = tx_cache_get_file_ro(file);
	err = generic_write_checks(_file, &pos, &count, S_ISBLK(_inode->i_mode));
	if (err)
		goto out;

	if (count == 0)
		goto out;

	err = remove_suid(file_get_dentry_ro(file));
	if (err)
		goto out;

	file_update_time(file);

	/* coalesce the iovecs and go direct-to-BIO for O_DIRECT */
	if (unlikely(_file->f_flags & O_DIRECT)) {
		loff_t endbyte;
		ssize_t written_buffered;

		KSTM_BUG_ON(live_transaction());

		written = generic_file_direct_write(iocb, iov, &nr_segs, pos,
							ppos, count, ocount);
		if (written < 0 || written == count)
			goto out;
		/*
		 * direct-io write to a hole: fall through to buffered I/O
		 * for completing the rest of the request.
		 */
		pos += written;
		count -= written;
		written_buffered = generic_file_buffered_write(iocb, iov,
						nr_segs, pos, ppos, count,
						written);
		/*
		 * If generic_file_buffered_write() retuned a synchronous error
		 * then we want to return the number of bytes which were
		 * direct-written, or the error code if that was zero.  Note
		 * that this differs from normal direct-io semantics, which
		 * will return -EFOO even if some bytes were written.
		 */
		if (written_buffered < 0) {
			err = written_buffered;
			goto out;
		}

		/*
		 * We need to ensure that the page cache pages are written to
		 * disk and invalidated to preserve the expected O_DIRECT
		 * semantics.
		 */
		endbyte = pos + written_buffered - written - 1;
		err = do_sync_mapping_range(file->f_mapping, pos, endbyte,
					    SYNC_FILE_RANGE_WAIT_BEFORE|
					    SYNC_FILE_RANGE_WRITE|
					    SYNC_FILE_RANGE_WAIT_AFTER);
		if (err == 0) {
			written = written_buffered;
			invalidate_mapping_pages(mapping,
						 pos >> PAGE_CACHE_SHIFT,
						 endbyte >> PAGE_CACHE_SHIFT);
		} else {
			/*
			 * We don't know how much we wrote, so just return
			 * the number of bytes which were direct-written
			 */
		}
	} else {
		written = generic_file_buffered_write(iocb, iov, nr_segs,
				pos, ppos, count, written);
	}
out:
	current->backing_dev_info = NULL;
	return written ? written : err;
}

ssize_t generic_file_aio_write_nolock(struct kiocb *iocb,
		const struct iovec *iov, unsigned long nr_segs, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	struct _inode *_inode = tx_cache_get_inode_ro(inode);
	ssize_t ret;

	BUG_ON(iocb->ki_pos != pos);

	ret = __generic_file_aio_write_nolock(iocb, iov, nr_segs,
			&iocb->ki_pos);

	if (ret > 0 && ((tx_cache_get_file_ro(file)->f_flags & O_SYNC) || IS_SYNC(_inode))) {
		ssize_t err;

		err = sync_page_range_nolock(inode, mapping, pos, ret);
		if (err < 0)
			ret = err;
	}
	return ret;
}
EXPORT_SYMBOL(generic_file_aio_write_nolock);

ssize_t generic_file_aio_write(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	struct _inode *_inode = tx_cache_get_inode_ro(inode);
	ssize_t ret;

	/* Put the inode in your workset ahead of time */

	BUG_ON(iocb->ki_pos != pos);

	KSTM_BUG_ON(committing_transaction());
	
	mutex_lock(&inode->i_mutex);
	record_tx_lock(&inode->i_mutex, MUTEX);

	ret = __generic_file_aio_write_nolock(iocb, iov, nr_segs,
			&iocb->ki_pos);

	mutex_unlock(&inode->i_mutex);
	record_tx_unlock(&inode->i_mutex, MUTEX);
	
	if (ret > 0 && ((tx_cache_get_file_ro(file)->f_flags & O_SYNC) 
			|| IS_SYNC(_inode))) {
		ssize_t err;

		err = sync_page_range(inode, mapping, pos, ret);
		if (err < 0)
			ret = err;
	}
	return ret;
}
EXPORT_SYMBOL(generic_file_aio_write);

/*
 * Called under i_mutex for writes to S_ISREG files.   Returns -EIO if something
 * went wrong during pagecache shootdown.
 */
static ssize_t
generic_file_direct_IO(int rw, struct kiocb *iocb, const struct iovec *iov,
	loff_t offset, unsigned long nr_segs)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	ssize_t retval;
	size_t write_len;
	pgoff_t end = 0; /* silence gcc */

	/*
	 * If it's a write, unmap all mmappings of the file up-front.  This
	 * will cause any pte dirty bits to be propagated into the pageframes
	 * for the subsequent filemap_write_and_wait().
	 */
	if (rw == WRITE) {
		write_len = iov_length(iov, nr_segs);
		end = (offset + write_len - 1) >> PAGE_CACHE_SHIFT;
	       	if (mapping_mapped(mapping))
			unmap_mapping_range(mapping, offset, write_len, 0);
	}

	retval = filemap_write_and_wait(mapping);
	if (retval)
		goto out;

	/*
	 * After a write we want buffered reads to be sure to go to disk to get
	 * the new data.  We invalidate clean cached page from the region we're
	 * about to write.  We do this *before* the write so that we can return
	 * -EIO without clobbering -EIOCBQUEUED from ->direct_IO().
	 */
	if (rw == WRITE && mapping->nrpages) {
		retval = invalidate_inode_pages2_range(mapping,
					offset >> PAGE_CACHE_SHIFT, end);
		if (retval)
			goto out;
	}

	retval = mapping->a_ops->direct_IO(rw, iocb, iov, offset, nr_segs);
	if (retval)
		goto out;

	/*
	 * Finally, try again to invalidate clean pages which might have been
	 * faulted in by get_user_pages() if the source of the write was an
	 * mmap()ed region of the file we're writing.  That's a pretty crazy
	 * thing to do, so we don't support it 100%.  If this invalidation
	 * fails and we have -EIOCBQUEUED we ignore the failure.
	 */
	if (rw == WRITE && mapping->nrpages) {
		int err = invalidate_inode_pages2_range(mapping,
					      offset >> PAGE_CACHE_SHIFT, end);
		if (err && retval >= 0)
			retval = err;
	}
out:
	return retval;
}

/**
 * try_to_release_page() - release old fs-specific metadata on a page
 *
 * @page: the page which the kernel is trying to free
 * @gfp_mask: memory allocation flags (and I/O mode)
 *
 * The address_space is to try to release any data against the page
 * (presumably at page->private).  If the release was successful, return `1'.
 * Otherwise return zero.
 *
 * The @gfp_mask argument specifies whether I/O may be performed to release
 * this page (__GFP_IO), and whether the call may block (__GFP_WAIT).
 *
 * NOTE: @gfp_mask may go away, and this function may become non-blocking.
 */
int try_to_release_page(struct page *page, gfp_t gfp_mask)
{
	struct address_space * const mapping = page->mapping;

	BUG_ON(!PageLocked(page));
	if (PageWriteback(page))
		return 0;

	if (mapping && mapping->a_ops->releasepage)
		return mapping->a_ops->releasepage(page, gfp_mask);
	return try_to_free_buffers(page);
}

EXPORT_SYMBOL(try_to_release_page);
