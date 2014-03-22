#ifndef _LINUX_TX_PAGES_H
#define _LINUX_TX_PAGES_H

#include <linux/pagemap.h>

#ifdef CONFIG_TX_KSTM

extern struct kmem_cache *tx_page_cachep;
#define alloc_txpg_buf() kmem_cache_alloc(tx_page_cachep, GFP_ATOMIC)
#define free_txpg_buf(item) kmem_cache_free(tx_page_cachep, (item))

// Defer page releases until commit
static inline void tx_page_cache_release(struct page * page){
	int i;
	struct page_record_buf *buf;

	BUG_ON(page_count(page) != 1);

	if(!live_transaction()){
		page_cache_release(page);
		return;
	}

	list_for_each_entry(buf, &current->tx_page_allocs, list){
		for(i = 0; i < buf->count; i++){
			if(page == buf->pages[i]){
				page_cache_release(page);
				buf->pages[i] = NULL;
				return;
			}
		}
	}

	list_for_each_entry(buf, &current->tx_page_frees, list){
		if(buf->count < MAX_TX_PAGES){
			buf->pages[buf->count++] = page;
			return;
		}
	}

	buf = alloc_txpg_buf();
	buf->count = 1;
	buf->pages[0] = page;
	INIT_LIST_HEAD(&buf->list);
	list_add(&buf->list, &current->tx_page_frees);
}


// Re-free alloc'ed pages at abort
static inline int _tx_alloc_page(struct page *ret, struct page_record_buf *buf){
	int i;
	for(i = 0; i < buf->count; i++){
		if(NULL == buf->pages[i]){
			buf->pages[i] = ret;
			return 1;
		}
	}
	if(i < MAX_TX_PAGES){
		buf->pages[i] = ret;
		buf->count++;
		return 1;
	}

	return 0;
}

static inline struct page * tx_alloc_page(gfp_t gfp_mask){
	struct page_record_buf *buf;
	struct page *ret = alloc_page(gfp_mask);
	if(!live_transaction())
		return ret;

	list_for_each_entry(buf, &current->tx_page_allocs, list)
		if(_tx_alloc_page(ret, buf))
			return ret;
	
	buf = alloc_txpg_buf();
	buf->count = 0;
	INIT_LIST_HEAD(&buf->list);
	list_add(&buf->list, &current->tx_page_allocs);
	_tx_alloc_page(ret, buf);

	return ret;
}

#else

#define tx_page_cache_release(page) page_cache_release(page)
#define tx_alloc_page(mask) alloc_page(mask)

#endif

#endif //_LINUX_TX_PAGES_H
