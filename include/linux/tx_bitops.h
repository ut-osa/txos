#ifndef _LINUX_TX_BITOPS_H
#define _LINUX_TX_BITOPS_H

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/jbd.h>

enum tx_bitmap_type { INODE_BIT, BLOCK_BIT };
enum tx_bitop_op { BIT_CLEAR, BIT_SET };
typedef struct tx_bitop_list_node {

	/*the list_head needs to be the first element, due to weird list function
	  use in tx_bitops.c*/
	struct list_head list;
	enum tx_bitmap_type type;
	unsigned int number;
	int bit_op;
	struct super_block *sb;
} tx_bitop_list_node_t;


//no is the block/inode no to flip
int tx_add_new_bitop(enum tx_bitmap_type type, enum tx_bitop_op op, unsigned int no,
			    struct super_block *sb);
	
int ext3_clear_inode_atomic_tx(spinlock_t * lock, unsigned long bit, char * data, unsigned int ino,
			       struct super_block *sb);


int ext3_set_inode_atomic_tx(spinlock_t * lock, unsigned long bit, char * data, unsigned int ino,
			     struct super_block *sb);

int commit_all_bitops(handle_t *handle);

int rollback_all_bitops(handle_t *handle);

#endif
