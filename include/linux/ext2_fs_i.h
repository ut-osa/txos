#ifndef _LINUX_EXT2_FS_I_H
#define _LINUX_EXT2_FS_I_H

#include <linux/types.h>
#include <linux/magic.h>

/*
 * second extended file system inode data in memory
 */
struct _ext2_inode_info {
	__u32	i_flags;
	__u32	i_faddr;
	__u8	i_frag_no;
	__u8	i_frag_size;
	__u32	i_file_acl;
	__u32	i_dir_acl;
	__u32	i_dtime;

	struct ext2_inode_info *parent;
	struct _inode	_vfs_inode;
};


struct ext2_inode_info {
	__le32	i_data[15];
	__u16	i_state;

	/*
	 * i_block_group is the number of the block group which contains
	 * this file's inode.  Constant across the lifetime of the inode,
	 * it is ued for making block allocation decisions - we try to
	 * place a file's data blocks near its inode block, and new inodes
	 * near to their parent directory's inode.
	 */
	__u32	i_block_group;

	/*
	 * i_next_alloc_block is the logical (file-relative) number of the
	 * most-recently-allocated block in this file.  Yes, it is misnamed.
	 * We use this for detecting linearly ascending allocation requests.
	 */
	__u32	i_next_alloc_block;

	/*
	 * i_next_alloc_goal is the *physical* companion to i_next_alloc_block.
	 * it the the physical block number of the block which was most-recently
	 * allocated to this file.  This give us the goal (target) for the next
	 * allocation when we detect linearly ascending requests.
	 */
	__u32	i_next_alloc_goal;
	__u32	i_prealloc_block;
	__u32	i_prealloc_count;
	__u32	i_dir_start_lookup;

#ifdef CONFIG_EXT2_FS_XATTR
	/*
	 * Extended attributes can be read independently of the main file
	 * data. Taking i_mutex even when reading would cause contention
	 * between readers of EAs and writers of regular file data, so
	 * instead we synchronize on xattr_sem when reading or changing
	 * EAs.
	 */
	struct rw_semaphore xattr_sem;
#endif
#ifdef CONFIG_EXT2_FS_POSIX_ACL
	struct posix_acl	*i_acl;
	struct posix_acl	*i_default_acl;
#endif
	rwlock_t i_meta_lock;
#ifdef CONFIG_TX_KSTM
   struct list_head sdentries;   /* Speculative modifications to the list of
                                    directory entries */
#endif
	struct inode	vfs_inode;
};

#endif
