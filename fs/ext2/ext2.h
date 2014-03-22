#include <linux/fs.h>
#include <linux/ext2_fs.h>

/*
 * ext2 mount options
 */
struct ext2_mount_options {
	unsigned long s_mount_opt;
	uid_t s_resuid;
	gid_t s_resgid;
};

#ifdef CONFIG_TX_KSTM
/* Cursor into the list of speculative and non-speculative dentries */
struct ext2_cur_sdirent {
	struct list_head *next_sdirent;	/* Next available speculative dirent */
	struct ext2_dir_entry_2 *entry;	/* Actual speculative or stable dirent */
	char *real_addr;						/* Real address this entry reflects */

	struct ext2_inode_info *inode;	/* Inode containing directory data */
	int pageno;								/* Which directory page cursor is on */
	char *kaddr;							/* Address of the current directory page */
};
#endif

/*
 * Inode dynamic state flags
 */
#define EXT2_STATE_NEW			0x00000001 /* inode is newly created */


/*
 * Function prototypes
 */

/*
 * Ok, these declarations are also in <linux/kernel.h> but none of the
 * ext2 source programs needs to include it so they are duplicated here.
 */

static inline struct ext2_inode_info *EXT2_I(const struct inode *inode)
{
	return container_of(inode, struct ext2_inode_info, vfs_inode);
}

static inline struct _ext2_inode_info *_EXT2_I(const struct _inode *inode)
{
	return container_of(inode, struct _ext2_inode_info, _vfs_inode);
}

/* balloc.c */
extern int ext2_bg_has_super(struct _super_block *sb, int group);
extern unsigned long ext2_bg_num_gdb(struct _super_block *sb, int group);
extern int ext2_new_block (struct inode *, unsigned long,
			   __u32 *, __u32 *, int *);
extern void ext2_free_blocks (struct inode *, unsigned long,
			      unsigned long);
extern unsigned long ext2_count_free_blocks (struct super_block *);
extern unsigned long ext2_count_dirs (struct super_block *);
extern void ext2_check_blocks_bitmap (struct super_block *);
extern struct ext2_group_desc * ext2_get_group_desc(struct super_block * sb,
						    unsigned int block_group,
						    struct buffer_head ** bh);

/* dir.c */
extern int ext2_add_link (struct _dentry *, struct _inode *);
extern ino_t ext2_inode_by_name(struct _inode *, struct _dentry *);
extern int ext2_make_empty(struct _inode *, struct _inode *);
extern void ext2_find_entry (struct ext2_cur_sdirent *cur_de, struct _inode *,struct _dentry *, struct page **);
extern int ext2_delete_entry (struct ext2_cur_sdirent *, struct page *);
extern int ext2_empty_dir (struct _inode *);
extern void ext2_dotdot (struct ext2_cur_sdirent *cur, struct _inode *, struct page **);
extern void ext2_set_link(struct _inode *, struct ext2_cur_sdirent *, struct page *, struct _inode *);

/* fsync.c */
extern int ext2_sync_file (struct file *, struct _dentry *, int);

/* ialloc.c */
extern struct inode * ext2_new_inode (struct _inode *, int);
extern void ext2_free_inode (struct _inode *);
extern unsigned long ext2_count_free_inodes (struct super_block *);
extern void ext2_check_inodes_bitmap (struct super_block *);
extern unsigned long ext2_count_free (struct buffer_head *, unsigned);

/* inode.c */
extern void ext2_read_inode (struct _inode *);
extern int ext2_write_inode (struct inode *, int);
extern void ext2_put_inode (struct _inode *);
extern void ext2_delete_inode (struct _inode *);
extern int ext2_sync_inode (struct inode *);
extern void ext2_discard_prealloc (struct inode *);
extern int ext2_get_block(struct _inode *, sector_t, struct buffer_head *, int);
extern void ext2_truncate (struct _inode *);
extern int ext2_setattr (struct dentry *, struct iattr *);
extern void ext2_set_inode_flags(struct _inode *inode);
extern void ext2_get_inode_flags(struct _ext2_inode_info *);

/* ioctl.c */
extern int ext2_ioctl (struct inode *, struct file *, unsigned int,
		       unsigned long);
extern long ext2_compat_ioctl(struct file *, unsigned int, unsigned long);

/* namei.c */
struct dentry *ext2_get_parent(struct _dentry *child);

/* super.c */
extern void ext2_error (struct super_block *, const char *, const char *, ...)
	__attribute__ ((format (printf, 3, 4)));
extern void ext2_warning (struct super_block *, const char *, const char *, ...)
	__attribute__ ((format (printf, 3, 4)));
extern void ext2_update_dynamic_rev (struct super_block *sb);
extern void ext2_write_super (struct super_block *);

/*
 * Inodes and files operations
 */

/* dir.c */
extern int ext2_init_sdirent_cache(void);
extern int ext2_commit_sdirents(struct ext2_inode_info *ei);
extern void ext2_abort_sdirents(struct ext2_inode_info *ei);
extern void ext2_init_sdirents(struct _inode *inode, enum access_mode mode);
extern const struct file_operations ext2_dir_operations;

/* file.c */
extern const struct inode_operations ext2_file_inode_operations;
extern const struct file_operations ext2_file_operations;
extern const struct file_operations ext2_xip_file_operations;

/* inode.c */
extern const struct address_space_operations ext2_aops;
extern const struct address_space_operations ext2_aops_xip;
extern const struct address_space_operations ext2_nobh_aops;

/* namei.c */
extern const struct inode_operations ext2_dir_inode_operations;
extern const struct inode_operations ext2_special_inode_operations;

/* symlink.c */
extern const struct inode_operations ext2_fast_symlink_inode_operations;
extern const struct inode_operations ext2_symlink_inode_operations;
