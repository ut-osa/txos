#ifndef _LINUX_FS_STACK_H
#define _LINUX_FS_STACK_H

/* This file defines generic functions used primarily by stackable
 * filesystems; none of these functions require i_mutex to be held.
 */

#include <linux/fs.h>

/* externs for fs/stack.c */
extern void fsstack_copy_attr_all(struct _inode *dest, const struct _inode *src,
				int (*get_nlinks)(struct _inode *));

extern void fsstack_copy_inode_size(struct _inode *dst, const struct _inode *src);

/* inlines */
static inline void fsstack_copy_attr_atime(struct _inode *dest,
					   const struct _inode *src)
{
	dest->i_atime = src->i_atime;
}

static inline void fsstack_copy_attr_times(struct _inode *dest,
					   const struct _inode *src)
{
	dest->i_atime = src->i_atime;
	dest->i_mtime = src->i_mtime;
	dest->i_ctime = src->i_ctime;
}

#endif /* _LINUX_FS_STACK_H */
