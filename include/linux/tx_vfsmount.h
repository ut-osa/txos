#ifndef _LINUX_TX_VFSMOUNT_H
#define _LINUX_TX_VFSMOUNT_H

void * tx_cache_get_vfsmount_void(void *, enum access_mode);
struct vfsmount * tx_cache_get_vfsmount(struct vfsmount * vfsmount);
struct vfsmount * tx_cache_get_vfsmount_ro(struct vfsmount * vfsmount);
struct vfsmount * mnt_get_parent(struct vfsmount *);
struct vfsmount * mnt_get_parent_ro(struct vfsmount *);

struct dentry * mnt_get_mountpoint(struct vfsmount *);
struct dentry * mnt_get_mountpoint_ro(struct vfsmount *);

#endif //_LINUX_TX_VFSMOUNT_H
