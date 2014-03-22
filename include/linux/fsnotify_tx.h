#ifndef _LINUX_FS_NOTIFY_TX_H
#define _LINUX_FS_NOTIFY_TX_H

/* A place for these delcarations to call home */

#ifdef CONFIG_TX_KSTM

enum fsnotify_id { D_MOVE, MOVE, NAMEREMOVE, INODEREMOVE, 
		   CREATE, MKDIR, ACCESS, MODIFY, FSNOTIFY_OPEN, CLOSE, XATTR,
		   CHANGE};

struct fsnotify_event_record {
	enum fsnotify_id id;
	void *arg1;
	void *arg2; 
	void *arg3;
	void *arg4;
	int   arg5;
	void *arg6;
	void *arg7;
};

#endif

#endif /* _LINUX_FS_NOTIFY_TX_H */
