/*
 * fs/sysfs/group.c - Operations for adding/removing multiple files at once.
 *
 * Copyright (c) 2003 Patrick Mochel
 * Copyright (c) 2003 Open Source Development Lab
 *
 * This file is released undert the GPL v2. 
 *
 */

#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <asm/semaphore.h>
#include "sysfs.h"


static void remove_files(struct dentry * dir, 
			 const struct attribute_group * grp)
{
	struct attribute *const* attr;

	for (attr = grp->attrs; *attr; attr++)
		sysfs_hash_and_remove(dir,(*attr)->name);
}

static int create_files(struct dentry * dir,
			const struct attribute_group * grp)
{
	struct attribute *const* attr;
	int error = 0;

	for (attr = grp->attrs; *attr && !error; attr++) {
		error = sysfs_add_file(dir, *attr, SYSFS_KOBJ_ATTR);
	}
	if (error)
		remove_files(dir,grp);
	return error;
}


int sysfs_create_group(struct kobject * kobj, 
		       const struct attribute_group * grp)
{
	struct _dentry * dir;
	int error;

	BUG_ON(!kobj || !kobj->dentry);

	if (grp->name) {
		error = sysfs_create_subdir(kobj,grp->name,&dir);
		if (error)
			return error;
	} else
		dir = tx_cache_get_dentry(kobj->dentry);
	dir = tx_cache_get_dentry(dget(parent(dir)));
	if ((error = create_files(parent(dir),grp))) {
		if (grp->name)
			sysfs_remove_subdir(dir);
	}
	dput(parent(dir));
	return error;
}

void sysfs_remove_group(struct kobject * kobj, 
			const struct attribute_group * grp)
{
	struct _dentry * dir;

	if (grp->name) {
		struct _dentry *dentry = tx_cache_get_dentry(kobj->dentry);
		dir = lookup_one_len_kern(grp->name, &dentry,
					  strlen(grp->name));
		BUG_ON(IS_ERR(dir));
	}
	else
		dir = tx_cache_get_dentry(dget(kobj->dentry));

	remove_files(parent(dir),grp);
	if (grp->name)
		sysfs_remove_subdir(dir);
	/* release the ref. taken in this routine */
	dput(parent(dir));
}


EXPORT_SYMBOL_GPL(sysfs_create_group);
EXPORT_SYMBOL_GPL(sysfs_remove_group);
