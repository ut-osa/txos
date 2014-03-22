/*
 *  linux/fs/pipe.c
 *
 *  Copyright (C) 1991, 1992, 1999  Linus Torvalds
 */

#include <linux/mm.h>
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/pipe_fs_i.h>
#include <linux/uio.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/audit.h>

#include <asm/uaccess.h>
#include <asm/ioctls.h>

#include <linux/transaction.h>
#include <linux/tx_inodes.h>
#include <linux/tx_pages.h>
#include <linux/tx_dentry.h>
#include <linux/tx_file.h>

/*
 * We use a start+len construction, which provides full use of the 
 * allocated memory.
 * -- Florian Coosmann (FGC)
 * 
 * Reads with count = 0 should always return 0.
 * -- Julian Bradfield 1999-06-07.
 *
 * FIFOs and Pipes now generate SIGIO for both readers and writers.
 * -- Jeremy Elson <jelson@circlemud.org> 2001-08-16
 *
 * pipe_read & write cleanup
 * -- Manfred Spraul <manfred@colorfullife.com> 2002-05-09
 */

/* A kmem cache for tx pipe info */
struct kmem_cache *tx_pipe_cachep;

#define alloc_tx_pipe() kmem_cache_zalloc(tx_pipe_cachep, GFP_KERNEL);
#define free_tx_pipe(pipe) kmem_cache_free(tx_pipe_cachep, pipe);

/* Drop the inode semaphore and wait for a pipe event, atomically */
void pipe_wait(struct pipe_inode_info *pipe)
{
	DEFINE_WAIT(wait);

	/*
	 * Pipes are system-local resources, so sleeping on them
	 * is considered a noninteractive wait:
	 */
	prepare_to_wait(&pipe->wait, &wait,
			TASK_INTERRUPTIBLE | TASK_NONINTERACTIVE);
	if (pipe->inode)
		mutex_unlock(&pipe->inode->i_mutex);
	schedule();
	finish_wait(&pipe->wait, &wait);
	if (pipe->inode)
		mutex_lock(&pipe->inode->i_mutex);

}

static int
pipe_iov_copy_from_user(void *to, struct iovec *iov, unsigned long len,
			int atomic)
{
	unsigned long copy;

	while (len > 0) {
		while (!iov->iov_len)
			iov++;
		copy = min_t(unsigned long, len, iov->iov_len);

		if (atomic) {
			if (__copy_from_user_inatomic(to, iov->iov_base, copy))
				return -EFAULT;
		} else {
			if (copy_from_user(to, iov->iov_base, copy))
				return -EFAULT;
		}
		to += copy;
		len -= copy;
		iov->iov_base += copy;
		iov->iov_len -= copy;
	}
	return 0;
}

static int
pipe_iov_copy_to_user(struct iovec *iov, const void *from, unsigned long len,
		      int atomic)
{
	unsigned long copy;

	while (len > 0) {
		while (!iov->iov_len)
			iov++;
		copy = min_t(unsigned long, len, iov->iov_len);

		if (atomic) {
			if (__copy_to_user_inatomic(iov->iov_base, from, copy))
				return -EFAULT;
		} else {
			if (copy_to_user(iov->iov_base, from, copy))
				return -EFAULT;
		}
		from += copy;
		len -= copy;
		iov->iov_base += copy;
		iov->iov_len -= copy;
	}
	return 0;
}

/*
 * Attempt to pre-fault in the user memory, so we can use atomic copies.
 * Returns the number of bytes not faulted in.
 */
static int iov_fault_in_pages_write(struct iovec *iov, unsigned long len)
{
	while (!iov->iov_len)
		iov++;

	while (len > 0) {
		unsigned long this_len;

		this_len = min_t(unsigned long, len, iov->iov_len);
		if (fault_in_pages_writeable(iov->iov_base, this_len))
			break;

		len -= this_len;
		iov++;
	}

	return len;
}

/*
 * Pre-fault in the user memory, so we can use atomic copies.
 */
static void iov_fault_in_pages_read(struct iovec *iov, unsigned long len)
{
	while (!iov->iov_len)
		iov++;

	while (len > 0) {
		unsigned long this_len;

		this_len = min_t(unsigned long, len, iov->iov_len);
		fault_in_pages_readable(iov->iov_base, this_len);
		len -= this_len;
		iov++;
	}
}

static void anon_pipe_buf_release(struct pipe_inode_info *pipe,
				  struct pipe_buffer *buf)
{
	struct page *page = buf->page;

	/*
	 * If nobody else uses this page, and we don't already have a
	 * temporary page, let's keep track of it as a one-deep
	 * allocation cache. (Otherwise just release our reference to it)
	 */
	if (page_count(page) == 1 && !pipe->tmp_page)
		pipe->tmp_page = page;
	else
		page_cache_release(page);
}

void *generic_pipe_buf_map(struct pipe_inode_info *pipe,
			   struct pipe_buffer *buf, int atomic)
{
	if (atomic) {
		buf->flags |= PIPE_BUF_FLAG_ATOMIC;
		return kmap_atomic(buf->page, KM_USER0);
	}

	return kmap(buf->page);
}

void generic_pipe_buf_unmap(struct pipe_inode_info *pipe,
			    struct pipe_buffer *buf, void *map_data)
{
	if (buf->flags & PIPE_BUF_FLAG_ATOMIC) {
		buf->flags &= ~PIPE_BUF_FLAG_ATOMIC;
		kunmap_atomic(map_data, KM_USER0);
	} else
		kunmap(buf->page);
}

int generic_pipe_buf_steal(struct pipe_inode_info *pipe,
			   struct pipe_buffer *buf)
{
	struct page *page = buf->page;

	if (page_count(page) == 1) {
		lock_page(page);
		return 0;
	}

	return 1;
}

void generic_pipe_buf_get(struct pipe_inode_info *info, struct pipe_buffer *buf)
{
	page_cache_get(buf->page);
}

int generic_pipe_buf_pin(struct pipe_inode_info *info, struct pipe_buffer *buf)
{
	return 0;
}

static const struct pipe_buf_operations anon_pipe_buf_ops = {
	.can_merge = 1,
	.map = generic_pipe_buf_map,
	.unmap = generic_pipe_buf_unmap,
	.pin = generic_pipe_buf_pin,
	.release = anon_pipe_buf_release,
	.steal = generic_pipe_buf_steal,
	.get = generic_pipe_buf_get,
};

static struct tx_pipe_data *tx_cache_get_pipe_data(struct pipe_inode_info *pipe, enum access_mode mode){

	/* The _inode should already be in our main working set.  Just
	 * check that we aren't aborted, do the pipe-specific conflict
	 * detection, and bookkeeping setup.  This should be done with
	 * the imutex held.
	 */
	void *tmp;
	struct tx_pipe_data *data, *n, *my_data = NULL;
	int add_w = 0, add_r = 0;

	if((tmp = tx_status_check(pipe, mode, 1)) != NULL){
		if (IS_ERR(tmp)){
			mutex_unlock(&pipe->inode->i_mutex);
			abort_self(NULL, 0);
		}
		// Asymmetric detection.
	retry:
		list_for_each_entry_safe(data, n, &pipe->active_tx_list, list){
			if( (mode == ACCESS_PIPE_READ && (data->mode == ACCESS_PIPE_READ || data->mode == ACCESS_PIPE_RW))
			    || (mode == ACCESS_PIPE_WRITE && (data->mode == ACCESS_PIPE_WRITE || data->mode == ACCESS_PIPE_RW))){
				
				if(contentionManager(current->transaction, data->transaction, NULL)){
					// We win
					abortTransaction(data->transaction);
					list_move(&pipe->aborted_tx_list, &data->list);
				} else {
					// We lose.  Stall and retry later.
					mutex_unlock(&pipe->inode->i_mutex);
					wait_on_tx(data->transaction);
					mutex_lock(&pipe->inode->i_mutex);
					goto retry;
				}
			}
		}

		return NULL;
	}
	
	// Conflict detection - at most 1 reader, 1 writer.  May be different tx's
	list_for_each_entry_safe(data, n, &pipe->active_tx_list, list){
		if(data->transaction == current->transaction){
			my_data = data;
			continue;
		}
				
		if( (mode == ACCESS_PIPE_READ && (data->mode == ACCESS_PIPE_READ || data->mode == ACCESS_PIPE_RW))
		    || (mode == ACCESS_PIPE_WRITE && (data->mode == ACCESS_PIPE_WRITE || data->mode == ACCESS_PIPE_RW))){
			if(contentionManager(current->transaction, data->transaction, NULL)){
				// We win
				abortTransaction(data->transaction);
				list_move(&pipe->aborted_tx_list, &data->list);
			} else {
				// We lose.  Stall and retry later.
				mutex_unlock(&pipe->inode->i_mutex);
				abort_self(data->transaction, 0);
			}
		}
	}
	
	if(!my_data){

		my_data = alloc_tx_pipe();
		my_data->mode = mode;
		
		// zalloc-ed buffer
		//for(i = 0; i < PIPE_BUFFERS; i++)
		//my_data->shadow_bufs[i].active = 0;

		list_add(&my_data->list, &pipe->active_tx_list);
		my_data->transaction = current->transaction;
		
		if(mode == ACCESS_PIPE_WRITE)
			add_w = 1;

		if(mode == ACCESS_PIPE_READ)
			add_r = 1;

	} else {
		if(my_data->mode == ACCESS_PIPE_READ && mode == ACCESS_PIPE_WRITE){
			add_w = 1;
			my_data->mode = ACCESS_PIPE_RW;
		}
		
		if(my_data->mode == ACCESS_PIPE_WRITE && mode == ACCESS_PIPE_READ){
			add_r = 1;
			my_data->mode = ACCESS_PIPE_RW;
		}
	}

	if(add_w)
		my_data->write_curbuf = pipe->write_curbuf;

	if(add_r)
		my_data->read_curbuf = pipe->read_curbuf;


	return my_data;
}

static ssize_t
pipe_read(struct kiocb *iocb, const struct iovec *_iov,
	   unsigned long nr_segs, loff_t pos)
{
	struct file *filp = iocb->ki_filp;
	struct _file *_filp = tx_cache_get_file_ro(filp);
	struct inode *inode = (f_get_dentry_ro(_filp))->d_inode;
	struct pipe_inode_info *pipe;
	int do_wakeup;
	ssize_t ret;
	struct iovec *iov = (struct iovec *)_iov;
	size_t total_len;
	struct tx_pipe_data *tx_pipe = NULL;

	total_len = iov_length(iov, nr_segs);
	/* Null read succeeds. */
	if (unlikely(total_len == 0))
		return 0;

	do_wakeup = 0;
	ret = 0;
	mutex_lock(&inode->i_mutex);
	pipe = inode->i_pipe;

	// XXX: Need a "yield" mechanism to address deadlock with producer/consumer sync
	//  * Prioritize exiting procs

	// XXX: At some point, protect non-tx written data from overwrite on wrap-around

	tx_pipe = tx_cache_get_pipe_data(pipe, ACCESS_PIPE_READ);
	KSTM_BUG_ON(inactive_transaction() && tx_pipe);
	KSTM_BUG_ON(active_transaction() && !tx_pipe);

	for (;;) {
		int read_curbuf = pipe->read_curbuf;
		int write_curbuf = pipe->write_curbuf;
		struct pipe_buffer *buf;
		size_t chars;
		struct shadow_buffer_info *shadow_buf = NULL;
		unsigned int offset;

		if(tx_pipe){
			read_curbuf = tx_pipe->read_curbuf;
			if(tx_pipe->mode == ACCESS_PIPE_RW)
				write_curbuf = tx_pipe->write_curbuf;
		}

		buf = pipe->bufs + read_curbuf;
		offset = buf->offset;
		chars = buf->len;

		if(tx_pipe){
			shadow_buf = &tx_pipe->shadow_bufs[read_curbuf];			
			if(!shadow_buf->active){
				shadow_buf->offset = buf->offset;
				shadow_buf->len = buf->len;
			} else {
				int total_difference = ((buf->len + buf->offset) - (shadow_buf->len + shadow_buf->offset));
				offset = shadow_buf->offset;
				chars = shadow_buf->len;
				
				// Pull in updates from an unrelated writer
				if(tx_pipe->mode == ACCESS_PIPE_READ
				   && total_difference > 0){
					DEBUG_BREAKPOINT();
					shadow_buf->len += total_difference;
				}
			}
		}
		
		KSTM_BUG_ON(chars + offset > PAGE_SIZE);

		if ((read_curbuf != write_curbuf) || chars){

			const struct pipe_buf_operations *ops = buf->ops;
			void *addr;
			int error, atomic;

			if (chars > total_len)
				chars = total_len;

			if(shadow_buf && !shadow_buf->active)
				shadow_buf->active = 1;

			KSTM_BUG_ON(!buf->ops);
			
			error = ops->pin(pipe, buf);
			if (error) {
				if (!ret)
					error = ret;
				break;
			}

			atomic = !iov_fault_in_pages_write(iov, chars);
redo:
			addr = ops->map(pipe, buf, atomic);
			error = pipe_iov_copy_to_user(iov, addr + offset, chars, atomic);
			ops->unmap(pipe, buf, addr);
			if (unlikely(error)) {
				/*
				 * Just retry with the slow path if we failed.
				 */
				if (atomic) {
					atomic = 0;
					goto redo;
				}
				if (!ret)
					ret = error;
				break;
			}
			ret += chars;
			total_len -= chars;
			if(tx_pipe){
				shadow_buf->offset += chars;
				shadow_buf->len -= chars;
				if(!shadow_buf->len){
					read_curbuf = (read_curbuf + 1) & (PIPE_BUFFERS-1);
					tx_pipe->read_curbuf = read_curbuf;
					do_wakeup = 1;
				}
				buf = pipe->bufs + read_curbuf;
				shadow_buf = &tx_pipe->shadow_bufs[read_curbuf];			
				if(!shadow_buf->active)
					chars = buf->len;
				else {
					int total_difference = ((buf->len + buf->offset) - (shadow_buf->len + shadow_buf->offset));
					offset = shadow_buf->offset;
					chars = shadow_buf->len;
					
					// Pull in updates from an unrelated writer
					if(tx_pipe->mode == ACCESS_PIPE_READ
					   && total_difference > 0){
						DEBUG_BREAKPOINT();
						shadow_buf->len += total_difference;
					}
				}
				
			} else {
				buf->offset += chars;
				buf->len -= chars;
				if (!buf->len) {
					buf->ops = NULL;
					ops->release(pipe, buf);
					buf->page = NULL;
					read_curbuf = (read_curbuf + 1) & (PIPE_BUFFERS-1);
					pipe->read_curbuf = read_curbuf;
					do_wakeup = 1;
				}
				buf = pipe->bufs + read_curbuf;
				chars = buf->len;
			}

			if (!total_len)
				break;	/* common path: read succeeded */

		}
		if (read_curbuf != write_curbuf || chars) 	/* More to do? */
			continue;
		if (!pipe->writers)
			break;

		if (!pipe->waiting_writers) {
			/* syscall merging: Usually we must not sleep
			 * if O_NONBLOCK is set, or if we got some data.
			 * But if a writer sleeps in kernel space, then
			 * we can wait for that data without violating POSIX.
			 */
			if (ret)
				break;
			if (_filp->f_flags & O_NONBLOCK) {
				ret = -EAGAIN;
				break;
			}
		}
		if (signal_pending(current)) {
			if (!ret)
				ret = -ERESTARTSYS;
			break;
		}

		if (do_wakeup) {
			wake_up_interruptible_sync(&pipe->wait);
 			kill_fasync(&pipe->fasync_writers, SIGIO, POLL_OUT);
		}
		pipe_wait(pipe);

	}
	mutex_unlock(&inode->i_mutex);

	/* Signal writers asynchronously that there is more room. */
	if (do_wakeup) {
		wake_up_interruptible(&pipe->wait);
		kill_fasync(&pipe->fasync_writers, SIGIO, POLL_OUT);
	}
	if (ret > 0)
		file_accessed(_filp);

	return ret;
}

static ssize_t
pipe_write(struct kiocb *iocb, const struct iovec *_iov,
	    unsigned long nr_segs, loff_t ppos)
{
	struct file *filp = iocb->ki_filp;
	struct inode *inode = (file_get_dentry_ro(filp))->d_inode;
	struct pipe_inode_info *pipe;
	ssize_t ret;
	int do_wakeup;
	struct iovec *iov = (struct iovec *)_iov;
	size_t total_len;
	ssize_t chars;
	struct tx_pipe_data *tx_pipe = NULL;
	unsigned int write_curbuf, read_curbuf;
	//int lastbuf;

	total_len = iov_length(iov, nr_segs);
	/* Null write succeeds. */
	if (unlikely(total_len == 0))
		return 0;

	do_wakeup = 0;
	ret = 0;
	mutex_lock(&inode->i_mutex);
	pipe = inode->i_pipe;

	if (!pipe->readers) {
		send_sig(SIGPIPE, current, 0);
		ret = -EPIPE;
		goto out;
	}

	tx_pipe = tx_cache_get_pipe_data(pipe, ACCESS_PIPE_WRITE);
	KSTM_BUG_ON(inactive_transaction() && tx_pipe);
	KSTM_BUG_ON(active_transaction() && !tx_pipe);

	if(tx_pipe){
		write_curbuf = tx_pipe->write_curbuf;
		if(tx_pipe->mode == ACCESS_PIPE_RW)
			read_curbuf = tx_pipe->read_curbuf;
		else
			read_curbuf = pipe->read_curbuf;
	} else{
		write_curbuf = pipe->write_curbuf;
		read_curbuf = pipe->read_curbuf;
	}

	/* We try to merge small writes */
	chars = total_len & (PAGE_SIZE-1); /* size of the last buffer */
	// dP: This is a tad conservative, but better safe than sorry
	if(read_curbuf != write_curbuf){
		//pipe->bufs[lastbuf].len && chars != 0) {
		int lastbuf = (write_curbuf - 1) & (PIPE_BUFFERS-1);
		struct pipe_buffer *buf = pipe->bufs + lastbuf;
		const struct pipe_buf_operations *ops = buf->ops;
		int offset;
		struct shadow_buffer_info *shadow_buf = NULL;

		if(tx_pipe){
			shadow_buf = &tx_pipe->shadow_bufs[lastbuf];
			if(shadow_buf->active)
				offset = shadow_buf->offset + shadow_buf->len;
			else {
				shadow_buf->active = 1;
				shadow_buf->offset = buf->offset;
				shadow_buf->len = buf->len;
				offset = buf->offset + buf->len;
			}
			
		} else
			offset = buf->offset + buf->len;

		if (ops->can_merge && offset + chars <= PAGE_SIZE) {
			int error, atomic = 1;
			void *addr;

			error = ops->pin(pipe, buf);
			if (error)
				goto out;

			iov_fault_in_pages_read(iov, chars);
redo1:
			addr = ops->map(pipe, buf, atomic);
			error = pipe_iov_copy_from_user(offset + addr, iov,
							chars, atomic);
			ops->unmap(pipe, buf, addr);
			ret = error;
			do_wakeup = 1;
			if (error) {
				if (atomic) {
					atomic = 0;
					goto redo1;
				}
				goto out;
			}
			if(tx_pipe){
				shadow_buf->len += chars;
				KSTM_BUG_ON(shadow_buf->len > PAGE_SIZE);
			} else {
				buf->len += chars;
			}

			total_len -= chars;
			ret = chars;
			if (!total_len)
				goto out;
		}
	}

	for (;;) {
		struct pipe_buffer *buf;
		unsigned int len;

		if (!pipe->readers) {
			send_sig(SIGPIPE, current, 0);
			if (!ret)
				ret = -EPIPE;
			break;
		}

		if(tx_pipe){
			write_curbuf = tx_pipe->write_curbuf;
			if(tx_pipe->mode == ACCESS_PIPE_RW)
				read_curbuf = tx_pipe->read_curbuf;
			else
				read_curbuf = pipe->read_curbuf;
		} else{
			write_curbuf = pipe->write_curbuf;
			read_curbuf = pipe->read_curbuf;
		}

		buf = pipe->bufs + write_curbuf;
		len = tx_pipe ? tx_pipe->shadow_bufs[write_curbuf].len : buf->len;

		if (write_curbuf != read_curbuf || !len){
			int newbuf = write_curbuf;
			struct page *page = buf->page ? buf->page : pipe->tmp_page;
			char *src;
			int error, atomic = 1;
			struct shadow_buffer_info *shadow_buf = NULL;

			KSTM_BUG_ON(len);

			if (!page) {
				page = alloc_page(GFP_HIGHUSER);
				if (unlikely(!page)) {
					ret = ret ? : -ENOMEM;
					break;
				}
				pipe->tmp_page = page;
			}
			/* Always wake up, even if the copy fails. Otherwise
			 * we lock up (O_NONBLOCK-)readers that sleep due to
			 * syscall merging.
			 * FIXME! Is this really true?
			 */
			do_wakeup = 1;
			chars = PAGE_SIZE;
			if (chars > total_len)
				chars = total_len;

			iov_fault_in_pages_read(iov, chars);
redo2:
			if (atomic)
				src = kmap_atomic(page, KM_USER0);
			else
				src = kmap(page);

			error = pipe_iov_copy_from_user(src, iov, chars,
							atomic);
			if (atomic)
				kunmap_atomic(src, KM_USER0);
			else
				kunmap(page);

			if (unlikely(error)) {
				if (atomic) {
					atomic = 0;
					goto redo2;
				}
				if (!ret)
					ret = error;
				break;
			}
			ret += chars;

			/* Insert it into the buffer array */
			buf->page = page;
			buf->ops = &anon_pipe_buf_ops;
			if(tx_pipe){
				shadow_buf = &tx_pipe->shadow_bufs[newbuf];
				if(!shadow_buf->active)
					shadow_buf->active = 1;

				shadow_buf->offset = 0;
				shadow_buf->len = chars;
				write_curbuf = tx_pipe->write_curbuf = (write_curbuf + 1) & (PIPE_BUFFERS-1);
			} else {
				buf->offset = 0;
				buf->len = chars;
				write_curbuf = pipe->write_curbuf = (write_curbuf + 1) & (PIPE_BUFFERS-1);
			}
			buf = pipe->bufs + write_curbuf;
			len = tx_pipe ? tx_pipe->shadow_bufs[write_curbuf].len : buf->len;
			pipe->tmp_page = NULL;

			total_len -= chars;
			if (!total_len)
				break;
		}
		if (write_curbuf != read_curbuf || !len)
			continue;
		if (tx_cache_get_file_ro(filp)->f_flags & O_NONBLOCK) {
			if (!ret)
				ret = -EAGAIN;
			break;
		}
		if (signal_pending(current)) {
			if (!ret)
				ret = -ERESTARTSYS;
			break;
		}

		if (do_wakeup) {
			wake_up_interruptible_sync(&pipe->wait);
			kill_fasync(&pipe->fasync_readers, SIGIO, POLL_IN);
			do_wakeup = 0;
		}

		pipe->waiting_writers++;
		pipe_wait(pipe);
		pipe->waiting_writers--;
	}
out:
	mutex_unlock(&inode->i_mutex);
	if (do_wakeup) {
		wake_up_interruptible(&pipe->wait);
		kill_fasync(&pipe->fasync_readers, SIGIO, POLL_IN);
	}
	if (ret > 0)
		file_update_time(filp);
	return ret;
}

static ssize_t
bad_pipe_r(struct file *filp, char __user *buf, size_t count, loff_t *ppos)
{
	return -EBADF;
}

static ssize_t
bad_pipe_w(struct file *filp, const char __user *buf, size_t count,
	   loff_t *ppos)
{
	return -EBADF;
}

static int
pipe_ioctl(struct inode *pino, struct file *filp,
	   unsigned int cmd, unsigned long arg)
{
	struct inode *inode = (file_get_dentry(filp))->d_inode;
	struct pipe_inode_info *pipe;
	int count, buf, wbuf;

	switch (cmd) {
		case FIONREAD:
			if(active_transaction())
				OSA_MAGIC(OSA_BREAKSIM);
			mutex_lock(&inode->i_mutex);
			pipe = inode->i_pipe;
			count = 0;
			buf = pipe->read_curbuf;
			wbuf = pipe->write_curbuf;
			do{
				count += pipe->bufs[buf].len;
				buf = (buf+1) & (PIPE_BUFFERS-1);
			} while (buf != wbuf);
			mutex_unlock(&inode->i_mutex);

			return put_user(count, (int __user *)arg);
		default:
			return -EINVAL;
	}
}

/* No kernel lock held - fine */
static unsigned int
pipe_poll(struct file *filp, poll_table *wait)
{
	unsigned int mask;
	struct inode *inode = (file_get_dentry(filp))->d_inode;
	struct pipe_inode_info *pipe = inode->i_pipe;
	struct _file *_filp = tx_cache_get_file_ro(filp);

	poll_wait(filp, &pipe->wait, wait);

	/* Reading only -- no need for acquiring the semaphore.  */
	mask = 0;
	if (_filp->f_mode & FMODE_READ) {
		mask = (pipe->read_curbuf != pipe->write_curbuf) ? POLLIN | POLLRDNORM : 0;
		if (!pipe->writers && _filp->f_version != pipe->w_counter)
			mask |= POLLHUP;
	}

	if (_filp->f_mode & FMODE_WRITE) {
		mask |= (((pipe->write_curbuf + 1) & (PIPE_BUFFERS-1)) != pipe->read_curbuf) ? POLLOUT | POLLWRNORM : 0;
		/*
		 * Most Unices do not set POLLERR for FIFOs but on Linux they
		 * behave exactly like pipes for poll().
		 */
		if (!pipe->readers)
			mask |= POLLERR;
	}

	return mask;
}

static int
pipe_release(struct inode *inode, int decr, int decw)
{
	struct pipe_inode_info *pipe;

	mutex_lock(&inode->i_mutex);
	pipe = inode->i_pipe;
	pipe->readers -= decr;
	pipe->writers -= decw;

	if (!pipe->readers && !pipe->writers) {
		/* If we are in a transaction, and the current
		 * transaction is the only reader/writer of the pipe,
		 * allow it to be freed.
		 */
		if(live_transaction()){
			struct tx_pipe_data *tx_pipe;
			if(!list_empty(&pipe->active_tx_list)){
				tx_pipe = list_entry(pipe->active_tx_list.next, struct tx_pipe_data, list);
				KSTM_BUG_ON(tx_pipe->list.next != &pipe->active_tx_list);
				KSTM_BUG_ON(tx_pipe->list.prev != &pipe->active_tx_list);
				list_del(&tx_pipe->list);
				free_tx_pipe(tx_pipe);
			}
			if(!list_empty(&pipe->aborted_tx_list)){
				tx_pipe = list_entry(pipe->aborted_tx_list.next, struct tx_pipe_data, list);
				KSTM_BUG_ON(tx_pipe->list.next != &pipe->aborted_tx_list);
				KSTM_BUG_ON(tx_pipe->list.prev != &pipe->aborted_tx_list);
				list_del(&tx_pipe->list);
				free_tx_pipe(tx_pipe);
			}
		}
		
		KSTM_BUG_ON(!list_empty(&pipe->active_tx_list));
		KSTM_BUG_ON(!list_empty(&pipe->aborted_tx_list));
		free_pipe_info(inode);
	} else {
		// Allow non-transactional scheduling
		pipe = inode->i_pipe;
		wake_up_interruptible(&pipe->wait);
		kill_fasync(&pipe->fasync_readers, SIGIO, POLL_IN);
		kill_fasync(&pipe->fasync_writers, SIGIO, POLL_OUT);
	}
	mutex_unlock(&inode->i_mutex);

	return 0;
}

static int
pipe_read_fasync(int fd, struct file *filp, int on)
{
	struct inode *inode = (file_get_dentry(filp))->d_inode;
	int retval;

	/* DEP: Use the non-transactional fasync struct for scheduling */
	mutex_lock(&inode->i_mutex);
	retval = fasync_helper(fd, filp, on, &inode->i_pipe->fasync_readers);
	mutex_unlock(&inode->i_mutex);

	if (retval < 0)
		return retval;

	return 0;
}


static int
pipe_write_fasync(int fd, struct file *filp, int on)
{
	struct inode *inode = (file_get_dentry_ro(filp))->d_inode;
	int retval;

	/* DEP: Use the non-transactional fasync struct for scheduling */
	mutex_lock(&inode->i_mutex);
	retval = fasync_helper(fd, filp, on, &inode->i_pipe->fasync_writers);
	mutex_unlock(&inode->i_mutex);

	if (retval < 0)
		return retval;

	return 0;
}


static int
pipe_rdwr_fasync(int fd, struct file *filp, int on)
{
	struct inode *inode = (file_get_dentry(filp))->d_inode;
	struct pipe_inode_info *pipe = inode->i_pipe;
	int retval;

	/* DEP: Use the non-transactional fasync struct for scheduling */
	mutex_lock(&inode->i_mutex);

	retval = fasync_helper(fd, filp, on, &pipe->fasync_readers);

	if (retval >= 0)
		retval = fasync_helper(fd, filp, on, &pipe->fasync_writers);

	mutex_unlock(&inode->i_mutex);

	if (retval < 0)
		return retval;

	return 0;
}


static int
pipe_read_release(struct _inode *inode, struct file *filp)
{
	pipe_read_fasync(-1, filp, 0);
	return pipe_release(parent(inode), 1, 0);
}

static int
pipe_write_release(struct _inode *inode, struct file *filp)
{
	pipe_write_fasync(-1, filp, 0);
	return pipe_release(parent(inode), 0, 1);
}

static int
pipe_rdwr_release(struct _inode *inode, struct file *filp)
{
	int decr, decw;
	struct _file *_filp = tx_cache_get_file(filp);

	pipe_rdwr_fasync(-1, filp, 0);
	decr = (_filp->f_mode & FMODE_READ) != 0;
	decw = (_filp->f_mode & FMODE_WRITE) != 0;
	return pipe_release(parent(inode), decr, decw);
}

static int
pipe_read_open(struct _inode *_inode, struct file *filp)
{
	struct inode *inode = parent(_inode);
	/* We could have perhaps used atomic_t, but this and friends
	   below are the only places.  So it doesn't seem worthwhile.  */
	mutex_lock(&inode->i_mutex);
	inode->i_pipe->readers++;
	mutex_unlock(&inode->i_mutex);

	return 0;
}

static int
pipe_write_open(struct _inode *_inode, struct file *filp)
{
	struct inode *inode = parent(_inode);
	mutex_lock(&inode->i_mutex);
	inode->i_pipe->writers++;
	mutex_unlock(&inode->i_mutex);

	return 0;
}

static int
pipe_rdwr_open(struct _inode *_inode, struct file *filp)
{
	struct _file *_filp = tx_cache_get_file_ro(filp);
	struct inode *inode = parent(_inode);
	mutex_lock(&inode->i_mutex);
	if (_filp->f_mode & FMODE_READ)
		inode->i_pipe->readers++;
	if (_filp->f_mode & FMODE_WRITE)
		inode->i_pipe->writers++;
	mutex_unlock(&inode->i_mutex);

	return 0;
}

/*
 * The file_operations structs are not static because they
 * are also used in linux/fs/fifo.c to do operations on FIFOs.
 */
const struct file_operations read_fifo_fops = {
	.llseek		= no_llseek,
	.read		= do_sync_read,
	.aio_read	= pipe_read,
	.write		= bad_pipe_w,
	.poll		= pipe_poll,
	.ioctl		= pipe_ioctl,
	.open		= pipe_read_open,
	.release	= pipe_read_release,
	.fasync		= pipe_read_fasync,
};

const struct file_operations write_fifo_fops = {
	.llseek		= no_llseek,
	.read		= bad_pipe_r,
	.write		= do_sync_write,
	.aio_write	= pipe_write,
	.poll		= pipe_poll,
	.ioctl		= pipe_ioctl,
	.open		= pipe_write_open,
	.release	= pipe_write_release,
	.fasync		= pipe_write_fasync,
};

const struct file_operations rdwr_fifo_fops = {
	.llseek		= no_llseek,
	.read		= do_sync_read,
	.aio_read	= pipe_read,
	.write		= do_sync_write,
	.aio_write	= pipe_write,
	.poll		= pipe_poll,
	.ioctl		= pipe_ioctl,
	.open		= pipe_rdwr_open,
	.release	= pipe_rdwr_release,
	.fasync		= pipe_rdwr_fasync,
};

static const struct file_operations read_pipe_fops = {
	.llseek		= no_llseek,
	.read		= do_sync_read,
	.aio_read	= pipe_read,
	.write		= bad_pipe_w,
	.poll		= pipe_poll,
	.ioctl		= pipe_ioctl,
	.open		= pipe_read_open,
	.release	= pipe_read_release,
	.fasync		= pipe_read_fasync,
};

static const struct file_operations write_pipe_fops = {
	.llseek		= no_llseek,
	.read		= bad_pipe_r,
	.write		= do_sync_write,
	.aio_write	= pipe_write,
	.poll		= pipe_poll,
	.ioctl		= pipe_ioctl,
	.open		= pipe_write_open,
	.release	= pipe_write_release,
	.fasync		= pipe_write_fasync,
};

static const struct file_operations rdwr_pipe_fops = {
	.llseek		= no_llseek,
	.read		= do_sync_read,
	.aio_read	= pipe_read,
	.write		= do_sync_write,
	.aio_write	= pipe_write,
	.poll		= pipe_poll,
	.ioctl		= pipe_ioctl,
	.open		= pipe_rdwr_open,
	.release	= pipe_rdwr_release,
	.fasync		= pipe_rdwr_fasync,
};

/* DEP: Ok to call this with a shadow inode, as it is only called in
 * one place
 */
struct pipe_inode_info * alloc_pipe_info(struct inode *inode)
{
	struct pipe_inode_info *pipe;

	pipe = kzalloc(sizeof(struct pipe_inode_info), GFP_KERNEL);
	if (pipe) {
		init_waitqueue_head(&pipe->wait);
		pipe->r_counter = pipe->w_counter = 1;
		pipe->inode = inode;
		INIT_LIST_HEAD(&pipe->active_tx_list);
		INIT_LIST_HEAD(&pipe->aborted_tx_list);
	}

	return pipe;
}

void __free_pipe_info(struct pipe_inode_info *pipe)
{
	int i;

	for (i = 0; i < PIPE_BUFFERS; i++) {
		struct pipe_buffer *buf = pipe->bufs + i;
		if (buf->ops)
			buf->ops->release(pipe, buf);
	}
	if (pipe->tmp_page) {
		__free_page(pipe->tmp_page);
		pipe->tmp_page = NULL;
	}
	kfree(pipe);
}

/* DEP: One of the few places where it is ok to pass a speculative
 * inode.  The function is just so short and called in so few places
 * that I couldn't stand to add that overhead.
 */

void free_pipe_info(struct inode *inode)
{
	__free_pipe_info(inode->i_pipe);
	inode->i_pipe = NULL;
}

static struct vfsmount *pipe_mnt __read_mostly;
static int pipefs_delete_dentry(struct _dentry *dentry)
{
	/*
	 * At creation time, we pretended this dentry was hashed
	 * (by clearing DCACHE_UNHASHED bit in d_flags)
	 * At delete time, we restore the truth : not hashed.
	 * (so that dput() can proceed correctly)
	 */
	dentry->d_flags |= DCACHE_UNHASHED;
	return 0;
}

/*
 * pipefs_dname() is called from d_path().
 */
static char *pipefs_dname(const struct _dentry *dentry, char *buffer, int buflen)
{
	return dynamic_dname(dentry, buffer, buflen, "pipe:[%lu]",
			     d_get_inode_ro(dentry)->i_ino);
}

static struct dentry_operations pipefs_dentry_operations = {
	.d_delete	= pipefs_delete_dentry,
	.d_dname	= pipefs_dname,
};

/* Tx Hooks */
static void pipefs_commit(struct _inode *_inode, enum access_mode mode, int file_write_data)
{
	struct pipe_inode_info *pipe = parent(_inode)->i_pipe;
	struct tx_pipe_data *tx_pipe;
	int wakeup_readers = 0, wakeup_writers = 0;
	int i;

	/* If we have a dangling reference to a freed pipe, that is
	 * ok.  A clearer early release might be better.
	 */
	if(!pipe)
		return;

	if(list_empty(&pipe->active_tx_list))
		return;

	list_for_each_entry(tx_pipe, &pipe->active_tx_list, list){
		if(tx_pipe->transaction == current->transaction){
			list_del(&tx_pipe->list);
			break;
		}
	}

	// We didn't read or write the pipe
	if(&tx_pipe->list == &pipe->active_tx_list)
		return;

	for(i = 0; i < PIPE_BUFFERS; i++){
		struct pipe_buffer *buf = pipe->bufs + i;
		struct shadow_buffer_info *shadow_buf = &tx_pipe->shadow_bufs[i];
		
		if(shadow_buf->active){
			buf->len = shadow_buf->len;
			buf->offset = shadow_buf->offset;
			if(!buf->len){
				// We've read everything in this buffer.  Just release it
				const struct pipe_buf_operations *ops = buf->ops;
				buf->ops = NULL;
				ops->release(pipe, buf);
			}
		}
	}

	if(tx_pipe->mode == ACCESS_PIPE_RW || tx_pipe->mode == ACCESS_PIPE_WRITE){
		pipe->write_curbuf = tx_pipe->write_curbuf;
		wakeup_readers = 1;
	}

	if(tx_pipe->mode == ACCESS_PIPE_RW || tx_pipe->mode == ACCESS_PIPE_READ){
		pipe->read_curbuf = tx_pipe->read_curbuf;
		wakeup_writers = 1;
	}

	// Wake up any waiters.  This is a bit sloppy and imprecise, but should work.
	wake_up_interruptible(&pipe->wait);
	if(wakeup_readers)
		kill_fasync(&pipe->fasync_readers, SIGIO, POLL_IN);
	if(wakeup_writers)
		kill_fasync(&pipe->fasync_writers, SIGIO, POLL_IN);

	free_tx_pipe(tx_pipe);
}

static void pipefs_abort(struct _inode *_inode, enum access_mode mode)
{
	struct pipe_inode_info *pipe = parent(_inode)->i_pipe;
	struct tx_pipe_data *tx_pipe = NULL;

	/* If we have a dangling reference to a freed pipe, that is
	 * ok.  A clearer early release might be better.
	 */
	if(!pipe)
		return;


	list_for_each_entry(tx_pipe, &pipe->active_tx_list, list){
		if(tx_pipe->transaction == current->transaction){
			list_del(&tx_pipe->list);
			free_tx_pipe(tx_pipe);
			break;
		}
	}

	list_for_each_entry(tx_pipe, &pipe->aborted_tx_list, list){
		if(tx_pipe->transaction == current->transaction){
			list_del(&tx_pipe->list);
			free_tx_pipe(tx_pipe);
			break;
		}
	}
}

static struct inode_operations pipefs_inode_operations = {
	.commit         = pipefs_commit,
	.abort          = pipefs_abort,
};

static struct inode * get_pipe_inode(void)
{
	struct inode *inode = new_inode(pipe_mnt->mnt_sb);
	struct _inode *_inode;
	struct pipe_inode_info *pipe;

	if (!inode)
		goto fail_inode;

	pipe = alloc_pipe_info(inode);
	if (!pipe)
		goto fail_iput;

	inode->i_pipe = pipe;
	_inode = tx_cache_get_inode(inode);

	_inode->i_op = &pipefs_inode_operations;

	pipe->readers = pipe->writers = 1;
	_inode->i_fop = &rdwr_pipe_fops;

	/*
	 * Mark the inode dirty from the very beginning,
	 * that way it will never be moved to the dirty
	 * list because "mark_inode_dirty()" will think
	 * that it already _is_ on the dirty list.
	 */
	inode->i_state = I_DIRTY;
	_inode->i_mode = S_IFIFO | S_IRUSR | S_IWUSR;
	_inode->i_uid = current->fsuid;
	_inode->i_gid = current->fsgid;
	_inode->i_atime = _inode->i_mtime = _inode->i_ctime = CURRENT_TIME;

	return inode;

fail_iput:
	iput(inode);

fail_inode:
	return NULL;
}

struct file *create_write_pipe(void)
{
	int err;
	struct inode *inode;
	struct _inode *_inode;
	struct file *f;
	struct _file *_f;
	struct dentry *dentry;
	struct _dentry *_dentry;
	struct qstr name = { .name = "" };

	f = get_empty_filp();
	if (!f)
		return ERR_PTR(-ENFILE);
	err = -ENFILE;
	inode = get_pipe_inode();
	if (!inode)
		goto err_file;

	_inode = tx_cache_get_inode(inode);

	err = -ENOMEM;
	dentry = d_alloc(tx_cache_get_dentry(pipe_mnt->mnt_sb->s_root), &name);
	if (!dentry)
		goto err_inode;

	_dentry = tx_cache_get_dentry(dentry);
	_dentry->d_op = &pipefs_dentry_operations;
	/*
	 * We dont want to publish this dentry into global dentry hash table.
	 * We pretend dentry is already hashed, by unsetting DCACHE_UNHASHED
	 * This permits a working /proc/$pid/fd/XXX on pipes
	 */
	_dentry->d_flags &= ~DCACHE_UNHASHED;
	d_instantiate(_dentry, _inode);
	_f = tx_cache_get_file(f);
	_f->f_path.mnt = mntget(pipe_mnt);
	_f->f_path.dentry = dentry;
	f->f_mapping = _inode->i_mapping;

	_f->f_flags = O_WRONLY;
	f->f_op = &write_pipe_fops;
	_f->f_mode = FMODE_WRITE;
	_f->f_version = 0;

	return f;

 err_inode:
	free_pipe_info(inode);
	iput(inode);
 err_file:
	put_filp(f);
	return ERR_PTR(err);
}

void free_write_pipe(struct file *f)
{
	struct _file *_f = tx_cache_get_file_ro(f);
	struct inode *inode = (f_get_dentry(_f))->d_inode;
	free_pipe_info(inode);
	dput(_f->f_path.dentry);
	mntput(_f->f_path.mnt);
	put_filp(f);
}

struct file *create_read_pipe(struct file *wrf)
{
	struct file *f = get_empty_filp();
	struct _file *_f, *_wrf;
	if (!f)
		return ERR_PTR(-ENFILE);

	_f = tx_cache_get_file(f);
	/* Grab pipe from the writer */
	_wrf = tx_cache_get_file_ro(wrf);
	_f->f_path.mnt = mntget(_wrf->f_path.mnt);
	_f->f_path.dentry = dget(_wrf->f_path.dentry);
	f->f_mapping = d_get_inode(f_get_dentry(_wrf))->i_mapping;

	_f->f_pos = 0;
	_f->f_flags = O_RDONLY;
	f->f_op = &read_pipe_fops;
	_f->f_mode = FMODE_READ;
	_f->f_version = 0;

	return f;
}

int do_pipe(int *fd)
{
	struct file *fw, *fr;
	int error;
	int fdw, fdr;
	struct _file *_fr;

	fw = create_write_pipe();
	if (IS_ERR(fw))
		return PTR_ERR(fw);
	fr = create_read_pipe(fw);
	error = PTR_ERR(fr);
	if (IS_ERR(fr))
		goto err_write_pipe;

	error = get_unused_fd();
	if (error < 0)
		goto err_read_pipe;
	fdr = error;

	error = get_unused_fd();
	if (error < 0)
		goto err_fdr;
	fdw = error;

	error = audit_fd_pair(fdr, fdw);
	if (error < 0)
		goto err_fdw;

	fd_install(fdr, fr);
	fd_install(fdw, fw);
	fd[0] = fdr;
	fd[1] = fdw;

	return 0;

 err_fdw:
	put_unused_fd(fdw);
 err_fdr:
	put_unused_fd(fdr);
 err_read_pipe:
	_fr = tx_cache_get_file_ro(fr);
	dput(_fr->f_dentry);
	mntput(_fr->f_vfsmnt);
	put_filp(fr);
 err_write_pipe:
	free_write_pipe(fw);
	return error;
}

/*
 * pipefs should _never_ be mounted by userland - too much of security hassle,
 * no real gain from having the whole whorehouse mounted. So we don't need
 * any operations on the root directory. However, we need a non-trivial
 * d_name - pipe: will go nicely and kill the special-casing in procfs.
 */
static int pipefs_get_sb(struct file_system_type *fs_type,
			 int flags, const char *dev_name, void *data,
			 struct vfsmount *mnt)
{
	return get_sb_pseudo(fs_type, "pipe:", NULL, PIPEFS_MAGIC, mnt);
}

static struct file_system_type pipe_fs_type = {
	.name		= "pipefs",
	.get_sb		= pipefs_get_sb,
	.kill_sb	= kill_anon_super,
};

static int __init init_pipe_fs(void)
{
	int err = register_filesystem(&pipe_fs_type);

	if (!err) {
		pipe_mnt = kern_mount(&pipe_fs_type);
		if (IS_ERR(pipe_mnt)) {
			err = PTR_ERR(pipe_mnt);
			unregister_filesystem(&pipe_fs_type);
		}
	}

	tx_pipe_cachep = kmem_cache_create("tx_pipe_inode_info_struct",
					   sizeof(struct tx_pipe_data),
					   0, SLAB_HWCACHE_ALIGN | SLAB_DESTROY_BY_RCU,
					   NULL, NULL);

	return err;
}

static void __exit exit_pipe_fs(void)
{
	unregister_filesystem(&pipe_fs_type);
	mntput(pipe_mnt);
}

fs_initcall(init_pipe_fs);
module_exit(exit_pipe_fs);
