#include <linux/transaction.h>
#include <asm/i387.h>
#include <asm/uaccess.h>

// This should be called from the interrupt handling path before
// getting to the syscall table
asmlinkage void preSyscallHook(unsigned long eax, struct pt_regs regs){
	/* Let the simulator know what system call we are making */
	OSA_CUR_SYSCALL(current->pid, eax);

#ifdef CONFIG_TX_SYSCALLS

	if(current->transactional){
		int status = atomic_read(&current->transaction->status);
		// We are already in a tx
		
	   	// We don't currently support nesting
		BUG_ON(eax == __NR_xbegin);

		if(current->usertm){
			/* Re-Checkpoint the kernel stack and such for
			 * usertm so that we drop into the entry point
			 * for this system call, rather than
			 * sys_xbegin, which is only safe if the
			 * kernel rolls back the task's address
			 * space.
			 */
			current->eax = eax;
			current->eaxp = &eax;
			
			current->regs_checkpoint = regs;
			current->regsp = &regs;
		}

		/* Do a quicker retry of the tx if we realize that we are aborted */
		
		if(status == TX_ABORTED
		   || status == TX_ABORTING){
			if(current->usertm){
				if(eax != __NR_xend
				   && eax != __NR_xabort){
					eax = __NR_xbogus;
					current->xbogus_return_code = -ETXABORT;
					/* Not sure this is strictly necessary, but better safe... */
					set_thread_flag(TIF_IRET);
					return;
				}
			} else
				abort_self(NULL, 0); /* doesn't return */
		}
		
		checkWhitelist(&eax);

	} else {
		int user_htm = XGETTXID_USER();
		/* See if we are starting a new tx, either through an
		 * explicit xbegin or and implicit xbegin via a
		 * user-level hardware transaction.
		 *
		 *
		 * Magic instruction
		 * approximates something sensible, like a register push onto
		 * the interrupt handling stack.
		 * 
		 * Also, punt on xpush in userland.
		 */

		if(eax == __NR_xbegin
		   || user_htm){

			stats_begin_tx(eax);

			common_tx_reset();			
			current->transaction->count = 0;
			/* Mark task as transactional if we are an
			 * HTM, as sys_xbegin isn't called 
			 */
			current->transactional = user_htm;
			current->usertm = user_htm;
			current->xsw = NULL;
			current->transaction->autoretry = 0;
			current->transaction->abortWithErr = 0;
			
			current->transaction->timestamp 
				= atomic_inc_return(&timestamp_counter);
			
			if(user_htm)
				/* Noop without USER_HTM enabled */
				XSET_USER_TM_SYSCALL_BIT(1);

			/* Checkpoint the kernel stack and such */
			current->eax = eax;
			current->eaxp = &eax;
			
			current->regs_checkpoint = regs;
			current->regsp = &regs;
			
			/* Checkpoint the register state Save
			 * register and kernel stack
			 * checkpoint pt_regs is exactly this
			 * - need to memcpy it, though, as the
			 * stack will go away
			 */
			__asm__ __volatile__ ("movl 4(%%ebp), %0\n\t" 
					      : "=g"(current->return_program_counter) 
					      : : "memory");
			__asm__ __volatile__ ("movl (%%ebp), %0\n\t" 
					      : "=g"(current->return_frame_pointer)
					      : : "memory");
			__asm__ __volatile__ ("movl %%ebp, %0\n\t" 
					      : "=g"(current->return_stack_pointer)
					      : : "memory");
				
			// Save FPU and MMX regs, if needed
			// Checkpoint TS_USEDFPU
			// If used, 
			// Checkpoint current->thread.i387.fsave
			if(!user_htm && 
			   task_thread_info(current)->status & TS_USEDFPU){
				prepare_to_copy(current);
				current->thread_checkpoint = current->thread;
				current->thread_info_status = 
					task_thread_info(current)->status;
				
				/* Re-set current->status and
				 * reload the registers
				 * (fnsave doesn't save state
				 * :( ) 
				 */
				restore_fpu(current);
			}
			// End FPU/MMX save / i386-specific code
		} else {
			/* Always update the timestamp on a notx
			 * system call for fair asymmetric contention
			 */
			current->transaction->timestamp = 
				atomic_inc_return(&timestamp_counter);
			return;	
		}	
	}
#else
	stats_begin_tx(eax);
	current->eax = eax;
#endif
}

asmlinkage long postSyscallHook(volatile unsigned long eax, volatile struct pt_regs regs){

	/* Not really zero but whatev's */
	OSA_CUR_SYSCALL(current->pid, 0);

#ifdef CONFIG_TX_SYSCALLS

	if(current->xsw){
		int status = atomic_read(&current->transaction->status);
		put_user(status, current->xsw);
	}

	if(unlikely(current->need_autoretry)){
		// Put back the checkpointed registers.  This drops you just
		// after the call to beginTransaction.  Note that
		// beginTransaction() doesn't get reexecuted.
		regs = current->regs_checkpoint;
		eax = current->eax;
		__asm__ __volatile__ ("movl %0, %%eax\n\t" \
				      "movl %%eax, 4(%%ebp)\n\t" : : "g"(current->return_program_counter) : "memory", "%eax");

		/* Learning the hard way: Every time we dick with registers to
		 * do an abort, we must use iret.  Otherwise the user process
		 * actually expects to get live register values back from the
		 * kernel via calling conventions.
		 */
		set_thread_flag(TIF_IRET);

		// Including floating point/mmx if used
		if(current->thread_info_status & TS_USEDFPU){
			current->thread = current->thread_checkpoint;
			restore_fpu(current);
			return -1;
		}
		current->need_autoretry = 0;
	}
	return 0;
#else
	stats_end_tx(current->eax);
	current->eax = 0;
	return 0;
#endif
}
