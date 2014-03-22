#include <linux/transaction.h>
#include <asm/i387.h>

// This struct is for passing argument from x86-64 asm code to C code
// only by stack (without using %rdi, %rsi, and so on)
struct hook_args{
	unsigned long rax;
	struct pt_regs regs;
};

// This should be called from the interrupt handling path before
// getting to the syscall table

//
// Note that the pt_regs is now a pointer unlike 32bit version
//
void preSyscallHook64(struct hook_args args){
	/* Let the simulator know what system call we are making */
	OSA_CUR_SYSCALL(current->pid, args.rax);

#ifdef CONFIG_TX_SYSCALLS

	if(current->transactional){
		int status = atomic_read(&current->transaction->status);
		// We are already in a tx
		
	   	// We don't currently support nesting
		BUG_ON(args.rax == __NR_xbegin);

		if(current->usertm){
			/* Re-Checkpoint the kernel stack and such for
			 * usertm so that we drop into the entry point
			 * for this system call, rather than
			 * sys_xbegin, which is only safe if the
			 * kernel rolls back the task's address
			 * space.
			 */
			current->eax = args.rax;
						//
			// because of AMD64 calling convention
			// we cannot use just &rax
			// 
			current->eax = &(args.rax);
			current->regs_checkpoint = args.regs;
			current->regsp = &(args.regs);
		}

		/* Do a quicker retry of the tx if we realize that we are aborted */
		
		if(status == TX_ABORTED
		   || status == TX_ABORTING){
			if(current->usertm){
				if(args.rax != __NR_xend
				   && args.rax != __NR_xabort){
					args.rax = __NR_xbogus;
					/* Not sure this is strictly necessary, but better safe... */
					set_thread_flag(TIF_IRET);
					return;
				}
			} else
				abort_self(NULL, 0); /* doesn't return */
		}
		
		checkWhitelist(&args.rax);
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

		if(args.rax == __NR_xbegin
		   || user_htm){

			stats_begin_tx(args.rax);

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
			current->eax = args.rax;
			current->eaxp = &(args.rax);
			
			current->regs_checkpoint = args.regs;
			current->regsp = &(args.regs);
			
			/* Checkpoint the register state Save
			 * register and kernel stack
			 * checkpoint pt_regs is exactly this
			 * - need to memcpy it, though, as the
			 * stack will go away

			 */
			__asm__ __volatile__ ("movq 8(%%rbp), %0\n\t" 
					      : "=g"(current->return_program_counter) 
					      : : "memory");
			__asm__ __volatile__ ("movq (%%rbp), %0\n\t" 
					      : "=g"(current->return_frame_pointer)
					      : : "memory");
			__asm__ __volatile__ ("movq %%rbp, %0\n\t" 
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
				restore_fpu_checking(&(current->thread.i387.fxsave));

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
	stats_begin_tx(args.rax);
	current->eax = args.rax;
#endif
}

long postSyscallHook64(struct hook_args args){

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
		args.regs = current->regs_checkpoint;
		args.rax = current->eax;
		__asm__ __volatile__ ("movq %0, %%rax\n\t" \
				      "movq %%rax, 8(%%rbp)\n\t"
				      : 
				      : "g"(current->return_program_counter)
				      : "memory", "%rax");

		/* Learning the hard way: Every time we dick with registers to
		 * do an abort, we must use iret.  Otherwise the user process
		 * actually expects to get live register values back from the
		 * kernel via calling conventions.
		 */
		set_thread_flag(TIF_IRET);

		// Including floating point/mmx if used
		if(current->thread_info_status & TS_USEDFPU){
			current->thread = current->thread_checkpoint;
			restore_fpu_checking(&(current->thread.i387.fxsave));
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
