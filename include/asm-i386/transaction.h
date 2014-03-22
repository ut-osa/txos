#ifndef _ASM_I386_TRANSACTION_H_
#define _ASM_I386_TRANSACTION_H_

static inline void jump_out_of_stack(void){
	__asm__ __volatile__ (
			      "movl %2, %%eax\n\t"			\
			      "movl %%eax, %%ebp\n\t"			\
			      "movl %0, %%eax\n\t"			\
			      "movl %%eax, 4(%%ebp)\n\t"		\
			      "movl %1, %%eax\n\t"			\
			      "movl %%eax, (%%ebp)\n\t"			\
			      "movl %%ebp, %%esp\n\t"			\
			      "pop %%ebp\n\t"				\
			      "ret\n\t"					\
			      : : "g"(current->return_program_counter),
				"g"(current->return_frame_pointer),
				"g"(current->return_stack_pointer)
			      : "memory", "%eax");
}


#endif // _ASM_I386_TRANSACTION_H_
