#ifndef _ASM_X86_64_TRANSACTION_H_
#define _ASM_X86_64_TRANSACTION_H_

static inline void jump_out_of_stack(void){
	__asm__ __volatile__ (
		"movq %2, %%rax\n\t"					\
		"movq %%rax, %%rbp\n\t"					\
		"movq %0, %%rax\n\t"					\
		"movq %%rax, 8(%%rbp)\n\t"				\
		"movq %1, %%rax\n\t"					\
		"movq %%rax, (%%rbp)\n\t"				\
		"movq %%rbp, %%rsp\n\t"					\
		"popq %%rbp\n\t"					\
		"ret\n\t"						\
		: : "g"(current->return_program_counter), 
		  "g"(current->return_frame_pointer), 
		  "g"(current->return_stack_pointer)
		: "memory", "%rax");
}


#endif // _ASM_X86_64_TRANSACTION_H_
