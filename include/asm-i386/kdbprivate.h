#ifndef	_ASM_KDBPRIVATE_H
#define _ASM_KDBPRIVATE_H

/*
 * Kernel Debugger Architecture Dependent Private Headers
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (c) 1999-2006 Silicon Graphics, Inc.  All Rights Reserved.
 */

typedef unsigned char kdb_machinst_t;

/*
 * KDB_MAXBPT describes the total number of breakpoints
 * supported by this architecure.
 */
#define KDB_MAXBPT	16

/*
 * KDB_MAXHARDBPT describes the total number of hardware
 * breakpoint registers that exist.
 */
#define KDB_MAXHARDBPT	 4

/* Maximum number of arguments to a function  */
#define KDBA_MAXARGS	16

/*
 * Platform specific environment entries
 */
#define KDB_PLATFORM_ENV	"IDMODE=x86", "BYTESPERWORD=4", "IDCOUNT=16"

/*
 * Support for ia32 debug registers
 */
typedef struct _kdbhard_bp {
	kdb_machreg_t	bph_reg;	/* Register this breakpoint uses */

	unsigned int	bph_free:1;	/* Register available for use */
	unsigned int	bph_data:1;	/* Data Access breakpoint */

	unsigned int	bph_write:1;	/* Write Data breakpoint */
	unsigned int	bph_mode:2;	/* 0=inst, 1=write, 2=io, 3=read */
	unsigned int	bph_length:2;	/* 0=1, 1=2, 2=BAD, 3=4 (bytes) */
} kdbhard_bp_t;

#define IA32_BREAKPOINT_INSTRUCTION	0xcc

#define DR6_BT  0x00008000
#define DR6_BS  0x00004000
#define DR6_BD  0x00002000

#define DR6_B3  0x00000008
#define DR6_B2  0x00000004
#define DR6_B1  0x00000002
#define DR6_B0  0x00000001
#define DR6_DR_MASK  0x0000000F

#define DR7_RW_VAL(dr, drnum) \
       (((dr) >> (16 + (4 * (drnum)))) & 0x3)

#define DR7_RW_SET(dr, drnum, rw)                              \
       do {                                                    \
	       (dr) &= ~(0x3 << (16 + (4 * (drnum))));         \
	       (dr) |= (((rw) & 0x3) << (16 + (4 * (drnum)))); \
       } while (0)

#define DR7_RW0(dr)		DR7_RW_VAL(dr, 0)
#define DR7_RW0SET(dr,rw)	DR7_RW_SET(dr, 0, rw)
#define DR7_RW1(dr)		DR7_RW_VAL(dr, 1)
#define DR7_RW1SET(dr,rw)	DR7_RW_SET(dr, 1, rw)
#define DR7_RW2(dr)		DR7_RW_VAL(dr, 2)
#define DR7_RW2SET(dr,rw)	DR7_RW_SET(dr, 2, rw)
#define DR7_RW3(dr)		DR7_RW_VAL(dr, 3)
#define DR7_RW3SET(dr,rw)	DR7_RW_SET(dr, 3, rw)


#define DR7_LEN_VAL(dr, drnum) \
       (((dr) >> (18 + (4 * (drnum)))) & 0x3)

#define DR7_LEN_SET(dr, drnum, rw)                             \
       do {                                                    \
	       (dr) &= ~(0x3 << (18 + (4 * (drnum))));         \
	       (dr) |= (((rw) & 0x3) << (18 + (4 * (drnum)))); \
       } while (0)

#define DR7_LEN0(dr)		DR7_LEN_VAL(dr, 0)
#define DR7_LEN0SET(dr,len)	DR7_LEN_SET(dr, 0, len)
#define DR7_LEN1(dr)		DR7_LEN_VAL(dr, 1)
#define DR7_LEN1SET(dr,len)	DR7_LEN_SET(dr, 1, len)
#define DR7_LEN2(dr)		DR7_LEN_VAL(dr, 2)
#define DR7_LEN2SET(dr,len)	DR7_LEN_SET(dr, 2, len)
#define DR7_LEN3(dr)		DR7_LEN_VAL(dr, 3)
#define DR7_LEN3SET(dr,len)	DR7_LEN_SET(dr, 3, len)

#define DR7_G0(dr)    (((dr)>>1)&0x1)
#define DR7_G0SET(dr) ((dr) |= 0x2)
#define DR7_G0CLR(dr) ((dr) &= ~0x2)
#define DR7_G1(dr)    (((dr)>>3)&0x1)
#define DR7_G1SET(dr) ((dr) |= 0x8)
#define DR7_G1CLR(dr) ((dr) &= ~0x8)
#define DR7_G2(dr)    (((dr)>>5)&0x1)
#define DR7_G2SET(dr) ((dr) |= 0x20)
#define DR7_G2CLR(dr) ((dr) &= ~0x20)
#define DR7_G3(dr)    (((dr)>>7)&0x1)
#define DR7_G3SET(dr) ((dr) |= 0x80)
#define DR7_G3CLR(dr) ((dr) &= ~0x80)

#define DR7_L0(dr)    (((dr))&0x1)
#define DR7_L0SET(dr) ((dr) |= 0x1)
#define DR7_L0CLR(dr) ((dr) &= ~0x1)
#define DR7_L1(dr)    (((dr)>>2)&0x1)
#define DR7_L1SET(dr) ((dr) |= 0x4)
#define DR7_L1CLR(dr) ((dr) &= ~0x4)
#define DR7_L2(dr)    (((dr)>>4)&0x1)
#define DR7_L2SET(dr) ((dr) |= 0x10)
#define DR7_L2CLR(dr) ((dr) &= ~0x10)
#define DR7_L3(dr)    (((dr)>>6)&0x1)
#define DR7_L3SET(dr) ((dr) |= 0x40)
#define DR7_L3CLR(dr) ((dr) &= ~0x40)

#define DR7_GD          0x00002000              /* General Detect Enable */
#define DR7_GE          0x00000200              /* Global exact */
#define DR7_LE          0x00000100              /* Local exact */

#define DR_TYPE_EXECUTE	0x0
#define DR_TYPE_WRITE	0x1
#define DR_TYPE_IO	0x2
#define DR_TYPE_RW	0x3

extern kdb_machreg_t kdba_getdr6(void);
extern void kdba_putdr6(kdb_machreg_t);

extern kdb_machreg_t kdba_getdr7(void);

/*
 * Support for setjmp/longjmp
 */
#define JB_BX   0
#define JB_SI   1
#define JB_DI   2
#define JB_BP   3
#define JB_SP   4
#define JB_PC   5

typedef struct __kdb_jmp_buf {
	unsigned long   regs[6];	/* kdba_setjmp assumes fixed offsets here */
} kdb_jmp_buf;

extern int asmlinkage kdba_setjmp(kdb_jmp_buf *);
extern void asmlinkage kdba_longjmp(kdb_jmp_buf *, int);
#define kdba_setjmp kdba_setjmp

extern kdb_jmp_buf  *kdbjmpbuf;

/* Arch specific data saved for running processes */

struct kdba_running_process {
	long esp;	/* CONFIG_4KSTACKS may be on a different stack */
	long eip;	/* eip when esp was set */
};

static inline
void kdba_save_running(struct kdba_running_process *k, struct pt_regs *regs)
{
	k->esp = current_stack_pointer;
	__asm__ __volatile__ ( " lea 1f,%%eax; movl %%eax,%0 ; 1: " : "=r"(k->eip) : : "eax" );
}

static inline
void kdba_unsave_running(struct kdba_running_process *k, struct pt_regs *regs)
{
}

struct kdb_activation_record;
extern void kdba_get_stack_info_alternate(kdb_machreg_t addr, int cpu,
					  struct kdb_activation_record *ar);

extern void kdba_wait_for_cpus(void);

extern fastcall void kdb_interrupt(void);

#define	KDB_INT_REGISTERS	8


#endif	/* !_ASM_KDBPRIVATE_H */
