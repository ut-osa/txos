#ifndef _LINUX_DEBUGTX_H
#define _LINUX_DEBUGTX_H
#include <linux/osamagic.h>

/* Generalized Breakpoints */
#ifdef CONFIG_KDB
extern int kdb_on;
extern volatile int kdb_initial_cpu;
#define KDB_IS_RUNNING() (kdb_initial_cpu != -1)
#define KDB_ENTER()	do {if (kdb_on && !KDB_IS_RUNNING()) { asm("\tint $129\n"); }} while(0)
#define DEBUG_BREAKPOINT() KDB_ENTER()
#elif (defined CONFIG_OSA)
#define DEBUG_BREAKPOINT() OSA_MAGIC(OSA_BREAKSIM)
#else
#define DEBUG_BREAKPOINT()
#endif

#endif
