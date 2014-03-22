#ifndef __LINUX_PREEMPT_H
#define __LINUX_PREEMPT_H

/*
 * include/linux/preempt.h - macros for accessing and manipulating
 * preempt_count (used for kernel preemption, interrupt count, etc.)
 */

#include <linux/thread_info.h>
#include <linux/linkage.h>
#include <linux/osamagic.h>

#ifdef CONFIG_DEBUG_PREEMPT
  extern void fastcall add_preempt_count(int val);
  extern void fastcall sub_preempt_count(int val);
#else
# define add_preempt_count(val)	do { preempt_count() += (val); \
		preempt_count2() += (val);		       \
	} while (0)
# define sub_preempt_count(val)	do { preempt_count() -= (val); \
		preempt_count2() -= (val);		       \
	} while (0)
#endif

#define inc_preempt_count() add_preempt_count(1)
#define dec_preempt_count() sub_preempt_count(1)

#define preempt_count()	(current_thread_info()->preempt_count)
#define preempt_count2()(current_thread_info()->preempt_count2)

#ifdef CONFIG_PREEMPT

asmlinkage void preempt_schedule(void);

#define preempt_disable() \
do { \
	inc_preempt_count(); \
	barrier(); \
} while (0)

#define preempt_enable_no_resched() \
do { \
	barrier(); \
	dec_preempt_count(); \
} while (0)

#define preempt_check_resched() \
do { \
	if (unlikely(test_thread_flag(TIF_NEED_RESCHED))) \
		preempt_schedule(); \
} while (0)

#define preempt_enable() \
do { \
	preempt_enable_no_resched(); \
	barrier(); \
	preempt_check_resched(); \
} while (0)

#else

#ifdef CONFIG_TX_KSTM

#define preempt_disable()		do { preempt_count2() += 1; } while (0)
#define preempt_enable_no_resched()	do { preempt_count2() -= 1; } while (0)
#define preempt_enable()		do { preempt_count2() -= 1; } while (0)

#else

#define preempt_disable()		do { } while (0)
#define preempt_enable_no_resched()	do { } while (0)
#define preempt_enable()		do { } while (0)

#endif

#define preempt_check_resched()		do { } while (0)

#endif

#endif /* __LINUX_PREEMPT_H */
