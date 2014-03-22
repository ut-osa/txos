//////////////////////////////////////////////////////////
// Transactional defines for linux/simics cooperation

#ifndef _OSAMAGIC_H
#define _OSAMAGIC_H
#include <linux/spinlock_types.h>

// no need to have OS visibility built in
// to make use of magic breakpoints!
// -----------------------------------
// #ifdef CONFIG_OS_VISIBILITY

#define OSA_ILLEGAL 0
#define OSA_INIT_STAT 0 /* Jungwoo! */
#define OSA_PRINT_STR_VAL 1
#define OSA_CLEAR_STAT 2
#define OSA_OUTPUT_STAT 3
#define OSA_KILLSIM 4
#define OSA_BREAKSIM 5
// Intervening codes are used in sws/modules/osatxm/osamagic.h
#define OSA_PRINT_NUM_CHAR 9 /* Print X characters */
#define OSA_PRINT_STACK_TRACE 20

#define SYNCCHAR_CLEAR_MAP          16
#define SYNCCHAR_LOAD_MAP           17


/* 100-199 OS Visibility and simulator debugging */
#define OSA_SCHED_STR 100
#define OSA_FORK_STR 101
#define OSA_TIMER_STR 102
#define OSA_KSTAT_STR 103
#define OSA_EXIT_CODE 104
#define OSA_REGISTER_SPINLOCK_VAL   105
#define OSA_ENTER_SCHED_VAL         106
#define OSA_EXIT_SWITCH_TO_VAL      107
#define OSA_KSTAT_2_4               108
#define OSA_TASK_STATE_VAL          109
#define OSA_CUR_SYSCALL_VAL         110
#define OSA_PROTECT_ADDR_VAL        111
#define OSA_UNPROTECT_ADDR_VAL      112
#define OSA_PROTECT_SUSPEND_VAL     113
#define OSA_PROTECT_RESUME_VAL      114
#define OSA_LOG_SIGSEGV_VAL         115

/* 200-299 osatxm hackery */
#define OSA_XSETPID_VAL             200
#define OSA_NEW_PROC_VAL            201
#define OSA_SINK_AREA_VAL           202

/* 300-399 os priority */
#define OSA_PROC_PRIO_VAL           300  
#define OSA_PAGE_FAULT_VAL          301  
#define OSA_ACTIVETX_DATA_VAL       302
#define OSA_ACTIVETX_PARAM_VAL      303
#define OSA_GET_RANDOM_VAL          304
#define OSA_GET_CM_POLICY_VAL       305
#define OSA_SET_CM_POLICY_VAL       306
#define OSA_GET_CM_POLCHG_THRESH_VAL 307
#define OSA_GET_BACKOFF_POLICY_VAL  308
#define OSA_SET_BACKOFF_POLICY_VAL  309
#define OSA_GET_BK_POLCHG_THRESH_VAL 310

/* 500-599 ??? */
#define OSA_ACTTX_EXISTS            543
#define OSA_ACTTX_RESTARTS          544
#define OSA_ACTTX_SIZE              545
#define OSA_ACTTX_OVERFLOWED        546
#define OSA_ACTTX_COMPLEXCONF       547
#define OSA_ACTTX_LONGRUNNING       548
#define OSA_ACTTX_STALLED           549    
#define OSA_PINNED_CACHECOLD_TX     550
#define OSA_ACTTX_DESCHEDTHRESH     551
#define OSA_ACTTX_RESTARTAVG        552
#define OSA_ACTTX_CONFLICTSET       553    

/* 600-699 ??? */
#define OSA_THREAD_PROF_DATA_VAL    600
#define OSA_THREAD_PROF_RESTARTS    601
#define OSA_THREAD_PROF_SIZE        602 
#define OSA_THREAD_PROF_OVERFLOWED  603 
#define OSA_THREAD_PROF_COMPLEXCONF 604 
#define OSA_THREAD_PROF_LONGRUNNING 605 
#define OSA_THREAD_PROF_UNIQUE_TX   606
#define OSA_THREAD_PROF_CURRENT_RESTARTS 607
#define OSA_THREAD_PROF_BKCYC_TX    608
#define OSA_SCHEDULER_MODE          609
#define OSA_ACTTX_HASCTMDEPS        610
#define OSA_ACTTX_ACTTXXPUSHED      611
#define OSA_ACTTX_SETNODEPS         612
#define OSA_GET_MAX_CONFLICTER_VAL  650
#define OSA_CLEAR_MAX_CONFLICTER_VAL  651
#define OSA_LOG_SCHEDULE_VAL          670
#define OSA_LOG_ANTI_CONFLICT         671
#define OSA_LOG_RESTART_DESCHED       672
#define OSA_SCHED_PARAMETER_VAL       677
#define OSA_TX_STATE_VAL              678
#define OSA_KILL_TX_VAL               679
#define OSA_SET_VCONF_ADDR_BUF_VAL    680

/* 700-799 ??? */
#define OSA_TXMIGRATION_MODE_VAL    700

#define OSA_SET_LOG_BASE            800
#define OSA_GET_LOG_BASE            801

/* 900-999 ??? */
#define OSA_PFTYP_PAGE_FAULT_VAL    987
#define OSA_PFTYP_MAJOR_FAULT_VAL   988
#define OSA_PFTYP_MIGRATE_FAULT_VAL 989

/* 1100 Flag that we are past bios (not actually booted).  Really
 * belongs in os visibility code.
 */
#define OSA_KERNEL_BOOT             1100

/* 1200-1204 Cxspin */
#define OSA_CXSPIN_INFO_TX          1201
#define OSA_CXSPIN_INFO_NOTX        1202
#define OSA_CXSPIN_INFO_IOTX        1203
#define OSA_CXSPIN_INFO_IONOTX      1204

/* 1206 - 1299 opcodes */
#define OSA_OP_XGETTXID             1206
#define OSA_OP_XBEGIN               1207
#define OSA_OP_XBEGIN_IO            1208
#define OSA_OP_XEND                 1209
#define OSA_OP_XRETRY               1210
#define OSA_OP_XRETRY_EX            1211
#define OSA_OP_XCAS                 1212
#define OSA_OP_XPUSH                1213
#define OSA_OP_XPOP                 1214
#define OSA_OP_XTEST                1215
#define OSA_OP_XEND_USER            1216
#define OSA_OP_XABORT_USER          1217
#define OSA_OP_XGETTXID_USER        1218
#define OSA_OP_SET_USER_SYSCALL_BIT 1219
#define OSA_OP_GET_USER_SYSCALL_BIT 1220

#define OSA_TXCACHE_TRACE           1300

#define OSA_USER_OVERFLOW_BEGIN     1400
#define OSA_USER_OVERFLOW_END       1401

#define OSA_RANDOM_SHUTDOWN_BEGIN   1501
#define OSA_RANDOM_SHUTDOWN_UNSAFE  1502
#define OSA_RANDOM_SHUTDOWN_SAFE    1503


#ifdef CONFIG_OSA

#define OSA_TASK_STATE(pid, state)					\
	asm volatile ("xchg %%bx, %%bx "				\
		      : /*no output*/					\
		      : "S"(OSA_TASK_STATE_VAL), "b"(pid), "c"(state)	\
		)

#define OSA_TX_STATE(txid, buffer, confaddr)				\
	asm volatile ("xchg %%bx, %%bx "				\
		      : /*no output*/					\
		      : "S"(OSA_TX_STATE_VAL), "b"(txid), "c"(buffer), "a"(confaddr) \
		)

#define OSA_KILL_TX(txid)					     \
	({ int ret; asm volatile ("xchg %%bx, %%bx "		     \
				  : "=b"(ret)			     \
				  : "S"(OSA_KILL_TX_VAL), "b"(txid)  \
				  : "memory"); ret; })

#define OSA_SET_VCONF_ADDR_BUF(ncpu, vaddr)				\
	asm volatile ("xchg %%bx, %%bx "				\
		      : /*no output*/					\
		      : "S"(OSA_SET_VCONF_ADDR_BUF_VAL), "b"(ncpu), "c"(vaddr) \
		)

#define OSA_PRINT(str,num)						\
	asm volatile ("xchg %%bx, %%bx "				\
		      : /*no output*/					\
		      : "b"(str), "c"(num), "S"(OSA_PRINT_STR_VAL)	\
		)

#define OSA_PRINT_NUMCHAR(str,len)					\
	asm volatile ("xchg %%bx, %%bx "				\
		      : /*no output*/					\
		      : "b"(str), "c"(len), "S"(OSA_PRINT_NUM_CHAR)	\
		)

#define OSA_MAGIC(n) do {						\
		asm volatile ("movl %0, %%esi" : : "g" (n) : "esi");	\
		asm volatile ("xchg %bx, %bx"); } while(0)

#define OSA_SCHED(cmdline,pid,len)					\
	asm volatile ("xchg %%bx, %%bx "				\
		      : /*no output*/					\
		      : "b"(cmdline), "c"(pid), "d"(len), "S"(OSA_SCHED_STR) \
		)

#define OSA_FORK(pid,kernel)						\
	asm volatile ("xchg %%bx, %%bx "				\
		      : /*no output*/					\
		      : "b"(pid), "c"(kernel), "S"(OSA_FORK_STR)	\
		)

#define OSA_TIMER()				\
	asm volatile ("xchg %%bx, %%bx "	\
		      : /*no output*/		\
		      : "S"(OSA_TIMER_STR)	\
		)

#define OSA_KSTAT(offset, addr) \
      asm volatile ("xchg %%bx, %%bx " \
                     : /*no output*/ \
                     : "S"(OSA_KSTAT_STR), "b"(offset), "c"(addr) \
                     );

#define OSA_ENTER_SCHED(pid)					\
	asm volatile ("xchg %%bx, %%bx "			\
		      : /*no output*/				\
		      : "S"(OSA_ENTER_SCHED_VAL), "b"(pid)	\
		)

#define OSA_EXIT_SWITCH_TO(pid)					\
	asm volatile ("xchg %%bx, %%bx "			\
		      : /*no output*/				\
		      : "S"(OSA_EXIT_SWITCH_TO_VAL), "b"(pid)	\
		)

#define OSA_EXIT(stk, pid)					\
	asm volatile ("xchg %%bx, %%bx "			\
		      : /*no output*/				\
		      : "S"(OSA_EXIT_CODE), "b"(stk), "c"(pid)	\
		)

static __inline__ unsigned int get_osa_random(void) {
	unsigned int val;
	asm volatile ("xchg %%bx, %%bx\n\t"	\
		      : "=b"(val)		\
		      : "S"(OSA_GET_RANDOM_VAL) \
		);
	return val;
}

#define OSA_CUR_SYSCALL(pid, syscall)	     \
      asm volatile ("xchg %%bx, %%bx " \
                     : /*no output*/ \
		    : "S"(OSA_CUR_SYSCALL_VAL), "b"(pid), "c"(syscall) \
	      );

#define OSA_LOG_SIGSEGV(addr, eip)					\
	asm volatile ("xchg %%bx, %%bx "				\
		    : /*no output*/					\
		    : "S"(OSA_LOG_SIGSEGV_VAL), "b"(addr), "c"(eip)	\
		);

#ifdef CONFIG_OSA_SIMPROTECT

#define OSA_PROTECT_ADDR(addr, len)					\
	asm volatile ("xchg %%bx, %%bx "				\
		      : /*no output*/					\
		      : "S"(OSA_PROTECT_ADDR_VAL), "b"(addr), "c"(len)	\
		)

#define OSA_UNPROTECT_ADDR(addr)				\
	asm volatile ("xchg %%bx, %%bx "			\
		      : /*no output*/				\
		      : "S"(OSA_UNPROTECT_ADDR_VAL), "b"(addr)	\
		)

#define OSA_PROTECT_SUSPEND()				\
	asm volatile ("xchg %%bx, %%bx "		\
		      : /*no output*/			\
		      : "S"(OSA_PROTECT_SUSPEND_VAL)	\
		)

#define OSA_PROTECT_RESUME()				\
	asm volatile ("xchg %%bx, %%bx "		\
		      : /*no output*/			\
		      : "S"(OSA_PROTECT_RESUME_VAL)	\
		)

#else

#define OSA_PROTECT_ADDR(addr, len) 
#define OSA_UNPROTECT_ADDR(addr) 
#define OSA_PROTECT_SUSPEND() 
#define OSA_PROTECT_RESUME() 
#endif

#else // CONFIG_OSA

#define OSA_PRINT(str, num)
#define OSA_PRINT_NUMCHAR(str, len)
#define OSA_MAGIC(n)
#define OSA_SCHED(cmdline, pid, len)
#define OSA_FORK(pid, kernel)
#define OSA_TIMER()
#define OSA_KSTAT(offset, addr)
#define OSA_ENTER_SCHED(pid)
#define OSA_EXIT_SWITCH_TO(pid)
#define OSA_EXIT(stk,pid)
#define OSA_CUR_SYSCALL(pid, syscall)
#define OSA_PROTECT_ADDR(addr, len) 
#define OSA_UNPROTECT_ADDR(addr) 
#define OSA_PROTECT_SUSPEND() 
#define OSA_PROTECT_RESUME() 
#define OSA_LOG_SIGSEGV(addr, eip)   
#define OSA_TX_STATE(pid, buffer, confaddr)
#define OSA_SET_VCONF_ADDR_BUF(ncpu, vaddr)	

static __inline__ unsigned int get_osa_random(void) {
	return 0;
}

#define OSA_TASK_STATE(pid, state)	    
#define OSA_KILL_TX(txid)

#endif // OSA

#ifdef CONFIG_TX

#define OSA_XSETPID(npid, esp, nesp)					\
	asm volatile ("xchg %%bx, %%bx "				\
		      : /*no output*/					\
		      : "b"(npid), "c"(esp), "d"(nesp), "S"(OSA_XSETPID_VAL) \
		)

#define OSA_NEW_PROC(ts, pid)						\
	asm volatile ("xchg %%bx, %%bx "				\
		      : /*no output*/					\
		      : "S"(OSA_NEW_PROC_VAL), "b"(ts), "c"(pid)	\
		)

#define OSA_SINK_AREA(addr)				\
	asm volatile ("xchg %%bx, %%bx "		\
		    : /*no output*/			\
		    : "S"(OSA_SINK_AREA_VAL), "b"(addr) \
	      )

static inline int XGETTXID( void ) {
   int ret;
   asm volatile ("xchg %%bx, %%bx" : "=a"(ret) : "S"(OSA_OP_XGETTXID));
   return ret;
}

#else

#define OSA_XSETPID(npid, esp, nesp)
#define OSA_NEW_PROC(ts, pid)
#define OSA_SINK_AREA(addr)

#endif // CONFIG_TX

#ifdef CONFIG_TX_PROFILE_PROC_PRIO
#define OSA_PROC_PRIO(prio,sched,pid)					\
	asm volatile ("xchg %%bx, %%bx "				\
		      : /*no output*/					\
		      : "b"(prio), "c"(sched), "d"(pid),"S"(OSA_PROC_PRIO_VAL) \
		)
#else
#define OSA_PROC_PRIO(prio,sched,pid) 
#endif // CONFIG_TX_PROFILE_PROC_PRIO

#ifdef CONFIG_TX_MIGRATION_AWARE_SCHEDULER
static __inline__ int get_tx_migration_mode(int mode) {
	asm volatile ("xchg %%bx, %%bx\n\t"		\
		      : "=b"(mode)			\
		      : "S"(OSA_TXMIGRATION_MODE_VAL)	\
		);
   return mode;
}
#else
#define get_tx_migration_mode(mode)
#endif


#ifdef CONFIG_TX_LOG_TM_MODE
static __inline__ unsigned long __osa_get_tx_logbase(void) {
   unsigned long base;
   asm volatile ("xchg %%bx, %%bx\n\t"		\
		 : "=b"(base)			\
		 : "S"(OSA_GET_LOG_BASE)	\
	   );
   return base;
}

static __inline__ void __osa_set_tx_logbase(unsigned long base) {
	asm volatile ("xchg %%bx, %%bx\n\t" 
		      : /* No output */
		      : "b"(base), "S"(OSA_SET_LOG_BASE)	\
		      : "esi", "ebx");
}
#define osa_get_tx_logbase() __osa_get_tx_logbase()
#define osa_set_tx_logbase(x) __osa_set_tx_logbase(x)
#else
#define osa_get_tx_logbase() 
#define osa_set_tx_logbase(x) 
#endif


#ifdef CONFIG_TX_TXAWARE_SCHEDULER
// contention management policies
// must match constants in osatxm.h
// ===============================================
#define CONF_POLICY_NONE            1891
#define CONF_POLICY_POLITE          (CONF_POLICY_NONE+1)
#define CONF_POLICY_KARMA           (CONF_POLICY_NONE+2)
#define CONF_POLICY_ERUPTION        (CONF_POLICY_NONE+3)
#define CONF_POLICY_KINDERGARTEN    (CONF_POLICY_NONE+4)
#define CONF_POLICY_TIMESTAMP       (CONF_POLICY_NONE+5)
#define CONF_POLICY_PUBTIMESTAMP    (CONF_POLICY_NONE+6)
#define CONF_POLICY_POLKA           (CONF_POLICY_NONE+7)
#define CONF_POLICY_PRIORITY        (CONF_POLICY_NONE+8)
#define CONF_POLICY_SIZEMATTERS     (CONF_POLICY_NONE+9)
#define CONF_POLICY_OSPRIO          (CONF_POLICY_NONE+10)

// backoff policies. 
// must match constants in osatxm.h
// ===============================================
#define BACKOFF_POLICY_DONT         5511
#define BACKOFF_POLICY_EXPONENTIAL  (BACKOFF_POLICY_DONT+1)
#define BACKOFF_POLICY_LINEAR       (BACKOFF_POLICY_DONT+2)
#define BACKOFF_POLICY_RANDOM       (BACKOFF_POLICY_DONT+3)

static __inline__ unsigned int __osa_get_cm_policy(void) {
  int val;
   asm volatile ("movl %1, %%esi\n\t" \
                 "xchg %%bx, %%bx\n\t" \
                 "movl %%ebx, %0\n\t"
                  : "=g"(val) \
                  : "g"(OSA_GET_CM_POLICY_VAL) \
                  : "esi", "ebx");
   return val;
}

static __inline__ unsigned int __osa_cmpol_chg_thresh(void) {
  int val;
   asm volatile ("movl %1, %%esi\n\t" \
                 "xchg %%bx, %%bx\n\t" \
                 "movl %%ebx, %0\n\t"
                  : "=g"(val) \
                  : "g"(OSA_GET_CM_POLCHG_THRESH_VAL) \
                  : "esi", "ebx");
   return val;
}

static __inline__ void __osa_set_cm_policy(int pol) {
   asm volatile ("movl %0, %%ebx\n\t" \
                 "movl %1, %%esi\n\t" \
                 "xchg %%bx, %%bx\n\t" 
		  : /* No output */
                  : "g"(pol), "g"(OSA_SET_CM_POLICY_VAL) \
                  : "esi", "ebx");
}

static __inline__ unsigned int __osa_get_backoff_policy(void) {
  int val;
   asm volatile ("movl %1, %%esi\n\t" \
                 "xchg %%bx, %%bx\n\t" \
                 "movl %%ebx, %0\n\t"
                  : "=g"(val) \
                  : "g"(OSA_GET_BACKOFF_POLICY_VAL) \
                  : "esi", "ebx");
   return val;
}

static __inline__ unsigned int __osa_bkpol_chg_thresh(void) {
  int val;
   asm volatile ("movl %1, %%esi\n\t" \
                 "xchg %%bx, %%bx\n\t" \
                 "movl %%ebx, %0\n\t"
                  : "=g"(val) \
                  : "g"(OSA_GET_BK_POLCHG_THRESH_VAL) \
                  : "esi", "ebx");
   return val;
}

static __inline__ void __osa_set_backoff_policy(int pol) {
   asm volatile ("movl %0, %%ebx\n\t" \
                 "movl %1, %%esi\n\t" \
                 "xchg %%bx, %%bx\n\t" 
		  : /* No output */
                  : "g"(pol), "g"(OSA_SET_BACKOFF_POLICY_VAL) \
                  : "esi", "ebx");
}

static __inline__ int get_activetx_data(int pid, int type) {
   asm volatile ("movl %1, %%ebx\n\t" \
                 "movl %3, %%esi\n\t" \
                 "movl %2, %%ecx\n\t" \
                 "xchg %%bx, %%bx\n\t" \
                 "movl %%ebx, %0\n\t"
                  : "=g"(type) \
                  : "g"(type), "g"(pid),"g"(OSA_ACTIVETX_DATA_VAL) \
                  : "esi", "ecx", "ebx");
   return type;
}

static __inline__ int get_activetx_param(int pid, int type) {
   asm volatile ("movl %1, %%ebx\n\t" \
                 "movl %3, %%esi\n\t" \
                 "movl %2, %%ecx\n\t" \
                 "xchg %%bx, %%bx\n\t" \
                 "movl %%ebx, %0\n\t"
                  : "=g"(type) \
                  : "g"(type), "g"(pid),"g"(OSA_ACTIVETX_PARAM_VAL) \
                  : "esi", "ecx", "ebx");
   return type;
}

#define NO_BONUS 5
#define intxbonus(p) get_activetx_param(p->pid,OSA_ACTTX_EXISTS)
#define txrestartsbonus(p) get_activetx_param(p->pid,OSA_ACTTX_RESTARTS)
#define txsizebonus(p) get_activetx_param(p->pid,OSA_ACTTX_SIZE)
#define txovflowbonus(p) get_activetx_param(p->pid,OSA_ACTTX_OVERFLOWED)
#define txcplxconfbonus(p) get_activetx_param(p->pid,OSA_ACTTX_COMPLEXCONF)
#define txlongrunbonus(p) get_activetx_param(p->pid,OSA_ACTTX_LONGRUNNING)
#define txstalledbonus(p) get_activetx_param(p->pid,OSA_ACTTX_STALLED)                     
#define tx_conflict_set(txid) get_activetx_param(txid,OSA_ACTTX_CONFLICT_SET)
#define intx(p) get_activetx_data(p->pid,OSA_ACTTX_EXISTS)
#define txrestarts(p) get_activetx_data(p->pid,OSA_ACTTX_RESTARTS)
#define txsize(p) get_activetx_data(p->pid,OSA_ACTTX_SIZE)
#define txovflow(p) get_activetx_data(p->pid,OSA_ACTTX_OVERFLOWED)
#define txcplxconf(p) get_activetx_data(p->pid,OSA_ACTTX_COMPLEXCONF)
#define txlongrun(p) get_activetx_data(p->pid,OSA_ACTTX_LONGRUNNING)
#define txstalled(p) get_activetx_data(p->pid,OSA_ACTTX_STALLED)
#define log_pinned_cachecold_tx(p) get_activetx_data(p->pid,OSA_PINNED_CACHECOLD_TX)
#define txschedmode(p) get_activetx_data(p->pid,OSA_SCHEDULER_MODE)
#define txrestart_desched_thresh(p) get_activetx_data(p->pid,OSA_ACTTX_DESCHEDTHRESH)
#define txrestart_average(p) get_activetx_data(p->pid,OSA_ACTTX_RESTARTAVG)
#define curtx_hasctmdeps(p) get_activetx_data(0,OSA_ACTTX_HASCTMDEPS)
#define curtx_xpushed(p) get_activetx_data(0,OSA_ACTTX_ACTTXXPUSHED)
#define curtx_setnoctm(p) get_activetx_data(0,OSA_ACTTX_SETNODEPS)
#define tx_cm_policy(p) __osa_get_cm_policy(p)
#define tx_cmpol_chg_thresh(p) __osa_cmpol_chg_thresh(p)
#define tx_set_cm_policy(p) __osa_set_cm_policy(p)
#define tx_backoff_policy(p) __osa_get_cm_policy(p)
#define tx_bkpol_chg_thresh(p) __osa_cmpol_chg_thresh(p)
#define tx_set_backoff_policy(p) __osa_set_cm_policy(p)
#define tx_set_vconf_addr(ncpu, vaddr)	OSA_SET_VCONF_ADDR_BUF(ncpu, vaddr) 

#else
#define NO_BONUS 5
#define intxbonus(p) NO_BONUS
#define txrestartsbonus(p) NO_BONUS
#define txsizebonus(p) NO_BONUS
#define txovflowbonus(p) NO_BONUS
#define txcplxconfbonus(p) NO_BONUS
#define txlongrunbonus(p) NO_BONUS
#define txstalledbonus(p) NO_BONUS
#define tx_conflict_set(p) 
#define intx(p) 0
#define txrestarts(p) 0
#define txsize(p) 0
#define txovflow(p) 0
#define txcplxconf(p) 0
#define txlongrun(p) 0
#define txstalled(p) 0
#define log_pinned_cachecold_tx(p)
#define txschedmode(p) 0
#define txrestart_desched_thresh(p) 8000
#define txrestart_average(p) 2000
#define tx_cm_policy(p) 0
#define tx_cmpol_chg_thresh(p) 1000000
#define tx_set_cm_policy(p) 
#define tx_backoff_policy(p) 0
#define tx_bkpol_chg_thresh(p) 100000
#define tx_set_backoff_policy(p) 
#define curtx_hasctmdeps(p) 0
#define curtx_xpushed(p) 0
#define curtx_setnoctm(p) 0
#define kill_tx(p)
#define tx_set_vconf_addr(ncpu, vaddr)	
#endif // CONFIG_TX_TXAWARE_SCHEDULER
#ifdef CONFIG_TX_TXAWARE_SCHEDULER

#define OSA_PAGE_FAULTCAP(pftyp) \
      asm volatile ("movl %0, %%esi; \
                     movl %1, %%ebx; \
                     xchg %%bx, %%bx " \
                     : /*no output*/ \
                     : "g"(OSA_PAGE_FAULT_VAL), "g"(pftyp) \
                     : "esi", "ebx");
#else
#define OSA_PAGE_FAULTCAP(pftyp) 
#endif // CONFIG_TX_PROFILE_PAGE_FAULTS

// len is output of strlen() - i.e. not including '\0'
#ifdef CONFIG_OSA_REGISTER_LOCKS
#define OSA_REGISTER_SPINLOCK(addr, name, len) \
      asm volatile ("movl %0, %%edx; \
                     movl %1, %%ecx; \
                     movl %2, %%ebx; \
                     movl %3, %%esi; \
                     xchg %%bx, %%bx " \
                     : /*no output*/ \
                     : "g"(addr), "g"(name), "g"(len), "g"(OSA_REGISTER_SPINLOCK_VAL) \
                     : "esi", "ebx", "ecx", "edx");
#else
#define OSA_REGISTER_SPINLOCK(addr, name, len) 
#endif


#if ( defined (CONFIG_TX_PROFILING) || defined (CONFIG_TX_NEW_THREAD_TX_PROFILING ) )
static __inline__ int get_thread_profile_data(int type) {
   asm volatile ("movl %1, %%ebx\n\t" \
                 "movl %2, %%esi\n\t" \
                 "xchg %%bx, %%bx\n\t" \
                 "movl %%ebx, %0\n\t"
                  : "=g"(type) \
                  : "g"(type), "g"(OSA_THREAD_PROF_DATA_VAL) \
                  : "esi", "ebx");
   return type;
}

static __inline__ int __get_max_conflicter(int pid) {
   asm volatile ("movl %1, %%ebx\n\t" \
                 "movl %2, %%esi\n\t" \
                 "xchg %%bx, %%bx\n\t" \
                 "movl %%ebx, %0\n\t"
                  : "=g"(pid) \
                  : "g"(pid), "g"(OSA_GET_MAX_CONFLICTER_VAL) \
                  : "esi", "ebx");
   return pid;
}

static __inline__ void __clear_max_conflicter(int pid) {
   asm volatile ("movl %0, %%ebx\n\t" \
                 "movl %1, %%esi\n\t" \
                 "xchg %%bx, %%bx\n\t" 
		  : /* No output */
                  : "g"(pid), "g"(OSA_CLEAR_MAX_CONFLICTER_VAL) \
                  : "esi", "ebx");
}

static __inline__ void __log_schedule(int type) {
   asm volatile ("movl %0, %%ebx\n\t" \
                 "movl %1, %%esi\n\t" \
                 "xchg %%bx, %%bx\n\t" 
		  : /* No output */
                  : "g"(type), "g"(OSA_LOG_SCHEDULE_VAL) \
                  : "esi", "ebx");
}
#define log_anti_conflict() __log_schedule(OSA_LOG_ANTI_CONFLICT)
#define log_restart_desched() __log_schedule(OSA_LOG_RESTART_DESCHED)
#define thread_tx_restarts_current() get_thread_profile_data(OSA_THREAD_PROF_CURRENT_RESTARTS)
#define thread_tx_restarts() get_thread_profile_data(OSA_THREAD_PROF_RESTARTS)
#define thread_tx_size() get_thread_profile_data(OSA_THREAD_PROF_SIZE)
#define thread_tx_overflowed() get_thread_profile_data(OSA_THREAD_PROF_OVERFLOWED)
#define thread_tx_complex_conflicts() get_thread_profile_data(OSA_THREAD_PROF_COMPLEXCONF)
#define thread_tx_long_running() get_thread_profile_data(OSA_THREAD_PROF_LONGRUNNING)
#define thread_tx_unique_tx() get_thread_profile_data(OSA_THREAD_PROF_UNIQUE_TX)
#define thread_tx_bkcyc() get_thread_profile_data(OSA_THREAD_PROF_BKCYC_TX)
#define get_max_conflicter(p) __get_max_conflicter(p)
#define clear_conflicters(p) __clear_max_conflicter(p)
#else
#define clear_conflicters(p)
#define get_max_conflicter(p) (p)
#define thread_tx_restarts_current() 0
#define thread_tx_restarts() 0
#define thread_tx_size() 0
#define thread_tx_overflowed() 0
#define thread_tx_complex_conflicts() 0
#define thread_tx_long_running() 0
#define thread_tx_unique_tx() 0
#define thread_tx_bkcyc() 0
#define log_anti_conflict()
#define log_restart_desched()
 
#endif // CONFIG_TX_PROFILING

#ifdef CONFIG_TX_CXSPIN_INFORM

#define CXSPIN_INFORM_TX(lock) OSA_CXSPIN_INFORM(OSA_CXSPIN_INFO_TX, lock)
#define CXSPIN_INFORM_NOTX(lock) OSA_CXSPIN_INFORM(OSA_CXSPIN_INFO_NOTX, lock)
#define CXSPIN_INFORM_IOTX(lock) OSA_CXSPIN_INFORM(OSA_CXSPIN_INFO_IOTX, lock)
#define CXSPIN_INFORM_IONOTX(lock) \
   OSA_CXSPIN_INFORM(OSA_CXSPIN_INFO_IONOTX, lock)

static inline void OSA_CXSPIN_INFORM(int code, spinlock_t *lock) {
   asm volatile("xchg %%bx, %%bx" : : "S"(code), "d"(lock));
}

#else
#define CXSPIN_INFORM_TX(lock) do{}while(0)
#define CXSPIN_INFORM_NOTX(lock) do{}while(0)
#define CXSPIN_INFORM_IOTX(lock) do{}while(0)
#define CXSPIN_INFORM_IONOTX(lock) do{}while(0)
#endif

#ifdef CONFIG_TX_USER_HTM

#define XABORT_USER()              OSA_MAGIC(OSA_OP_XABORT_USER)

static inline int XGETTXID_USER( void ) {
   int ret;
   asm volatile ("xchg %%bx, %%bx" : "=a"(ret) : "S"(OSA_OP_XGETTXID_USER));
   return ret;
}

static inline int XEND_USER( void ) {
   int ret;
   asm volatile ("xchg %%bx, %%bx" : "=a"(ret) : "S"(OSA_OP_XEND_USER));
   return ret;
}

#define XSET_USER_TM_SYSCALL_BIT(bit) \
	asm volatile ("xchg %%bx, %%bx" : : "a"(bit), "S"(OSA_OP_SET_USER_SYSCALL_BIT))

#else

#define XABORT_USER()              
#define XEND_USER()                
#define XGETTXID_USER() 0
#define XSET_USER_TM_SYSCALL_BIT(bit)

#endif

#endif // _OSAMAGIC_H
