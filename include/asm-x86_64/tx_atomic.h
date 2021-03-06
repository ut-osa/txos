#ifndef __ARCH_X86_64_TX_ATOMIC__
#define __ARCH_X86_64_TX_ATOMIC__

#include <asm/alternative.h>
#include <asm/cmpxchg.h>
#include <linux/transaction.h>

/*
 * Atomic operations that C can't guarantee us.  Useful for
 * resource counting etc..
 */

/*
 * Make sure gcc doesn't try to be clever and move things around
 * on us. We need to use _exactly_ the address the user gave us,
 * not some alias that contains the same information.
 */

#define TX_ATOMIC_INIT(i)	{ (i) }

/**
 * atomic_read - read atomic variable
 * @v: pointer of type atomic_t
 * 
 * Atomically reads the value of @v.
 */ 
#define tx_atomic_read(v)		((v)->counter)

/**
 * atomic_set - set atomic variable
 * @v: pointer of type atomic_t
 * @i: required value
 * 
 * Atomically sets the value of @v to @i.
 */ 
//#define tx_atomic_set(v,i)		(((v)->counter) = (i))

/**
 * atomic_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic_t
 * 
 * Atomically adds @i to @v.
 */
static __inline__ void tx_atomic_add(int i, tx_atomic_t *v)
{
	__asm__ __volatile__(
		LOCK_PREFIX "addl %1,%0"
		:"=m" (v->counter)
		:"ir" (i), "m" (v->counter));

	record_tx_atomic(v, i, ATOMIC_OP_ADD);
}

/**
 * atomic_sub - subtract integer from atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 * 
 * Atomically subtracts @i from @v.
 */
static __inline__ void tx_atomic_sub(int i, tx_atomic_t *v)
{
	__asm__ __volatile__(
		LOCK_PREFIX "subl %1,%0"
		:"=m" (v->counter)
		:"ir" (i), "m" (v->counter));

	record_tx_atomic(v, -i, ATOMIC_OP_ADD);
}

/**
 * atomic_sub_and_test - subtract value from variable and test result
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 * 
 * Atomically subtracts @i from @v and returns
 * true if the result is zero, or false for all
 * other cases.
 */
/*
static __inline__ int atomic_sub_and_test(int i, atomic_t *v)
{
	unsigned char c;

	__asm__ __volatile__(
		LOCK_PREFIX "subl %2,%0; sete %1"
		:"=m" (v->counter), "=qm" (c)
		:"ir" (i) : "memory", "m" (v->counter) : "memory");
	return c;
}
*/
/**
 * atomic_inc - increment atomic variable
 * @v: pointer of type atomic_t
 * 
 * Atomically increments @v by 1.
 */ 
static __inline__ void _tx_atomic_inc(tx_atomic_t *v)
{
	__asm__ __volatile__(
		LOCK_PREFIX "incl %0"
		:"=m" (v->counter)
		:"m" (v->counter));
}

#define tx_atomic_inc(v) do{				\
		_tx_atomic_inc(v);			\
		record_tx_atomic(v, 1, ATOMIC_OP_ADD);	\
	}while(0)
		
#define tx_atomic_inc_nolog(v)	_tx_atomic_inc(v)

/**
 * atomic_dec - decrement atomic variable
 * @v: pointer of type atomic_t
 * 
 * Atomically decrements @v by 1.
 */ 
static __inline__ void _tx_atomic_dec(tx_atomic_t *v)
{
	__asm__ __volatile__(
		LOCK_PREFIX "decl %0"
		:"=m" (v->counter)
		:"m" (v->counter));
}

#define tx_atomic_dec(v) do{				\
		_tx_atomic_dec(v);			\
		record_tx_atomic(v, -1, ATOMIC_OP_ADD);	\
	}while(0)

#define tx_atomic_dec_nolog(v)	_tx_atomic_dec(v)


/**
 * atomic_dec_and_test - decrement and test
 * @v: pointer of type atomic_t
 * 
 * Atomically decrements @v by 1 and
 * returns true if the result is 0, or false for all other
 * cases.
 */ 
static __inline__ int tx_atomic_dec_and_test(tx_atomic_t *v)
{
	unsigned char c;

	__asm__ __volatile__(
		LOCK_PREFIX "decl %0; sete %1"
		:"=m" (v->counter), "=qm" (c)
		: "m" (v->counter) : "memory");
	record_tx_atomic(v, -1, ATOMIC_OP_ADD);
	return c != 0;
}

extern int _tx_atomic_dec_and_lock(tx_atomic_t *atomic, spinlock_t *lock);
#define tx_atomic_dec_and_lock(atomic, lock)				\
	__cond_lock(lock, _tx_atomic_dec_and_lock(atomic, lock))


/**
 * atomic_inc_and_test - increment and test 
 * @v: pointer of type atomic_t
 * 
 * Atomically increments @v by 1
 * and returns true if the result is zero, or false for all
 * other cases.
 */ 
 /*
static __inline__ int atomic_inc_and_test(atomic_t *v)
{
	unsigned char c;

	__asm__ __volatile__(
		LOCK_PREFIX "incl %0; sete %1"
		:"+m" (v->counter), "=qm" (c)
		: : "memory");
	return c != 0;
}
 */
/**
 * atomic_add_negative - add and test if negative
 * @v: pointer of type atomic_t
 * @i: integer value to add
 * 
 * Atomically adds @i to @v and returns true
 * if the result is negative, or false when
 * result is greater than or equal to zero.
 */
  /* 
static __inline__ int atomic_add_negative(int i, atomic_t *v)
{
	unsigned char c;

	__asm__ __volatile__(
		LOCK_PREFIX "addl %2,%0; sets %1"
		:"+m" (v->counter), "=qm" (c)
		:"ir" (i) : "memory");
	return c;
}
  */

/**
 * atomic_add_return - add integer and return
 * @v: pointer of type atomic_t
 * @i: integer value to add
 *
 * Atomically adds @i to @v and returns @i + @v
 */
#if 0
static __inline__ int atomic_add_return(int i, atomic_t *v)
{
	int __i = i;
	__asm__ __volatile__(
		LOCK_PREFIX "xaddl %0, %1"
		:"+r" (i), "+m" (v->counter)
		: : "memory");
	return i + __i;
}
#endif

/**
 * atomic_sub_return - subtract integer and return
 * @v: pointer of type atomic_t
 * @i: integer value to subtract
 *
 * Atomically subtracts @i from @v and returns @v - @i
 */
    /*
static __inline__ int atomic_sub_return(int i, atomic_t *v)
{
	return atomic_add_return(-i,v);
}
    */

#define tx_atomic_cmpxchg(v, old, new) (cmpxchg(&((v)->counter), (old), (new)))
     //#define atomic_xchg(v, new) (xchg(&((v)->counter), (new)))

/**
 * atomic_add_unless - add unless the number is already a given value
 * @v: pointer of type atomic_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as @v was not already @u.
 * Returns non-zero if @v was not @u, and zero otherwise.
 */
static __inline__ int tx_atomic_add_unless(tx_atomic_t *v, int a, int u)
{
	int c, old;
	c = tx_atomic_read(v);
	for (;;) {
		if (unlikely(c == (u)))
			break;
		old = tx_atomic_cmpxchg((v), c, c + (a));
		if (likely(old == c)){
			record_tx_atomic(v, a, ATOMIC_OP_ADD);
			break;
		}
		c = old;
	}
	return c != (u);
}

#define tx_atomic_inc_not_zero(v) tx_atomic_add_unless((v), 1, 0)


/**
 * tx_atomic64_add_unless - add unless the number is a given value
 * @v: pointer of type atomic64_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as it was not @u.
 * Returns non-zero if @v was not @u, and zero otherwise.
 */
static __inline__ int tx_atomic64_add_unless(atomic64_t *v, long a, long u)
{
	long c, old;
	c = atomic64_read(v);
	for (;;) {
		if (unlikely(c == (u)))
			break;
		old = atomic64_cmpxchg((v), c, c + (a));
		if (likely(old == c))
			break;
		c = old;
	}
	return c != (u);
}

#define tx_atomic64_inc_not_zero(v) tx_atomic64_add_unless((v), 1, 0)


/*

#define atomic_inc_return(v)  (atomic_add_return(1,v))
#define atomic_dec_return(v)  (atomic_sub_return(1,v))
     */
/* These are x86-specific, used by some header files */
      /*
#define atomic_clear_mask(mask, addr) \
__asm__ __volatile__(LOCK_PREFIX "andl %0,%1" \
: : "r" (~(mask)),"m" (*addr) : "memory")

#define atomic_set_mask(mask, addr) \
__asm__ __volatile__(LOCK_PREFIX "orl %0,%1" \
: : "r" (mask),"m" (*(addr)) : "memory")
      */

#include <asm-generic/atomic.h>
#endif
