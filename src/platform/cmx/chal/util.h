#ifndef UTIL_H
#define UTIL_H

#include "stm32f767xx.h"
#include "core_cm7.h"
#include "cmsis_gcc.h"

#define CAS_SUCCESS 1
/* 
 * Return values:
 * 0 on failure due to contention (*target != old)
 * 1 otherwise (*target == old -> *target = updated)
 */
static inline int 
cos_cas(unsigned long *target, unsigned long old, unsigned long updated)
{
	unsigned long oldval, res;

	do {
		oldval=__LDREXW(target);

		if(oldval==old) /* 0=succeeded, 1=failed */
			res=__STREXW(updated, target);
		else {
			__CLREX();
			return 0;
		}
	}
	while(res);

	return 1;
}

/*
 * Fetch-and-add implementation on x86. It returns the original value
 * before xaddl.
 */
static inline int 
cos_faa(int *var, int value)
{
	unsigned int res;
	int oldval;

	do {
		oldval=(int)__LDREXW((volatile unsigned long*)var);
		res=__STREXW((unsigned long)(oldval+value), (volatile unsigned long*)var);
	}
	while(res);

	return oldval;
}

/* cortex-m isb instruction barrier. */
static inline void
cos_inst_bar(void)
{
	__asm__ __volatile__("isb":::);
}


#ifndef rdtscll
/* set rdtsc cacheable to non-cacheable */
extern volatile unsigned long long* rdtsc_sim;
static inline unsigned long long
__rdtscll(void)
{
	unsigned long long old_val;
	unsigned long long tim_reg;
	do {
		old_val=*rdtsc_sim;
		tim_reg=(TIM4->CNT);
	}
	while(old_val!=*rdtsc_sim);
	/* No need to multiply by two because prescaler at 2 will be
	 * multiplied by 2 later. What a joke on the STM32 clock tree!
	 */
	return (old_val+tim_reg);
}
#define rdtscll(val) do {val=__rdtscll();} while(0)
#endif


#endif
