#ifndef COS_CONFIG_H
#define COS_CONFIG_H

/***
 * Memory information.  Included are four sections:
 * - physical memory information (PA)
 * - virtual memory addresses (VA)
 * - resource table addresses to index memory resources (RTA)
 * - the maximum number of pages of the different types of memory.
 *   See BOOT_* in cos_types.h for this information
 *
 * These exist separately for kernel-accessible memory that can be
 * typed as either kernel or user virtual memory, and
 * kernel-inaccessible memory that can only be used as user virtual
 * memory.
 */

/* define when booting with Linux */
#define COS_LINUX

/* we already use 16 MB of kernel memory + the kernel img, thus 32MB offset for this: */
#ifndef COS_LINUX
#define COS_MEM_USER_PA (1<<25)
#define COS_MEM_USER_PA_SZ    (1<<25) /* start with 32MB of memory */
#else
#define COS_MEM_USER_PA (0x40000000)  /* 1 GB...memory untouched by Linux */
#define COS_MEM_USER_PA_SZ    (1<<29) /* 512 MB of memory */
#endif
/* 
 * 1 MB, note that this is not the PA of kernel-usable memory, instead
 * it is the PA of the kernel.  If you change this, update the kernel
 * linker script (.ld) as well.
 */ 
#define COS_MEM_KERN_PA (0x00100000)
#define COS_MEM_KERN_PA_ORDER (22)
#define COS_MEM_KERN_PA_SZ    (1<<COS_MEM_KERN_PA_ORDER)

#define COS_MEM_COMP_START_VA ((1<<30) + (1<<22)) /* 1GB + 4MB (a relic) */
#define COS_MEM_KERN_START_VA (0xc0000000) //COS_MEM_KERN_PA     /* currently, we don't do kernel relocation */

#define COS_MEM_USER_VA_SZ (1<<31) /* 2 GB */
#define COS_MEM_KERN_VA_SZ (1<<24) /* 16 MB from KERN_START_VA + end of kernel image onward */

/* To get more memory, we need many PTE caps in the captbl. So give
 * multiple pages to it. 5 is enough for 512 MBs.*/
#define BOOT_CAPTBL_NPAGES 5

#define BOOT_COMP_MAX_SZ   (1<<24) /* 16 MB for the booter component */

#include "cpu_ghz.h"
#define NUM_CPU                4

#define CPU_TIMER_FREQ         100 // set in your linux .config

#define RUNTIME                3 // seconds

/* The kernel quiescence period = WCET in Kernel + WCET of a CAS. */
#define KERN_QUIESCENCE_PERIOD_US 500
#define KERN_QUIESCENCE_CYCLES (KERN_QUIESCENCE_PERIOD_US * 4000)
#define TLB_QUIESCENCE_CYCLES  (4000 * 1000 * (1000 / CPU_TIMER_FREQ))

// After how many seconds should schedulers print out their information?
#define SCHED_PRINTOUT_PERIOD  100000
#define COMPONENT_ASSERTIONS   1 // activate assertions in components?

/* Should not set when NUM_CPU > 2 or FPU enabled. */
//#define LINUX_ON_IDLE          1 // should Linux be activated on Composite idle

/* 
 * Should Composite run as highest priority?  Absolutely should be set if
 * using networking (cnet). 
 */
#define LINUX_HIGHEST_PRIORITY 1

//#define FPU_ENABLED
#define FPU_SUPPORT_FXSR       1   /* >0 : CPU supports FXSR. */

/* the CPU that does initialization for Composite */
#define INIT_CORE              0
/* Currently Linux runs on the last CPU only. The code includes the
 * following macro assumes this. We might need to assign more cores
 * to Linux later. */
#define LINUX_CORE             (NUM_CPU - 1)
/* # of cores assigned to Composite */
#define NUM_CPU_COS            (NUM_CPU > 1 ? NUM_CPU - 1 : 1)

/* Composite user memory uses physical memory above this. */
#define COS_MEM_START          COS_MEM_USER_PA

/* NUM_CPU_SOCKETS defined in cpu_ghz.h. The information is used for
 * intelligent IPI distribution. */
#define NUM_CORE_PER_SOCKET    (NUM_CPU / NUM_CPU_SOCKETS)

// cos kernel settings
#define COS_PRINT_MEASUREMENTS 1
#define COS_PRINT_SCHED_EVENTS 1
#define COS_ASSERTIONS_ACTIVE  1

/*** Console and output options ***/
/* 
 * Notes: If you are using composite as high priority and no idle to
 * linux, then the shell output will not appear until the Composite
 * system has exited.  Thus, you will want to make the memory size
 * large enough to buffer _all_ output.  Note that currently
 * COS_PRINT_MEM_SZ should not exceed around (1024*1024*3).
 *
 * If you have COS_PRINT_SHELL, you _will not see output_ unless you
 * run 
 * $~/transfer/print
 * after
 * # make
 * but before the runscript.
 */
/* print out to the shell? */
#define COS_PRINT_SHELL   1
/* how much should we buffer before sending an event to the shell? */
#define COS_PRINT_BUF_SZ  128
/* how large should the shared memory region be that will buffer print data? */
#define COS_PRINT_MEM_SZ  (4096)

/* print out to dmesg? */
/* #define COS_PRINT_DMESG 1 */

#endif /* COS_CONFIG_H */
