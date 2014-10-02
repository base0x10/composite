/* error numbers required by eitre.h (included by pgtbl.h) */
#define EINVAL	22
#define EPERM	1
#define EEXIST	17
#define ENOENT	2

#include "string.h"
#include "assert.h"
#include <pgtbl.h>

#include "multiboot.h"
#include "kernel.h"
#include "string.h"
#include "isr.h"

#define POSSIBLE_FRAMES 1024*1024
#define USER_STACK_SIZE PAGE_SIZE

u32_t user_entry_point;
u32_t user_stack_address;

struct tlb_quiescence tlb_quiescence[NUM_CPU] CACHE_ALIGNED;
struct liveness_entry __liveness_tbl[LTBL_ENTS];

pgtbl_t pgtbl;
static u32_t pgdir[1024] __attribute__((aligned(4096)));
static u32_t pte[1024][1024] __attribute__((aligned(4096)));

static int
xdtoi(char c)
{
	if ('0' <= c && c <= '9') return c - '0';
	if ('a' <= c && c <= 'f') return c - 'a' + 10;
	if ('A' <= c && c <= 'F') return c - 'A' + 10;
	return 0;
}

static u32_t
hextol(const char *s)
{
	int i, r = 0;
	for (i = 0; i < 8; i++)
		r = (r * 0x10) + xdtoi(s[i]);
	return r;
}

void *
chal_pa2va(void *address)
{
	return address;
}

void *
chal_va2pa(void *address)
{
	return address;
}

static void
page_fault(struct registers *regs)
{
	u32_t fault_addr, cs, eip = 0;
    
	asm volatile("mov %%cr2, %0" : "=r" (fault_addr));
	asm volatile("mov %%cs, %0" : "=r" (cs));

	die("Page Fault (%s%s%s%s) at 0x%x, eip 0x%x, cs 0x%x\n",
		!(regs->err_code & PGTBL_PRESENT) ? "not-present " : "",
		regs->err_code & PGTBL_WRITABLE ? "read-only " : "read-fault ",
		regs->err_code & PGTBL_USER ? "user-mode " : "system ",
		regs->err_code & PGTBL_WT ? "reserved " : "",
		regs->err_code & PGTBL_NOCACHE ? "instruction-fetch " : "",
		fault_addr, eip, cs);
}

void
paging_init(u32_t memory_size, u32_t nmods, u32_t *mods)
{
	char *cmdline;
	u32_t cr0, i, user_stack_physical = 0;

	printk(INFO, "Initializing virtual memory (physical memory: %dMB / %d frames)\n", memory_size/1024, memory_size/4);
	register_interrupt_handler(14, page_fault);

	/* Allocate the Page Directory and initialize all Page Tables */
	pgtbl = pgtbl_alloc(pgdir);
	for (i = 0; i < 1024; i++) {
		pgtbl_intern_expand(pgtbl, i * PAGE_SIZE * 1024, &pte[i], PGTBL_WRITABLE | PGTBL_PRESENT | PGTBL_GLOBAL);
	}

	/* Identity map the kernel */
	for (i = 0; i < (u32_t)mods / (PAGE_SIZE); i++) {
		pgtbl_mapping_add(pgtbl, i * 4096, i * 4096, PGTBL_WRITABLE | PGTBL_PRESENT | PGTBL_GLOBAL);
	}

	/* Map user modules into userspace */
	if (nmods > 0) {
		unsigned int j = 0;
		multiboot_module_t *mod = (multiboot_module_t*)mods;
		u32_t module_address = 0;

		for (i = 0; i < nmods; i++) {
			cmdline = (char*)mod[i].cmdline;
			module_address = hextol(cmdline);
			printk(INFO, "Mapping multiboot Module %d \"%s\" [%x:%x] to 0x%08x\n",
				i, mod[i].cmdline, mod[i].mod_start, mod[i].mod_end, module_address);

			if (cmdline[8] == '-') {
				user_entry_point = hextol(&cmdline[9]);
			}

			for (j = 0; j <= ((mod[i].mod_end - mod[i].mod_start) / (PAGE_SIZE))+1; j++) {
				pgtbl_mapping_add(pgtbl, module_address + (j * 4096), mod[i].mod_start + (j * 4096), PGTBL_WRITABLE | PGTBL_PRESENT | PGTBL_USER);
			}
			if (mod[i].mod_end > user_stack_physical) {
				user_stack_physical = mod[i].mod_end;
			}
		}
		user_stack_physical = (user_stack_physical + USER_STACK_SIZE + PAGE_SIZE) & PGTBL_FRAME_MASK;
		user_stack_address = 0x7fff0000;
	}

	printk(INFO, "Reserving a user-space stack at v:0x%08x, p:0x%08x\n", user_stack_address, user_stack_physical);
	for (i = 0; i < (USER_STACK_SIZE / PAGE_SIZE); i++) {
		pgtbl_mapping_add(pgtbl,
			user_stack_physical - USER_STACK_SIZE + (i * PAGE_SIZE),
			user_stack_address - USER_STACK_SIZE + (i * PAGE_SIZE),
			PGTBL_WRITABLE | PGTBL_PRESENT | PGTBL_USER);
	}

	printk(INFO, "Enabling paging\n");
	pgtbl_update(pgtbl);
	asm volatile("mov %%cr0, %0" : "=r"(cr0));
	cr0 |= 0x80000000;
	asm volatile("mov %0, %%cr0" : : "r"(cr0));
}
