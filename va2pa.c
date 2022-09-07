
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/module.h>

// #define PAGE_SIZE       4096
// #define _PAGE_PRESENT   0x001

static int pid = 1;
module_param(pid, int, 0644);

static unsigned long start_addr = 0;
module_param(start_addr, long, S_IRUGO);

static unsigned long end_addr = 0;
module_param(end_addr, long, S_IRUGO);

static pte_t *get_pte(struct task_struct *task, unsigned long address)
{
	pgd_t* pgd;
    p4d_t* p4d;
	pud_t* pud;
	pmd_t* pmd;
	pte_t* pte;

	struct mm_struct *mm = task->mm;

	// mm里面存储了最高级页表的首地址，pgd_offset根据首地址和便宜算出下一级页表的首地址
	pgd = pgd_offset(mm, address);
	if(pgd_none(*pgd) || pgd_bad(*pgd))
	{
		printk("pgd is null\n");
		return NULL;
	}
    
    p4d = p4d_offset(pgd, address);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
	{
		printk("p4d is null\n");
		return NULL;
	}

    pud = pud_offset(p4d, address);
    if (pud_none(*pud) || pud_bad(*pud))
	{
		printk("pud is null\n");
		return NULL;
	}

	pmd = pmd_offset(pud, address);
	if(pmd_none(*pmd) || pmd_bad(*pmd))
	{
		printk("pmd is null\n");
		return NULL;
	}

	pte = pte_offset_kernel(pmd, address);
	if(pte_none(*pte))
	{
		printk("pte is null\n");
		return NULL;
	}

	return pte;
}

static int test_init(void)
{
	struct task_struct  *task;
    struct page* page;
	unsigned long addr = start_addr;
	printk("program begin\n");

	task = pid_task(find_pid_ns(pid, &init_pid_ns), PIDTYPE_PID);
	if(!task)
	{
		printk("tast is nullptr\n");
		return 0;
	}
	for(addr = start_addr; addr < end_addr; addr += PAGE_SIZE)
	{
		printk("addr=%lx\n", addr);

		pte_t *pte = get_pte(task, addr);

		if(pte == NULL)
		{
			return 0;
		}
        page = pte_page(*pte);
        unsigned long int temp = (pte_pfn(*pte));
        printk("%d\n", temp);

		// unsigned int level;
		// pte_t *pte = lookup_address(addr, &level);

		// if(pte)
		// {
		// 	printk("evict\n");
		// 	pte->pte &= (~_PAGE_PRESENT);
		// }

		// pte->pte |= (_PAGE_PROTNONE);

        // pte_t tmp_pte = *pte;
    	// set_pte(pte , pte_clear_flags(tmp_pte, _PAGE_PRESENT));
	}

	return 0;
}

static void test_exit(void)
{
	printk("program end\n");
}

module_init(test_init);
module_exit(test_exit);
MODULE_LICENSE("GPL");
