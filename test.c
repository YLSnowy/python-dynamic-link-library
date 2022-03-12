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

		// unsigned int level;
		// pte_t *pte = lookup_address(addr, &level);

		if(pte)
		{
			printk("evict\n");
			pte->pte &= (~_PAGE_PRESENT);
		}

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



#include "migration.h"
#include <linux/highmem.h>

static int (*ext4_iomap_begin)(struct inode *inode, loff_t offset, loff_t length,
			unsigned flags, struct iomap *iomap);

static int (*ext4_iomap_end)(struct inode *inode, loff_t offset, loff_t length,
			  ssize_t written, unsigned flags, struct iomap *iomap);

sector_t dax_iomap_sector(struct iomap *iomap, loff_t pos)
{
	return (iomap->addr + (pos & PAGE_MASK) - iomap->offset) >> 9;
}

/*
** _do_migration: do actually migration from nvm to dram
** @sector_from: nvm position
** @size: migration size
*/
unsigned int _do_migration(struct block_device *bdev, 
    struct dax_device *dax_dev,
    sector_t sector_from,
    size_t size,
    gfp_t gfp_mask)
{
    void *vto, *vfrom;
	long rc;
	int id;
    pgoff_t pgoff;
    struct page* page;


    /* 1. access vfrom */
	/* direct accessing the sector_from */
	rc = bdev_dax_pgoff(bdev, sector_from, size, &pgoff);
	if (rc)  
		return rc;
	id = dax_read_lock();
	rc = dax_direct_access(dax_dev, pgoff, PHYS_PFN(size), &vfrom, NULL);
	if (rc < 0) {
		dax_read_unlock(id);
		return rc;
	}

    /* 2. access vto */
    /* alloc page */
    page = __page_cache_alloc(gfp_mask);
    if(!page)
    {
        return -1;
    }
    // TODO
    // 相对于 文件开头的偏移？
    //  __do_page_cache_readahead
    // page->index = 
    vto = page_to_pfn(page);

    /* 3. do copy */
    copy_page(vto, vfrom);
    dax_read_unlock(id);

    /* 4. adjust address_mapping */
    // page->mapping = mapping;
    // page->index = pgoff; // TODO 
    // mapping->nrpages++;
    return vto;
}


int migrate_nvm_to_dram(int nr, pgoff_t migration_pgoff)
{
    int error;
    // void* vfrom;
    // void* pfrom;
    struct pid* pid_struct;
    struct task_struct* task;
    struct vm_area_struct* vma;
    struct file *file;
    struct address_space *mapping;
    struct inode *inode;
    gfp_t gfp_mask;
    ssize_t pos_from;

    /* 1. find mm struct */
    pid_struct = find_get_pid(nr);
    task = pid_task(pid_struct,PIDTYPE_PID);
    BUG_ON(!task);
    vma = find_vma(task->mm, migration_pgoff);
    BUG_ON(vma);
    
    /* 2. find inode */
	file = vma->vm_file;
	// struct file *fpin = NULL;
	mapping = file->f_mapping;
	// struct file_ra_state *ra = &file->f_ra;
	inode = mapping->host;
    gfp_mask = readahead_gfp_mask(mapping);

    /* get bdev sector_from */
    struct iomap iomap_from = { 0 };
    unsigned flags_from = IOMAP_WRITE;
    pos_from = vma->vm_pgoff;
    // const struct iomap_ops *ops = &ext4_iomap_ops;

    // down_read(&EXT4_I(inode)->i_mmap_sem);
    error = ext4_iomap_begin(inode, pos_from, PAGE_SIZE, flags_from, &iomap_from);
    WARN_ON(error);
    sector_t sector_from = dax_iomap_sector(&iomap_from, pos_from);
    _do_migration(iomap_from.bdev, iomap_from.dax_dev, sector_from, migration_pgoff, gfp_mask);
    error =  ext4_iomap_end(inode, pos_from, PAGE_SIZE, PAGE_SIZE, flags_from, &iomap_from);
    WARN_ON(error);
    // up_read(&EXT4_I(inode)->i_mmap_sem);
    
    // err = remap_pfn_range(vma,vma->vm_start, pfn, PAGE_SIZE, vma->vm_page_prot);
    // BUG_ON(error < 0);

    // #ifdef DEBUG_MGR
    // // find page 
    // // check if migration done
    // page = pagecache_get_page();
    // #endif

    return 0;
}

int migrate_dram_to_dram(int pid, pgoff_t migration_pgoff)
{
    // void* vfrom;
    // void* pfrom;
    struct pid* pid_struct;
    struct task_struct* task;
    struct vm_area_struct* vma;
    struct file *file;
    struct address_space *mapping;
    struct inode *inode;
    gfp_t gfp_mask;
    pgd_t * pgd;
    p4d_t * p4d;
    pud_t * pud;
    pmd_t * pmd;
    pte_t  pte;
    struct page* page;
    void* vto;
    void* vfrom;

    /* 1. find mm struct */
    pid_struct = find_get_pid(pid);
    task = pid_task(find_pid_ns(pid, &init_pid_ns),PIDTYPE_PID);
    printk(KERN_ERR "migration %s\n", task->comm);
    BUG_ON(!task);
    if(task->mm == NULL)
    {
        printk(KERN_ERR"mm is null\n");
    }
           //mm指向当前进程	
	struct vm_area_struct* testvma = task->mm->mmap;
    printk(KERN_ERR"addr %lx\n", migration_pgoff);
    while(testvma)
    {
        printk(KERN_ERR"%lx, %lx\n", testvma->vm_start, testvma->vm_end);
        if(testvma->vm_start <= migration_pgoff && testvma->vm_end >= migration_pgoff)
        {
            vma = testvma;
        }
        testvma = testvma->vm_next;
    }
    vma = find_vma(task->mm, migration_pgoff);
    if(!vma)
    {
        printk(KERN_ERR "migration vma error\n");

    }
    // BUG_ON(vma);
    
    /* 2. find inode */
	file = vma->vm_file;
    if(!file)
    {
        printk(KERN_ERR"file null\n");
        return -1;
    }
	// struct file *fpin = NULL;
	mapping = file->f_mapping;
	// struct file_ra_state *ra = &file->f_ra;
    if(!mapping)
    {
        printk(KERN_ERR"mapping null\n");
        return -1;
    }
	inode = mapping->host;
    if(!inode)
    {
        printk(KERN_ERR"inode null\n");
        return -1;
    }
    gfp_mask = readahead_gfp_mask(mapping);

    /* 3. vfrom */
    pgd = pgd_offset(task->mm, migration_pgoff);
    if(pgd_none(*pgd) || pgd_bad(*pgd))
    {
        printk(KERN_ERR"pgd null\n");
        return -1;
    }
    p4d = p4d_offset(pgd, migration_pgoff);
    if(p4d_none(*p4d) || p4d_bad(*p4d))
    {
        printk(KERN_ERR"p4d null\n");
        return -1;
    }
    pud = pud_offset(p4d, migration_pgoff);
    if(pud_none(*pud) || pud_bad(*pud))
    {
        printk(KERN_ERR"pud null\n");
        return -1;
    }
    pmd = pmd_offset(pud, migration_pgoff);  
    if(pmd_none(*pmd) || pmd_bad(*pmd))
    {
        printk(KERN_ERR"pmd null\n");
        return -1;
    }
    pte = *pte_offset_map(pmd, migration_pgoff);  
    // pte = *pte_offset_kernel(pmd, migration_pgoff);
    page = pte_page(pte);
    unsigned long int temp = (pte_pfn(pte));
    vfrom = (void*)(temp << PAGE_SHIFT);
    printk(KERN_ERR"addr %llu\n", temp << PAGE_SHIFT);
    vfrom = kmap(page);

    // /* 4. vto */
    page = __page_cache_alloc(gfp_mask);
    if(!page)
    {
        return -1;
    }
    temp = page_to_pfn(page);
    vto = (void*)(temp << PAGE_SHIFT);

    // /* 3. do copy */
    vto = kmap(page);
    copy_page(vto, vfrom);
    printk(KERN_ERR"vto %c, vfrom %c\n", *((char*)vto), *((char*)vfrom));
    kunmap(vto);
    kunmap(vfrom);
    return 0;
}

void migrate_init(void)
{
    printk(KERN_ERR"Migration init !\n");
    ext4_iomap_begin = (int (*)(struct inode *, loff_t , loff_t ,
			    unsigned , struct iomap *))kallsyms_lookup_name("ext4_iomap_begin");
    ext4_iomap_end = (int (*)(struct inode *, loff_t , loff_t ,
			  ssize_t , unsigned , struct iomap *))kallsyms_lookup_name("ext4_iomap_end");
    printk(KERN_ERR"Migration init over !\n");
}

int mgr_init(void)
{
    printk(KERN_ERR "Module init: Hello linux kernel.\n");
    ext4_iomap_begin = (int (*)(struct inode *, loff_t , loff_t ,
			    unsigned , struct iomap *))kallsyms_lookup_name("ext4_iomap_begin");
    ext4_iomap_end = (int (*)(struct inode *, loff_t , loff_t ,
			  ssize_t , unsigned , struct iomap *))kallsyms_lookup_name("ext4_iomap_end");
    migrate_dram_to_dram(2015, 0x7f70e7cd5000);
    return (0);
}

void mgr_exit(void)
{
    printk(KERN_ERR "Module exit: Bye-bye linux kernel.\n");
}

#ifdef _MGR_DEBUG_

MODULE_LICENSE("GPL");
module_init(mgr_init);
module_exit(mgr_exit);

#endif
