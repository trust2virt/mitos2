// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;
   // cprintf("pgfault-->>**%08x\n",addr);

   // Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at vpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
	pte_t pte =vpt[VPN(addr)];
		if((err & FEC_WR)== 0 || (pte & PTE_COW) == 0) {
			panic("lib/pgfault.c: bad page fault at %08x err %08x\n", addr, err);
			return;
		}

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.
	//   No need to explicitly delete the old page's mapping.

	// LAB 4: Your code here.

	if ((r = sys_page_alloc(0, PFTEMP,PTE_USER)) < 0)
		panic("pgfault page allocate for PFTEMP error\n");

	memmove(PFTEMP, ROUNDDOWN(addr, PGSIZE), PGSIZE);
	
	if ((r = sys_page_map(0, PFTEMP, 0, ROUNDDOWN(addr, PGSIZE), PTE_USER)) < 0)
		panic("pgfault page map for PFTEMP error\n");

	sys_page_unmap(0, PFTEMP);
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why might we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
// 
static int
duppage(envid_t envid, unsigned pn)
{
	int r; 
	void *addr; 
	// LAB 4: Your code here. 
	 
	addr = (void *)(pn * PGSIZE); 
	
    if ((r = sys_page_map(0, addr, envid, addr, PTE_P | PTE_U | PTE_COW)) < 0) 
			return r; 
	if ((r = sys_page_map(envid, addr, 0, addr, PTE_P | PTE_U | PTE_COW)) < 0) 
			return r; 
	   
		   return 0; 
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use vpd, vpt, and duppage.
//   Remember to fix "env" and the user exception stack in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{ 

   envid_t envid; 
   int r; 
   uint32_t pdeno, pteno;
   uint32_t pa;
   void *addr;
		 
   set_pgfault_handler(pgfault);

   envid = sys_exofork(); 
    if (envid < 0)  
       panic("fork: unable to create new env.\n"); 

	 // child 
    if (envid == 0) { 
       env = &envs[ENVX(sys_getenvid())];
        return 0; 
         } 
    // parent 
     env = &envs[ENVX(sys_getenvid())];
     for (pdeno = 0; pdeno < PDX(UTOP); pdeno++)
     {
	  if ((vpd[pdeno] & PTE_P)==0)
			     continue;
	  
      for (pteno = 0; pteno <NPTENTRIES; pteno++) 
	  {
	  // skip exception stack 
       if ((pteno * PGSIZE + pdeno * PTSIZE) == (UXSTACKTOP - PGSIZE))  
            continue;

	   pa=vpt[pdeno*NPTENTRIES+pteno];

	   if((pa&PTE_P)&&(pa&PTE_U))
        {
          duppage(envid,pdeno*NPTENTRIES+pteno);
		  //cprintf("fork-->>%08x\n",(pdeno*NPTENTRIES+pteno)*PGSIZE);
		}
	  }    
		          
     }
  
    if ((r = sys_page_alloc(envid, (void *)(UXSTACKTOP - PGSIZE), PTE_P | PTE_U | PTE_W)) < 0) 
         panic("fork: exception stack allocate error\n"); 
          
    extern void _pgfault_upcall(void); 
    if ((r = sys_env_set_pgfault_upcall(envid, _pgfault_upcall)) < 0) 
           panic("fork:  set pgfault upcall error\n");
		 
    if ((r = sys_env_set_status(envid, ENV_RUNNABLE)) < 0) 
           panic("fork: set env status error\n"); 

    sys_yield();
		 
    return envid; 
		
}

// Challenge! 
int 
sfork(void) 
{ 
		panic("sfork not implemented"); 
		return -E_INVAL; 
}  

