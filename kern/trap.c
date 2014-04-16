#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>
#include <kern/sched.h>
#include <kern/kclock.h>
#include <kern/picirq.h>

static struct Taskstate ts;

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
struct Gatedesc idt[256] = { { 0 } };
struct Pseudodesc idt_pd = {
	sizeof(idt) - 1, (uint32_t) idt
};


static const char *trapname(int trapno)
{
	static const char * const excnames[] = {
		"Divide error",
		"Debug",
		"Non-Maskable Interrupt",
		"Breakpoint",
		"Overflow",
		"BOUND Range Exceeded",
		"Invalid Opcode",
		"Device Not Available",
		"Double Fault",
		"Coprocessor Segment Overrun",
		"Invalid TSS",
		"Segment Not Present",
		"Stack Fault",
		"General Protection",
		"Page Fault",
		"(unknown trap)",
		"x87 FPU Floating-Point Error",
		"Alignment Check",
		"Machine-Check",
		"SIMD Floating-Point Exception"
	};

	if (trapno < sizeof(excnames)/sizeof(excnames[0]))
		return excnames[trapno];
	if (trapno == T_SYSCALL)
		return "System call";
	if (trapno >= IRQ_OFFSET && trapno < IRQ_OFFSET + 16)
		return "Hardware Interrupt";
	return "(unknown trap)";
}


void
idt_init(void)
{
	extern struct Segdesc gdt[];
	
	// LAB 3: Your code here.
	      extern void divide_error();
		  extern void debug_exception();
		  extern void non_maskable_interrupt();
		  extern void breakpointPtr();
		  extern void overflow();
		  extern void bounds_check();
		  extern void illegal_opcode();
		  extern void device_not_available();
		  extern void double_fault();
		  extern void invalid_task_switch_segment();
		  extern void segment_not_present();
		  extern void stack_segment();
		  extern void general_protection_fault();
		  extern void page_fault();
		  extern void float_point_error();
		  extern void alignment_check();
		  extern void machine_check();
		  extern void SIMD_float_point_error();
		  
		  extern void sys_call();
		  
		  SETGATE(idt[T_DIVIDE],1,GD_KT,divide_error,0)
		  SETGATE(idt[T_DEBUG], 1,GD_KT,debug_exception,0)
		  SETGATE(idt[T_NMI],1,GD_KT,non_maskable_interrupt,0)
		  SETGATE(idt[T_BRKPT],1,GD_KT,breakpointPtr,3)
		  SETGATE(idt[T_OFLOW],1,GD_KT,overflow,0)
		  SETGATE(idt[T_BOUND],1,GD_KT,bounds_check,0)
		  SETGATE(idt[T_ILLOP],1,GD_KT,illegal_opcode,0)
		  SETGATE(idt[T_DEVICE],1,GD_KT,device_not_available,0)
		  SETGATE(idt[T_DBLFLT],1,GD_KT,double_fault,0)
		  SETGATE(idt[T_TSS],1,GD_KT,invalid_task_switch_segment,0)
		  SETGATE(idt[T_SEGNP],1,GD_KT,segment_not_present,0)
		  SETGATE(idt[T_STACK],1,GD_KT,stack_segment, 0)
		  SETGATE(idt[T_GPFLT],1,GD_KT,general_protection_fault,0)
		  SETGATE(idt[T_PGFLT],1,GD_KT,page_fault, 0) 
		  SETGATE(idt[T_FPERR],1,GD_KT,float_point_error,0)
		  SETGATE(idt[T_ALIGN],1,GD_KT,alignment_check,0)
		  SETGATE(idt[T_MCHK],1,GD_KT,machine_check,0)
		  SETGATE(idt[T_SIMDERR],1,GD_KT,SIMD_float_point_error,0)
		  
		  SETGATE(idt[T_SYSCALL],1, GD_KT, sys_call, 3)

    //lab4 
		  // hardware interrupts   
			extern void irq0_entry();  
			extern void irq1_entry();  
			extern void irq2_entry();  
			extern void irq3_entry();  
			extern void irq4_entry();  
			extern void irq5_entry();  
			extern void irq6_entry();  
			extern void irq7_entry();  
			extern void irq8_entry();  
			extern void irq9_entry();  
			extern void irq10_entry();	
			extern void irq11_entry();	
			extern void irq12_entry();	
			extern void irq13_entry();	
			extern void irq14_entry(); 
			extern void irq15_entry(); 

	 SETGATE(idt[IRQ_OFFSET], 0, GD_KT, irq0_entry, 0);  
    SETGATE(idt[IRQ_OFFSET+1], 0, GD_KT, irq1_entry, 0);  
    SETGATE(idt[IRQ_OFFSET+2], 0, GD_KT, irq2_entry, 0);  
    SETGATE(idt[IRQ_OFFSET+3], 0, GD_KT, irq3_entry, 0);  
    SETGATE(idt[IRQ_OFFSET+4], 0, GD_KT, irq4_entry, 0);  
    SETGATE(idt[IRQ_OFFSET+5], 0, GD_KT, irq5_entry, 0);  
    SETGATE(idt[IRQ_OFFSET+6], 0, GD_KT, irq6_entry, 0);  
    SETGATE(idt[IRQ_OFFSET+7], 0, GD_KT, irq7_entry, 0);  
    SETGATE(idt[IRQ_OFFSET+8], 0, GD_KT, irq8_entry, 0);  
    SETGATE(idt[IRQ_OFFSET+9], 0, GD_KT, irq9_entry, 0);  
    SETGATE(idt[IRQ_OFFSET+10], 0, GD_KT, irq10_entry, 0);  
    SETGATE(idt[IRQ_OFFSET+11], 0, GD_KT, irq11_entry, 0);  
    SETGATE(idt[IRQ_OFFSET+12], 0, GD_KT, irq12_entry, 0);  
    SETGATE(idt[IRQ_OFFSET+13], 0, GD_KT, irq13_entry, 0);  
    SETGATE(idt[IRQ_OFFSET+14], 0, GD_KT, irq14_entry, 0);  
	SETGATE(idt[IRQ_OFFSET+15], 0, GD_KT, irq14_entry, 0); 
	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	ts.ts_esp0 = KSTACKTOP;
	ts.ts_ss0 = GD_KD;

	// Initialize the TSS field of the gdt.
	gdt[GD_TSS >> 3] = SEG16(STS_T32A, (uint32_t) (&ts),
					sizeof(struct Taskstate), 0);
	gdt[GD_TSS >> 3].sd_s = 0;

	// Load the TSS
	ltr(GD_TSS);

	// Load the IDT
	asm volatile("lidt idt_pd");
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p\n", tf);
	print_regs(&tf->tf_regs);
	cprintf("  es   0x----%04x\n", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	cprintf("  err  0x%08x\n", tf->tf_err);
	cprintf("  eip  0x%08x\n", tf->tf_eip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	cprintf("  esp  0x%08x\n", tf->tf_esp);
	cprintf("  ss   0x----%04x\n", tf->tf_ss);
}

void
print_regs(struct PushRegs *regs)
{
	cprintf("  edi  0x%08x\n", regs->reg_edi);
	cprintf("  esi  0x%08x\n", regs->reg_esi);
	cprintf("  ebp  0x%08x\n", regs->reg_ebp);
	cprintf("  oesp 0x%08x\n", regs->reg_oesp);
	cprintf("  ebx  0x%08x\n", regs->reg_ebx);
	cprintf("  edx  0x%08x\n", regs->reg_edx);
	cprintf("  ecx  0x%08x\n", regs->reg_ecx);
	cprintf("  eax  0x%08x\n", regs->reg_eax);
}

static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	// LAB 3: Your code here.
	if(tf->tf_trapno==T_PGFLT){
		page_fault_handler(tf);
		return;
	}else
	    if(tf->tf_trapno==T_BRKPT){
		monitor(tf);
		return;
	}else 
	    if(tf->tf_trapno==T_SYSCALL){
		
		tf->tf_regs.reg_eax=syscall(
				tf->tf_regs.reg_eax,
				tf->tf_regs.reg_edx,
				tf->tf_regs.reg_ecx,
				tf->tf_regs.reg_ebx,
				tf->tf_regs.reg_edi,
				tf->tf_regs.reg_esi
				);
		
		return;
	}else
	// Handle clock interrupts.
	// LAB 4: Your code here.
	if(tf->tf_trapno==(IRQ_OFFSET+IRQ_TIMER)){
			
			sched_yield();
			return;
	}else
		

	// Handle spurious interupts
	// The hardware sometimes raises these because of noise on the
	// IRQ line or other reasons. We don't care.
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_SPURIOUS) {
		cprintf("Spurious interrupt on irq 7\n");
		print_trapframe(tf);
		return;
	}


	// Unexpected trap: The user process or the kernel has a bug.
	print_trapframe(tf);
	if (tf->tf_cs == GD_KT)
		panic("unhandled trap in kernel");
	else {
		env_destroy(curenv);
		return;
	}
}

void
trap(struct Trapframe *tf)
{
	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		assert(curenv);
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		tf = &curenv->env_tf;
	}
	
	// Dispatch based on what type of trap occurred
	trap_dispatch(tf);

	// If we made it to this point, then no other environment was
	// scheduled, so we should return to the current environment
	// if doing so makes sense.
	if (curenv && curenv->env_status == ENV_RUNNABLE)
		env_run(curenv);
	else
		sched_yield();
}


void
page_fault_handler(struct Trapframe *tf)
{
	uint32_t fault_va;

	// Read processor's CR2 register to find the faulting address
	fault_va = rcr2();

	// Handle kernel-mode page faults.
	
	// LAB 3: Your code here.
	if ((tf->tf_cs & 3) != 3) panic("kenel mode page fault");

	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.

	// Call the environment's page fault upcall, if one exists.  Set up a
	// page fault stack frame on the user exception stack (below
	// UXSTACKTOP), then branch to curenv->env_pgfault_upcall.
	//
	// The page fault upcall might cause another page fault, in which case
	// we branch to the page fault upcall recursively, pushing another
	// page fault stack frame on top of the user exception stack.
	//
	// The trap handler needs one word of scratch space at the top of the
	// trap-time stack in order to return.  In the non-recursive case, we
	// don't have to worry about this because the top of the regular user
	// stack is free.  In the recursive case, this means we have to leave
	// an extra word between the current top of the exception stack and
	// the new stack frame because the exception stack _is_ the trap-time
	// stack.
	//
	// If there's no page fault upcall, the environment didn't allocate a
	// page for its exception stack or can't write to it, or the exception
	// stack overflows, then destroy the environment that caused the fault.
	//
	// Hints:
	//   user_mem_assert() and env_run() are useful here.
	//   To change what the user environment runs, modify 'curenv->env_tf'
	//   (the 'tf' variable points at 'curenv->env_tf').

	// LAB 4: Your code here.
	struct UTrapframe *utrap_frame;   
			 
		if(curenv->env_pgfault_upcall!=NULL){
			   
		if(tf->tf_esp>UXSTACKTOP-PGSIZE && tf->tf_esp<UXSTACKTOP)
		{
		  //In the recursive
		utrap_frame=(struct UTrapframe *)(tf->tf_esp-sizeof(struct UTrapframe)-4);	   
		}else{
		  //In the non-recursive
		  utrap_frame=(struct UTrapframe *)(UXSTACKTOP-sizeof(struct UTrapframe));
			
		}
			  //Check the perm of UTrapframe
	   user_mem_assert(curenv,utrap_frame,sizeof(struct UTrapframe),PTE_P|PTE_U|PTE_W);
			  
			  //Push the UTrapframe
					   utrap_frame->utf_fault_va=fault_va;
					   utrap_frame->utf_err=tf->tf_trapno;
					   utrap_frame->utf_regs=tf->tf_regs;
					   utrap_frame->utf_eip=tf->tf_eip;
					   utrap_frame->utf_eflags=tf->tf_eflags;
					   utrap_frame->utf_esp=tf->tf_esp;
					   tf->tf_eip=(uintptr_t)(curenv->env_pgfault_upcall);
					   tf->tf_esp=(uintptr_t)utrap_frame;
					   env_run(curenv);
			  
			  }

	// Destroy the environment that caused the fault.
	cprintf("[%08x] user fault va %08x ip %08x\n",
		curenv->env_id, fault_va, tf->tf_eip);
	print_trapframe(tf);
	env_destroy(curenv);
}

