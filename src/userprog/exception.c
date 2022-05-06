#include "userprog/exception.h"
#include "userprog/process.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include <string.h>
#ifdef VM
#include "vm/mm.h"
#include "vm/frame.h"
#include "vm/mapfile.h"
#include "vm/swap.h"

extern struct lock frame_table_lock;

#endif

/** Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/** Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/** Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/** Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);

      /* Killed by kernel, return status must be -1. */
      struct proc_stat_slot *pss = thread_current ()->pss;
      ASSERT (pss != NULL);
      pss->status = -1;

      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/** Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /**< True: not-present page, false: writing r/o page. */
  bool write;        /**< True: access was write, false: access was read. */
  bool user;         /**< True: access by user, false: access by kernel. */
  void *fault_addr;  /**< Fault address. */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

	struct thread *cur = thread_current ();

/* Without VM, only handle the special case where syscall handler
   PF. User processes are always killed when PF. */
#ifndef VM
	/* For kernel page faults during a syscall, we want to send error
     code back to the faulting access, which is done in tandem with
     get_user() and put_user() calls. 

     Specifically, we expect f->eax to hold the first instruction 
     after the faulting instruction, so that we set f->eip to it
     in order to skip the faulting access. We also set f->eax to
     be -1 as error code. */
	if (cur->syscall && !user) 
  	{
      f->eip = (void (*) (void)) f->eax;
      f->eax = -1;
      return;
  	}
  /* If the fault comes from kernel code, kill() will panic. */
  kill (f);
  printf ("Page fault at %p: %s error %s page in %s context.\n",
          fault_addr,
          not_present ? "not present" : "rights violation",
          write ? "writing" : "reading",
          user ? "user" : "kernel");

/* With VM, kernel PF still PANIC (given it's not from syscall handler). 
	 User PF, on the other hand, is more involved. */ 
#else 
	/* Kernel threads should never cause PF. */
	if (cur->pagedir == NULL)
		{
			kill (f);
			goto done;
		}

	if (fault_addr >= PHYS_BASE)
		goto bad_access;

	/* If PF happens at user access, read ESP from interrupt frame; otherwise, 
	   cur->esp is set by syscall handler at entrance. */
	if (user)
		cur->esp = f->esp;

	/* First, locate relevant VMA. */
	struct list_elem *e;
	struct vm_area *vma = NULL;
  for (e = list_begin (&cur->vma_list); e != list_end (&cur->vma_list);
       e = list_next (e))
		{
			vma = list_entry (e, struct vm_area, proc_elem);
			if (vma->upper_bound > fault_addr)
				{
					if (vma->lower_bound > fault_addr)
						/* Access to unmapped area. */
						goto bad_access;
					else
						break;
				}
		}
	if (vma == NULL)
		goto bad_access;
	
	/* VMA_LIST is sorted by virtual address in increasing order, 
		 so the last VMA is always stack. */
	bool is_stack = (list_next (&vma->proc_elem) == list_end (&cur->vma_list));

	/* Then check for permission. Note that NOT_PRESENT is not 
	   reliable here, as frame_evict() can interleave and page out
		 this frame, so we double check down below. */
	if (!not_present) 
		{
			lock_acquire (&frame_table_lock);
			void *from_page = pg_round_down (pagedir_get_page (cur->pagedir, fault_addr));
			struct frame *from_frame = phys_to_frame (from_page);
			if (from_page == NULL)
				{
					/* The frame is in fact evicted. Restart PF. */
					lock_release (&frame_table_lock);
					goto done;
				}
			else
				{
					/* ...or it remains resident. For COW purposes, temporarily
					   PIN this frame. */
					if (!frame_set_pinned (from_frame))
						{
							lock_release (&frame_table_lock);
							goto done;
						}
					lock_release (&frame_table_lock);
				}

			/* PF must be caused by writing a read-only page. */
			if ((vma->flags & MAP_PRIVATE) && (vma->flags & MAP_WRITE))
				{
					/* COW happens here. */
					void *to_page = anon_get_page (vma, vma->offset + (pg_round_down (fault_addr) 
																													- vma->lower_bound));
					if (to_page == NULL)
						{
							frame_clear_pinned (from_frame);
							goto done;
						}
					
					memcpy (to_page, from_page, PGSIZE);

					/* Set the PTE in current process to the new frame, 
					   marking it writable. 
             The PTE must be cleared first, to flush the TLB! */
					pagedir_clear_page (cur->pagedir, pg_round_down (fault_addr), 
															0, AVL_INVALID);
          pagedir_set_page (cur->pagedir, pg_round_down (fault_addr), 
							 							to_page, true);
					pagedir_set_accessed (cur->pagedir, fault_addr, true);
					frame_clear_pinned (from_frame);
					frame_clear_busy (phys_to_frame (to_page));
#ifdef FRAME_DEBUG
					printf ("%d COW on address %p, from frame %p, to frame %p\n", 
									thread_tid(), fault_addr, from_page, to_page);
#endif
					goto done;
				}
				
			/* Else, it's permission violation. */
			frame_clear_pinned (phys_to_frame (from_page));
			goto bad_access;
		}

	/* Now, must be fetching a non-resident page. */
	int how = pagedir_get_avl (cur->pagedir, fault_addr);
	int aux = pagedir_get_aux (cur->pagedir, fault_addr);
	void *page;
	bool writable;
	switch (how)
		{
		case AVL_INVALID: 
			/* Should not happen. PANIC the kernel. */
			PANIC ("%d PF handler: unsure how to fetch page %p", 
							thread_tid(), fault_addr);

		case AVL_INFILE:
			/* Find in backing file. */
			ASSERT (vma_is_filebacked (vma));
			page = mapfile_get_page (vma->mapfile, 
						 vma->offset + (pg_round_down (fault_addr) - vma->lower_bound),
						 aux, fault_addr);
			if (page == NULL)
				goto done;
			writable = pagedir_is_writable (cur->pagedir, fault_addr);
			pagedir_set_page (cur->pagedir, pg_round_down (fault_addr), 
							 					page, writable);
			pagedir_set_accessed (cur->pagedir, fault_addr, true);
			frame_clear_busy (phys_to_frame (page));
#ifdef FRAME_DEBUG
			printf ("%d Fetch from FILE on address %p, to frame %p\n", 
              thread_tid(), fault_addr, page);
#endif
			break;
		
		case AVL_INSWAP:
			/* Find in swap. */
			page = swap_get_page (vma, 
						 vma->offset + (pg_round_down (fault_addr) - vma->lower_bound),
						 aux);
			if (page == NULL)
				goto done;
			writable = pagedir_is_writable (cur->pagedir, fault_addr);
			pagedir_set_page (cur->pagedir, pg_round_down (fault_addr), 
							 					page, writable);
			pagedir_set_accessed (cur->pagedir, fault_addr, true);
			frame_clear_busy (phys_to_frame (page));
#ifdef FRAME_DEBUG
			printf ("%d Fetch from SWAP(%d) on address %p, to frame %p\n", 
              thread_tid(), aux, fault_addr, page);
#endif
			break;
		
		case AVL_ZEROED:
			/* The stack growth heuristic is implemented here. */
			if (is_stack)
				{
					ASSERT (cur->esp != NULL);
					/* Only allow for normal accesses, push and pusha instructions. */
					if (!(fault_addr >= cur->esp || fault_addr == cur->esp - 4 ||
					    	fault_addr == cur->esp - 32))
						goto bad_access;
				}

			/* Page should be zeroed. */
			page = anon_get_page (vma, vma->offset + (pg_round_down (fault_addr) 
																						 - vma->lower_bound));
			if (page == NULL)
				goto done;
			memset (page, 0, PGSIZE);

			writable = pagedir_is_writable (cur->pagedir, fault_addr);
			pagedir_set_page (cur->pagedir, pg_round_down (fault_addr), 
							 					page, writable);
			pagedir_set_accessed (cur->pagedir, fault_addr, true);
			frame_clear_busy (phys_to_frame (page));
#ifdef FRAME_DEBUG
			printf ("%d Zeroed page on address 0x%p, to frame %p\n", 
              thread_tid(), fault_addr, page);
#endif
			break;
		
		default:
			/* Should not happen. PANIC the kernel. */
			PANIC ("%d PF handler: AVL field corrupted", thread_tid());
		}

	done:
	/* Restart the same faulting instruction. 
		 Might PF immediately again, if COW, or this PF cannot fetch the
		 page right away. */
	return;

	bad_access:
	if (cur->syscall && !user) 
  	{
			/* If from syscall handler, set the error code as -1, 
	   		 when access is invalid (not in VMA; permission violation). */
      f->eip = (void (*) (void)) f->eax;
			f->eax = -1;
			return;
		}
	else
		{
			/* Otherwise, just kill the faulting thread. */
			printf ("Page fault at %p: %s error %s page in %s context.\n",
          		fault_addr,
          		not_present ? "not present" : "rights violation",
          		write ? "writing" : "reading",
          		user ? "user" : "kernel");
			kill (f);
			return;
		}
	
#endif   
}

