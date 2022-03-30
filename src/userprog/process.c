#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hash.h>
#include <list.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"

// #define PSS_DEBUG

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static void * load_arguments (struct cmdline_tokens* tok);

/** Helper struct for creating a process. 
    Fits in one page. */
struct proc_start_page
  {
    char cmdline[CMD_BUFFER_SIZE];    /**< Buffer for command line. */
    struct cmdline_tokens tok;        /**< Buffer for parsed tokens. */
    struct semaphore loaded;          /**< For syncing between parent and child. */
    bool success;                     /**< Whether child is loaded successfully. */
  };

/** Starts a new thread running a user program loaded from
   FILENAME. Returns the new process's thread id, or TID_ERROR 
   if the thread cannot be created or loaded.
   The new thread may be scheduled (and may even exit)
   before process_execute() returns. However, it is guaranteed
   to block until the new process is loaded (or fails to do so). */
tid_t
process_execute (const char *file_name) 
{
  struct proc_start_page *page;
  tid_t tid;

  /* Parse FILE_NAME into [prog] [arg1, arg2, ...].
     First make a copy of FILE_NAME, otherwise there's a race between 
     the caller and load(). */
  page = palloc_get_page (0);
  if (page == NULL)
    return TID_ERROR;
  strlcpy (page->cmdline, file_name, CMD_BUFFER_SIZE);

  /* Parse command line. It is modified in place. */
  int state = cmd_parseline(page->cmdline, &page->tok);

  /* Parsing error or FILE_NAME is empty. */
  if (state == -1 || page->tok.argc == 0)
    {
      tid = TID_ERROR;
      printf ("process_execute: parsing error\n");
      goto done;
    }

  sema_init (&page->loaded, 0);                                        

  /* Create a new thread to execute FILE_NAME. The arguments are loaded 
     in start_process(), as now the thread's PD is not created and activated
     yet, let alone its stack. */
  tid = thread_create ((const char *)page, PRI_DEFAULT, start_process, page);
  sema_down (&page->loaded);

  /* If loading fails, also return -1. */
  if (!page->success)
    tid = TID_ERROR;

 done:
  palloc_free_page (page);

  /* By now the child's PSS is allocated, and registered in parent's 
     children list. Both can exit freely now. */ 

  return tid;
}

/** A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  struct proc_start_page *page = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  /* FILE_NAME is effectively the program name because cmd_parseline() 
     NULL terminates each token. */
  success = load (page->cmdline, &if_.eip, &if_.esp);

  /* Notify parent about loading result. */
  page->success = success;
  sema_up (&page->loaded);

  /* After load() activates the process's PD, we now load arguments onto
     the USER STACK of the process, and set if_.esp so that later return
     from the intr_frame correctly jumps to the USER STACK. */
  if (success)
    if_.esp = load_arguments (&page->tok);
  else
    {
      struct thread *t = thread_current ();
      ASSERT (t->pss != NULL);
      t->pss->status = -1;
      thread_exit ();  
    }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/** Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting. */
int
process_wait (tid_t child_tid)
{
  if (child_tid == TID_ERROR)
    goto bad_wait;
  
  /* Go through the children list to see if child_tid is valid. */
  struct thread *cur = thread_current ();
  struct list_elem *e;
  bool found = false;
  for (e = list_begin (&cur->children); e != list_end (&cur->children);
       e = list_next (e))
    {
      if (list_entry (e, struct proc_stat_slot, elem)->tid == child_tid)
        {
          found = true;
          break;
        }
    }
  if(!found)
    goto bad_wait;

  /* Valid child_tid; wait by DOWNing its CNT. */
  struct proc_stat_slot *pss = list_entry (e, struct proc_stat_slot, elem);
  sema_down(&pss->cnt);

  /* By now child has passed its status. */
  int status = pss->status;

  /* Free the PSS, and remove from children list. 
     As CNT is downed, child (which might not have completely exited)
     will not find CNT == 2, hence no double freeing. Parent will also
     not access freed PSS when exiting, as it is removed. */
  list_remove (e);
#ifdef PSS_DEBUG
  printf ("%s freed slot %d\n", cur->name, pss->tid);
#endif 
  free (pss);

  return status;
 
 bad_wait:
  return -1;
}

/** Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Manage the process status slots. */
  struct proc_stat_slot *pss = cur->pss;
  
  int status = 0;
  if (pss != NULL)
    status = pss->status;

  do {
    /* The initial thread did not allocate a PSS, so don't
       free it. */
    if (pss == NULL)
      continue;

    /* If CNT reaches 2, both parent and child exited. */
    if (sema_up (&pss->cnt) == 2)
      {
        /* Reuse CNT to ensure only one of parent and child
           frees the slot. */
        bool success = sema_try_clear (&pss->cnt);
        if (success)
          {
#ifdef PSS_DEBUG
            printf ("%s freed slot %d\n", cur->name, pss->tid);
#endif 
            free (pss);
          }
      }
    
    /* Note that when process_wait() is interleaved here, once
       sema_up() returns, pss can be invalid anytime (as it is
       freed). However, the new value for CNT then will not be
       2, so subsequent references to pss is bypassed. */
  
  /* Subsequently UPs all children's CNT. */
  } while (!list_empty (&cur->children) &&
           (pss = list_entry (list_pop_front (&cur->children), 
                              struct proc_stat_slot, elem)));


  /* Interestingly (and reassuringly), user processes can only acquire
     locks via controlled ways, i.e. the syscall (printf(), for example,
     boils down to WRITE, which then acquires the console lock in 
     kernel). Hence, as long as we check for memory validity thoroughly
     at syscall handlers, we don't need to worry about process exiting
     before it releases its lock. */


  /* Close opened files. */
  lock_acquire (&filesys_lock);

  /* Close the file of current process, thus re-enabling writes. */
  file_close (cur->file_self);

  if (cur->fdt != NULL)
    {
      for (unsigned int i = STDOUT_FILENO + 1; 
           i < (sizeof (struct fd_table)>>2); i++)
        {
          if (cur->fdt->fde[i] != NULL)
            file_close (cur->fdt->fde[i]);
        }
      /* Finally, free the FDT page. */
      palloc_free_page (cur->fdt);
    }

  lock_release (&filesys_lock);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Which means current thread is also a user process.
         Print termination message. */
      printf ("%s: exit(%d)\n", cur->name, status);

      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/** Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/** We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/** ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/** For use with ELF types in printf(). */
#define PE32Wx PRIx32   /**< Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /**< Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /**< Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /**< Print Elf32_Half in hexadecimal. */

/** Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/** Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/** Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /**< Ignore. */
#define PT_LOAD    1            /**< Loadable segment. */
#define PT_DYNAMIC 2            /**< Dynamic linking info. */
#define PT_INTERP  3            /**< Name of dynamic loader. */
#define PT_NOTE    4            /**< Auxiliary info. */
#define PT_SHLIB   5            /**< Reserved. */
#define PT_PHDR    6            /**< Program header table. */
#define PT_STACK   0x6474e551   /**< Stack segment. */

/** Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /**< Executable. */
#define PF_W 2          /**< Writable. */
#define PF_R 4          /**< Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/** Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  lock_acquire (&filesys_lock);

  t->file_self = file = filesys_open (file_name);
  /* Deny writes to executable. */
  if (file != NULL)
    file_deny_write (file);
  else
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  
  /* For denying writes to executables, the process file must keep 
     opened, and gets closed when it finishes running. */
  if(!success)
    /* Closing NULL is allowed. */
    {
      file_close (file);
      t->file_self = NULL;
      /* ... so that process_exit() will not close it again. */
    }
  
  lock_release (&filesys_lock);
  return success;
}

/** load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/** Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/** Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/** Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/** Load the process program arguments at the top of its stack. 
    Only invoked in start_process() after setup_stack() and before
    process program runs for the first time. 
    Returns the new stack top. */
static void *
load_arguments (struct cmdline_tokens* tok)
{
  /* Loading starts at stack top. */
  uint32_t top = (uint32_t) PHYS_BASE;

  /* Load the actual strings */
  int argc = tok->argc;
  for (int i = argc - 1; i >= 0; i--)
    {
      /* Include terminating '\0'. */
      size_t len = strlen (tok->argv[i]) + 1;
      top -= len;
      strlcpy ((char *)top, tok->argv[i], len);

      /* Set argv[i] for later loading. */
      tok->argv[i] = (char *)top;
    }
  
  /* Word alignment*/
  top -= top % sizeof (void *);

  /* Load ARGV[i], including the terminating NULL */
  for (int i = argc; i >= 0; i--)
    {
      top -= sizeof (char *);
      *(char **)top = tok->argv[i];
    }
  
  /* Load ARGV */
  char **argv = (char **)top;
  top -= sizeof (char **);
  *(char ***)top = argv;

  /* Load ARGC */
  top -= sizeof (int);
  *(int *)top = tok->argc;

  /* Load dummy return address */
  top -= sizeof (void *);
  *(void **)top = NULL;

  return (void *) top;
}

/** Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
