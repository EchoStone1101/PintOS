#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <user/syscall.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/init.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/directory.h"
#ifdef VM
#include "vm/mm.h"
#include "vm/frame.h"
#include "vm/mapfile.h"
#include "pagedir.h"
#include "devices/timer.h"
extern struct lock frame_table_lock;
#endif

static void syscall_handler (struct intr_frame *);

static const int args_length [] = {
  0, // SYS_HALT                
  1, // SYS_EXIT                
  1, // SYS_EXEC                
  1, // SYS_WAIT                  
  2, // SYS_CREATE                 
  1, // SYS_REMOVE             
  1, // SYS_OPEN                
  1, // SYS_FILESIZE              
  3, // SYS_READ                   
  3, // SYS_WRITE                  
  2, // SYS_SEEK                   
  1, // SYS_TELL                   
  1, // SYS_CLOSE     
  2, // SYS_MMAP                  
  1, // SYS_MUNMAP  

  /* Not implemented yet */                  
  0, // SYS_CHDIR                 
  0, // SYS_MKDIR                
  0, // SYS_READDIR                
  0, // SYS_ISDIR                 
  0, // SYS_INUMBER                
};

static void syscall_halt (void);
static void syscall_exit (int status);
static pid_t syscall_exec (const char *cmd_line);
static int syscall_wait (pid_t pid);
static bool syscall_create (const char *file, unsigned initial_size);
static bool syscall_remove (const char *file);
static int syscall_open (const char *file);
static int syscall_filesize (int fd);
static int syscall_read (int fd, void *buffer, unsigned size);
static int syscall_write(int fd, const void *buffer, unsigned size);
static void syscall_seek (int fd, unsigned position);
static unsigned syscall_tell (int fd);
static void syscall_close (int fd);
static mapid_t syscall_mmap (int fd, void *addr);
static void syscall_munmap (mapid_t mapid);

/* Placeholder for un-implemented syscalls. */
static void syscall_unhandled (void);

static const void * syscall_worker [] = {
  syscall_halt, syscall_exit, syscall_exec, syscall_wait, syscall_create,
  syscall_remove, syscall_open, syscall_filesize, syscall_read, syscall_write,
  syscall_seek, syscall_tell, syscall_close,
  syscall_mmap, syscall_munmap, syscall_unhandled, syscall_unhandled,
  syscall_unhandled, syscall_unhandled, syscall_unhandled,
};

extern struct lock filesys_lock;

#ifdef VM
/** Unpin the user buffer spanning from UADDR for up to MAXLEN 
    bytes. We expect consecutive frames starting from UADDR to
    be present and PINNED. */
static void
unpin_user_buffer (const char * uaddr, size_t maxlen, bool is_string)
{
  bool early_stop = !(uaddr < (const char *)PHYS_BASE) || maxlen == 0;
  void *phys_addr;
  struct frame *f = NULL;
  struct thread *cur = thread_current ();
  ASSERT (cur->want_pinned == false);
  lock_acquire (&frame_table_lock);
  for (unsigned i = 0; !early_stop; i++)
    {
      if (i == 0 || (int32_t)(uaddr + i) % PGSIZE == 0)
        {
          void *page = (void*)((int)(uaddr + i) & (~PGMASK));
          phys_addr = pagedir_get_page (cur->pagedir, page);
          if (phys_addr != NULL)
            {
              f = phys_to_frame (phys_addr);
              ASSERT (frame_pinned (f));
            }
          else
            {
              if (f != NULL)
                {
                  frame_clear_pinned (f);
                }
              lock_release (&frame_table_lock);
              return;
            }
        }
      if ((is_string && *(uaddr + i) == '\0') || i == maxlen - 1 || 
           (uaddr + i + 1) >= (const char *)PHYS_BASE)
        early_stop = true;
      if (early_stop || (int32_t)(uaddr + i + 1) % PGSIZE == 0)
        {
          frame_clear_pinned (f);
        }
    }
  lock_release (&frame_table_lock);
}
#endif

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr) 
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
} 

/* Reads a word at user virtual address UADDR, stored to DST.
   Checks that the entire access is below PHYS_BASE, then invokes
   get_user() to actually read. Useful in reading arguments from
   user address space.
   Returns false if access surpasses PHYS_BASE or segfault occurred. */
static bool
get_user_word (const uint8_t *uaddr, int32_t *dst) 
{
  if ((void *)uaddr + sizeof(int) >= PHYS_BASE)
    return false;
  
  uint8_t *_dst = (uint8_t *)dst;
  for (unsigned i = 0; i < sizeof(int); i++)
    {
      int result = get_user (uaddr);
      if (result == -1)
        return false;

      *_dst = (uint8_t)result; 
      _dst++;
      uaddr++;
    }
  return true;
}

/* Checks for the validity of READABLE buffer starting from UADDR, spanning 
   at most MAXLEN bytes. Lack of '\0' is tolerated, requiring subsequent 
   operations to check for the length or terminate the string themselves.
   Returns false if access surpasses PHYS_BASE or segfault occurred. */
static bool
check_user_read_buffer (const char * uaddr, size_t maxlen, bool is_string) 
{
#ifdef VM
  struct thread *cur = thread_current ();
  cur->want_pinned = true;
#endif

  for (unsigned i = 0; i < maxlen; i++)
    {
      int ch;

/* With VM, must also PIN the user buffer, if valid, so that it is not
   evicted during later I/O by syscall workers. 
   For every UADDR that is page-aligned, by holding frame_table_lock, PTE
   can be examined without racing. If it is present, FRAME can be directly
   located and PINNED. Otherwise, later access causes PF, where we make the
   handler PIN the frame after paging-in. */
#ifdef VM 
      if ((i == 0 || (int32_t)(uaddr + i) % PGSIZE == 0)
          && uaddr + i < (const char *)PHYS_BASE)
        {
          lock_acquire (&frame_table_lock);
          void *page = (void*)((int)(uaddr + i) & (~PGMASK));
          void *phys_addr;
          retry:
          phys_addr = pagedir_get_page (cur->pagedir, page);
          if (phys_addr != NULL)
            {
              struct frame *f = phys_to_frame (phys_addr);
              if (!frame_set_pinned (f))
                {
                  lock_release (&frame_table_lock);
                  timer_msleep (10);
                  lock_acquire (&frame_table_lock);
                  goto retry;
                }
            }
          lock_release (&frame_table_lock);
        }
#endif
      /* Bad buffer. */
      if (uaddr + i >= (const char *)PHYS_BASE ||
         ((ch = get_user ((uint8_t *)uaddr + i)) == -1))
        {
#ifdef VM
          cur->want_pinned = false;
          unpin_user_buffer (uaddr, maxlen, is_string);
#endif
          return false;
        }

      /* ... or it actually is valid. */
      if (ch == '\0' && is_string)
        break;
    }

#ifdef VM
  cur->want_pinned = false;
#endif
  return true;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte) 
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/* Checks for the validity of WRITABLE buffer starting from UADDR, spanning 
   at most MAXLEN bytes. 
   Returns false if access surpasses PHYS_BASE or segfault occurred. */
static bool
check_user_write_buffer (const char * uaddr, size_t maxlen) 
{
#ifdef VM
  struct thread *cur = thread_current ();
  cur->want_pinned = true;
#endif

  for (unsigned i = 0; i < maxlen; i++)
    {
#ifdef VM 
      if ((i == 0 || (int32_t)(uaddr + i) % PGSIZE == 0)
          && uaddr + i < (const char *)PHYS_BASE)
        {
          lock_acquire (&frame_table_lock);
          void *page = (void*)((int)(uaddr + i) & (~PGMASK));
          void *phys_addr;
          retry:
          phys_addr = pagedir_get_page (cur->pagedir, page);
          if (phys_addr != NULL)
            {
              struct frame *f = phys_to_frame (phys_addr);
              if (!frame_set_pinned (f))
                {
                  lock_release (&frame_table_lock);
                  timer_msleep (10);
                  lock_acquire (&frame_table_lock);
                  goto retry;
                }
            }
          lock_release (&frame_table_lock);
        }
#endif
      /* Bad buffer. */
      if (uaddr + i >= (const char *)PHYS_BASE || 
          !put_user ((uint8_t *)uaddr + i, 0))
        {
#ifdef VM
          cur->want_pinned = false;
          unpin_user_buffer (uaddr, maxlen, false);
#endif
          return false;
        }
    }

#ifdef VM
  cur->want_pinned = false;
#endif
  return true;
}

/* Checks for the validity of FD as an opened FD.
   Returns true if valid, false if not. */
static bool
fd_valid (int fd)
{
  /* STDIN and STDOUT are always valid. */
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
    return true;
  
  /* Range check. */
  if (fd < 0 || fd >= (int)(sizeof (struct fd_table)>>2))
    return false;

  struct thread *t = thread_current ();
  if (t->fdt == NULL || t->fdt->fde[fd] == NULL)
    return false;

  return true;
}

/* Terminated current process for misconduct.
   Set its return status to -1. */
static void
syscall_terminate (void)
{
  struct thread *t = thread_current ();
#ifdef VM
  t->want_pinned = false;
  t->syscall = false;
#endif
  ASSERT (t->pss != NULL);
  t->pss->status = -1;
  thread_exit ();
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
}

/* The registered syscall handler. Reads the syscall number and
   the arguments, and invoke corresponding fucntions to actually
   do the work. */
static void
syscall_handler (struct intr_frame *f) 
{
  /* Set syscall to true before any memory access to user memory. */
  struct thread *t = thread_current ();
  t->syscall = true;
#ifdef VM
  t->esp = f->esp;
#endif

  /* Read the syscall number */
  void *user_stack = f->esp;
  int syscall_no;
  if (!get_user_word (user_stack, &syscall_no))
    syscall_terminate ();
  
  /* The caller's stack should now be formatted as:
                [ arg3 ]
                [ arg2 ]
                [ arg1 ]
              [syscall_no]
     To avoid explicitly casting these arguments to their due types
     for every syscall, we instead simply load them to kernel stack
     and use assembly CALL to invoke the actual handlers. */

  /* Unexpected syscall number. Terminate the caller process. */
  if (!(syscall_no >= SYS_HALT && syscall_no <= SYS_INUMBER))
    syscall_terminate ();
  
  struct syscall_frame
    {
      /* ARGS at bottom to be passed to workers. OLD_ESP and RET
         at top, saved from the frame of worker. */
      void *args[3];
      void *old_esp;
      unsigned ret;
    } syscall_f;

  for (int i = 0; i < args_length[syscall_no]; i++)
    {
      user_stack += sizeof(int);
      if (!get_user_word (user_stack, (int32_t *)&syscall_f.args[i]))
        syscall_terminate ();
    }

  /* Assembly magic to call worker with ARGS as arguments.
     Basically, the worker is invoked with assembly "call", bypassing
     any type check / conversion needed. Point %esp to start of ARGS,
     issue "call", restore %esp, and it's done. */
  asm ("movl %%esp, %0; movl %1, %%esp;"
       : "=m" (syscall_f.old_esp) : "q" (syscall_f.args));
  asm ("call *%1; movl %2, %%esp; movl %%eax, %0;"
       : "=m" (syscall_f.ret) 
       : "q" (syscall_worker[syscall_no]), "m" (syscall_f.old_esp));

  /* Set the return value of syscall. */
  f->eax = syscall_f.ret;

  /* Set syscall back to false. */
  t->syscall = false;
#ifdef VM
  t->esp = NULL;
#endif
  return;
}


/** Worker for HALT. 
    Terminates pintos by calling shutdown_power_off(). */
static void 
syscall_halt (void)
{
  /* The file system is safely closed within shutdown_power_off (),
     and there should be no more to save before shutdown. */
  shutdown_power_off ();
}

/** Worker for EXIT. 
    Terminates the current user program, returning status to the kernel.
    This worker simply passes STATUS to the process status slot in heap,
    and calls thread_exit(), in which process_exit() decides what to do
    with the process status slots. */
static void 
syscall_exit (int status)
{
  thread_current ()->pss->status = status;
  thread_exit ();
}

/** Worker for EXEC. 
    Runs the executable whose name is given in cmd_line, passing any given 
    arguments, and returns the new process's program id (pid). 
    If the program cannot load or run for any reason, must return pid -1, 
    which otherwise should not be a valid pid. */
static pid_t 
syscall_exec (const char *cmd_line)
{
  /* Must first check for the validity of CMD_LINE. */
  if (!check_user_read_buffer (cmd_line, CMD_BUFFER_SIZE, true))
    syscall_terminate ();

  /* Now we can be reassured to pass CMD_LINE to process_execute().
     The wanted behavior is already implemented in process_execute(),
     i.e., it blocks until child finishes loading and reports result. */
  pid_t pid = (pid_t) process_execute (cmd_line);

#ifdef VM
  unpin_user_buffer (cmd_line, CMD_BUFFER_SIZE, true);
#endif
  return pid;
}

/** Worker for WAIT. 
    Waits for a child process pid and retrieves the child's exit status. */
static int 
syscall_wait (pid_t pid)
{
  tid_t child_tid = (tid_t) pid;

  /* The wanted behavior is already implemented in process_wait().
     Refer to the comment there for details. */
  return process_wait (child_tid);
}

/** Worker for CREATE. 
    Creates a new file called file initially initial_size bytes in size. 
    Returns true if successful, false otherwise. 
    Creating a new file does not open it: opening the new file is a separate 
    operation which would require a open system call. */
static bool 
syscall_create (const char *file, unsigned initial_size)
{
  if (!check_user_read_buffer (file, NAME_MAX, true))
    syscall_terminate ();

  lock_acquire (&filesys_lock);
  bool success = filesys_create (file, initial_size);
  lock_release (&filesys_lock);

#ifdef VM
  unpin_user_buffer (file, NAME_MAX, true);
#endif
  return success;
}

/** Worker for REMOVE. 
    Deletes the file called file. Returns true if successful, false otherwise. 
    A file may be removed regardless of whether it is open or closed, and 
    removing an open file does not close it. */
static bool 
syscall_remove (const char *file)
{
  if (!check_user_read_buffer (file, NAME_MAX, true))
    syscall_terminate ();
  
  lock_acquire (&filesys_lock);
  bool success = filesys_remove (file);
  lock_release (&filesys_lock);

#ifdef VM
  unpin_user_buffer (file, NAME_MAX, true);
#endif
  return success;
}

/** Worker for OPEN. 
    Opens the file called file. Returns a nonnegative integer handle called 
    a "file descriptor" (fd), or -1 if the file could not be opened. 
    File descriptors are not inherited by child processes 
    (different from Unix semantics)!!! */
static int 
syscall_open (const char *file)
{
  if (!check_user_read_buffer (file, NAME_MAX, true))
    syscall_terminate ();

  /* Try open the file. */
  lock_acquire (&filesys_lock);
  struct file * opened_file = filesys_open (file);
  lock_release (&filesys_lock);

  if (opened_file == NULL)
    {
#ifdef VM
      unpin_user_buffer (file, NAME_MAX, true);
#endif
      return -1;
    }

  /* Then assign the FD. */
  struct thread *t = thread_current ();
  unsigned next_fd;
  
  if (t->fdt != NULL)
    {
      /* FDT exists, find the next empty entry. */
      for (next_fd = 0; next_fd < (sizeof(struct fd_table)>>2); next_fd++)
        if (t->fdt->fde[next_fd] == NULL)
          break;
    }
  else
    {
      /* Or, lazily allocate page for FDT. */
      t->fdt = palloc_get_page (PAL_ZERO);
      /* Allocation failed. */
      if (t->fdt == NULL)
        goto no_available_fd;
      
      /* Fill entry for STDIN/STDOUT with non-zero invalid value,
         for lookup and assertion use. */
      t->fdt->fde[STDIN_FILENO] = (struct file *)0xffffffff;
      t->fdt->fde[STDOUT_FILENO] = (struct file *)0xffffffff;
      next_fd = STDOUT_FILENO + 1;
    }
  
  /* FDT full. Cannot open more file. */
  if (next_fd == (sizeof(struct fd_table)>>2))
    goto no_available_fd;

  /* Now finally add NEXT_FD to FDT. */
  t->fdt->fde[next_fd] = opened_file;
#ifdef VM
  unpin_user_buffer (file, NAME_MAX, true);
#endif
  return next_fd;
  
 no_available_fd:
  lock_acquire (&filesys_lock);
  file_close (opened_file);
  lock_release (&filesys_lock);
#ifdef VM
  unpin_user_buffer (file, NAME_MAX, true);
#endif
  return -1;
}

/** Worker for FILESIZE. 
    Returns the size, in bytes, of the file open as fd. */
static int 
syscall_filesize (int fd)
{
  /* Invalid FD in terms of FILESIZE. */
  if (!fd_valid(fd) || fd == STDIN_FILENO || fd == STDOUT_FILENO)
    return -1;

  /* Now FDT must be valid. */
  lock_acquire (&filesys_lock);
  size_t size = file_length (thread_current ()->fdt->fde[fd]);
  lock_release (&filesys_lock);

  return size;
}

/** Worker for READ. 
    Reads size bytes from the file open as fd into buffer. Note that
    current implementation always ZEROs BUFFER to check for validity,
    which non-malicious users have to cope with for safety.
    Returns the number of bytes actually read (0 at end of file), or -1 
    if the file could not be read (due to a condition other than EOF). */
static int 
syscall_read (int fd, void *buffer, unsigned size)
{
  /* Invalid FD in terms of READ. */
  if (fd == STDOUT_FILENO || !fd_valid(fd))
    return -1;
  
  /* Then checks for validity of BUFFER. */
  if (!check_user_write_buffer (buffer, size))
    syscall_terminate ();

  /* Now safely writes. */
  int bytes_read;

  if (fd == STDIN_FILENO)
    {
      /* Reading from console, as BUFFER is valid, should always succeed. */
      for (unsigned i = 0; i < size; i++)
        *(char *)(buffer + i) = input_getc ();
      bytes_read = (int)size;
    }
  else
    {
      /* May read less than SIZE if EOF is encountered, which is handled
         in file_read(). */
      lock_acquire (&filesys_lock);
      bytes_read = (int) file_read (thread_current ()->fdt->fde[fd], 
                                    buffer, size);
      lock_release (&filesys_lock);
    }
#ifdef VM
  unpin_user_buffer (buffer, size, false);
#endif
  return bytes_read;
}

/** Worker for WRITE. 
    Writes size bytes from buffer to the open file fd. 
    Returns the number of bytes actually written, which may be less than 
    size if some bytes could not be written.
    Writing past end-of-file would normally extend the file, but file growth 
    is not implemented by the basic file system. The expected behavior is to 
    write as many bytes as possible up to end-of-file and return the actual 
    number written, or 0 if no bytes could be written at all. */
static int 
syscall_write(int fd, const void *buffer, unsigned size)
{
  /* Invalid FD in terms of WRITE. 
     The deny-write behavior is handled in file_write(). */
  if (fd == STDIN_FILENO || !fd_valid(fd))
    return -1;

  /* Then checks for validity of BUFFER. */
  if (!check_user_read_buffer (buffer, size, false))
    syscall_terminate ();
  
  /* Now safely writes. */
  int bytes_written;

  if (fd == STDOUT_FILENO)
    {
      /* Writing to console, as BUFFER is valid, should always succeed. */
      putbuf ((char *)buffer, size);
      bytes_written = (int)size;
    }
  else
    {
      /* May write less than SIZE if EOF is encountered, which is handled
         in file_write(). */
      lock_acquire (&filesys_lock);
      bytes_written = (int) file_write (thread_current ()->fdt->fde[fd], 
                                        buffer, size);
      lock_release (&filesys_lock);
    }
#ifdef VM
  unpin_user_buffer (buffer, size, false);
#endif
  return bytes_written;
}

/** Worker for SEEK.
    Changes the next byte to be read or written in open file fd to position, 
    expressed in bytes from the beginning of the file. */
static void 
syscall_seek (int fd, unsigned position)
{
  /* Invalid FD in terms of SEEK. */
  if (!fd_valid(fd) || fd == STDIN_FILENO || fd == STDOUT_FILENO)
    return;
  
  /* POSITION is nonnegative; moreover, it can be arbitrarily large. Subsequent
     READ and WRITE just fail if it goes past EOF. */
  lock_acquire (&filesys_lock);
  file_seek (thread_current ()->fdt->fde[fd], position);
  lock_release (&filesys_lock);
}

/** Worker for TELL.
    Returns the position of the next byte to be read or written in open file 
    fd, expressed in bytes from the beginning of the file. */
static unsigned 
syscall_tell (int fd)
{
  /* Invalid FD in terms of TELL. */
  if (!fd_valid(fd) || fd == STDIN_FILENO || fd == STDOUT_FILENO)
    return 0;

  lock_acquire (&filesys_lock);
  unsigned pos = (unsigned) file_tell (thread_current ()->fdt->fde[fd]);
  lock_release (&filesys_lock);
  
  return pos;
}

/** Worker for CLOSE.
    Closes file descriptor fd. */
static void 
syscall_close (int fd)
{
  /* Invalid FD in terms of CLOSE.
     Specifically, STDIN and STDOUT are not closable. */
  if (!fd_valid(fd) || fd == STDIN_FILENO || fd == STDOUT_FILENO)
    return;
  
  struct thread *t = thread_current ();
  lock_acquire (&filesys_lock);
  file_close (t->fdt->fde[fd]);
  lock_release (&filesys_lock);

  /* Clear the closed FD entry. */
  t->fdt->fde[fd] = NULL;
}

/** Worker for MMAP.
    Maps the file open as fd into the process's virtual address space, as 
    consecutive virtual pages starting at ADDR. 
    In Pintos, MMAP is not configurable by flags, and all MMAPs default
    to MAP_SHARED | MAP_WRITE. */
static mapid_t syscall_mmap (int fd, void *addr)
{
#ifndef VM
  syscall_terminate ();
  NOT_REACHED ();
#endif
  struct thread *cur = thread_current ();

  /* Invalid FD in terms of MMAP.
     Specifically, STDIN and STDOUT are not mappable. */
  if (!fd_valid(fd) || fd == STDIN_FILENO || fd == STDOUT_FILENO)
    goto bad_mmap;
  
  /* Fail if trying to load a running executable. */
  struct file *file = cur->fdt->fde[fd];
  struct map_file *existing = mapfile_get_by_file (file);
  if (existing != NULL && existing->writable == false)
    goto bad_mmap;

  /* Fail if ADDR is NULL or not page-aligned. */
  if (((int)addr & PGMASK) != 0 || addr == NULL)
    goto bad_mmap;


  lock_acquire (&filesys_lock);
  size_t read_bytes = file_length (file);
  lock_release (&filesys_lock);
  size_t size = (size_t) pg_round_up ((void *)read_bytes);
  size_t zero_bytes = size - read_bytes;

  /* Fail if SIZE is 0. */
  if (size == 0)
    goto bad_mmap;
  
  /* Fail if [ADDR, ADDR + SIZE] intersects with existing VMAs. */
  struct list_elem *e;
  for (e = list_begin (&cur->vma_list); e != list_end (&cur->vma_list);
       e = list_next (e))
		{
			struct vm_area *vma = list_entry (e, struct vm_area, proc_elem);
			if (vma->lower_bound < addr + size)
				{
          if (vma->upper_bound > addr)
            goto bad_mmap;  
        }
      else
        break;
		}

  /* By now, we confirm the MMAP call is valid. It can still fail
     if kernel runs out of memory. */

  /* Create VMA for this MMAPed area. */
  struct vm_area *vma = malloc (sizeof (struct vm_area));
  if (vma == NULL)
    goto bad_mmap;
              
  vma->lower_bound = (void *)addr;
  vma->upper_bound = (void *)addr + size;
  vma->proc = cur;
  /* A MMAPed area is always MAP_SHARED | MAP_WRITE. */
  vma->flags = MAP_SHARED | MAP_WRITE;
  vma->offset = 0;
  vma->filesize = read_bytes;

  lock_acquire (&filesys_lock);
  bool success = mapfile_add_vma (file, vma, true);
  lock_release (&filesys_lock);

  if (!success)
    {
      free (vma);
      goto bad_mmap;
    }
  
  /* VMA successfully attached. */
  list_insert (e, &vma->proc_elem);

  /* Finally, set up PTEs. */
  void *upage = addr;
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* WRITABLE set to false, to ensure COW later.
         If page_read_bytes is non-zero, AUX is set as page_read_bytes,
         with AVL_FLAG as AVL_INFILE. Else, AUX is zeroed, with AVL_FLAG
         set as AVL_ZEROED. */
      if (!pagedir_set_page_lazy (cur->pagedir, upage, true,
                                  page_read_bytes, AVL_INFILE))
        goto bad_mmap;

      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  
  /* Successful MMAP. */
  return (mapid_t)vma;

  bad_mmap:
  return (mapid_t)-1;
}

/** Worker for MUMMAP. 
    The VMA specified by MAPID is freed, which must be returned by a previous
    MMAP call. */
static void syscall_munmap (mapid_t mapid)
{
#ifndef VM
  syscall_terminate ();
  NOT_REACHED ();
#endif
  struct thread *cur = thread_current ();
  struct list_elem *e;
  struct vm_area *vma = NULL;
  for (e = list_begin (&cur->vma_list); e != list_end (&cur->vma_list);
       e = list_next (e))
		{
			struct vm_area *_vma = list_entry (e, struct vm_area, proc_elem);
      /* We use the VMA->flags to distinguish between MMAPed VMAs and VMAs 
         describing an executable segment. This works because Pintos MMAPs
         has only one flags option, and can be improved by marking explicitly
         the MMAPed VMAs. */
			if ((mapid_t)_vma == mapid &&
          _vma->flags == (MAP_SHARED | MAP_WRITE))
        {
          vma = _vma;
          break;
        }
		}
  
  /* Fail if MAPID is not valid. */
  if (vma == NULL)
    return;

  
  /* Scan the mapped pages. */
  lock_acquire (&frame_table_lock);
  for (void *upage = vma->lower_bound; upage < vma->upper_bound;
       upage += PGSIZE)
    {
      void * phys_addr = pagedir_get_page (cur->pagedir, upage);
      if (phys_addr != NULL)
        {
          /* Present. */
          struct frame *f = phys_to_frame (phys_addr);
          ASSERT (!frame_is_empty (f) && frame_is_filebacked (f));

          if (pagedir_is_dirty (cur->pagedir, upage))
            frame_set_write (f);
        }
    }
  lock_release (&frame_table_lock);
  
  /* By now, remove the VMA describing mapped area MAPID. */
  list_remove (&vma->proc_elem);
  mapfile_remove_vma (vma->mapfile, vma);
  /* Dirty pages are writen back automatically within this call. */

  free (vma);
}

/** Worker for un-implemented syscalls. 
    Simply terminate the process. */
static void
syscall_unhandled (void)
{
  syscall_terminate ();
}