#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "filesys/file.h"

#define STDIN_FILENO 0
#define STDOUT_FILENO 1

/* User stack is limited to STACK_PG_CNT pages at most. */
#define STACK_PG_CNT 128

/* Not sure why this typedef is not captured by compiler. */
typedef int tid_t;

/* Process status slot. */
struct proc_stat_slot
  {
    /** CNT is the key of synchronizing between parent and child 
        processes.

        It starts with value 0. Exiting (by calling process_exit())
        in parent and child both UP it by 1. process_wait(), on the
        other hand, DOWNs on it.

        This way, process_wait() returns from downing only after child
        exits, and it doesn't matter the order, which is the wanted 
        behavior. 
       
        Finally, a slot is freed (1) in process_exit() if the UPed CNT
        reaches 2, which means both parent and child has exited (2)
        in process_wait() after status is read, which means child must
        have exited, and the slot is no longer necessary. In the second
        case, the slot is removed from parent's children list, which also
        implements the correct behavior for multiple waits (all but the 
        first returns -1 immediately, as the waited process is no longer
        child.) */

    struct semaphore cnt;           /**< Synchronization for freeing PSS. */    
    int status;                     /**< Return status. */
    tid_t tid;                      /**< Tid for identifying process. */
    struct list_elem elem;          /**< List element for parent's children list. */
  };

/* Table of opened file descriptors. 
   Takes up exactly one page, meaning that a process can open
   at most 1024 files. Similar constraint is found in Linux. 
   
   Note that the fd_table page is lazily allocated. Namely, only at the
   first OPEN syscall with FD other than STDIN_FILENO and STDOUT_FILENO
   is this page created. Processes that only uses STDIN / STDOUT do not
   need a page of FDs. Other FD related syscalls, e.g. FILESZ or WRITE,
   do not trigger the allocation, as we can check their FD are invalid
   by noting t->fdt == NULL. */
struct fd_table
  {
    struct file *fde[PGSIZE >> 2];         /**< Pointers to file. FD index into this array. */
  };

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /**< userprog/process.h */
