#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include <fixedpoint.h>
#include "threads/synch.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif
#ifdef VM
#include "vm/mm.h"
#endif

/** States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /**< Running thread. */
    THREAD_READY,       /**< Not running but ready to run. */
    THREAD_BLOCKED,     /**< Waiting for an event to trigger. */
    THREAD_DYING        /**< About to be destroyed. */
  };

/** Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /**< Error value for tid_t. */

/** Thread priorities. */
#define PRI_MIN 0                       /**< Lowest priority. */
#define PRI_DEFAULT 31                  /**< Default priority. */
#define PRI_MAX 63                      /**< Highest priority. */

/** MLFQ scheduler frequency for recalculating priorities */
#define MLFQ_FREQ 4                     

/** A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/** The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /**< Thread identifier. */
    enum thread_status status;          /**< Thread state. */
    char name[16];                      /**< Name (for debugging purposes). */
    uint8_t *stack;                     /**< Saved stack pointer. */
    struct list_elem allelem;           /**< List element for all threads list. */

    /* For alarm clock */
    int64_t alarm;                      /**< Tick when thread should wake up. */
    struct semaphore wakeup;            /**< Semaphore for actual sleeping and wake-up */

    /* For priority */
    int priority;                       /**< Effective priority. */
    
    int base_priority;                  /**< Base priority for donation. */
    struct list donors;                 /**< List of locks which gives donation. */
    struct lock *donee_lock;            /**< The lock receiving donation. */
    
    int nice;                           /**< The nice value for MLFQS */
    fp_real recent_cpu_time;            /**< The rolling average recent cpu time for MLFQS */

    /* Meant to be reused like elem; currently only for alarm clock. */
    struct list_elem blockelem;         /**< List element for blocked threads. */

    /* Shared between ready list(s) and semaphores. */
    struct list_elem elem;              /**< List element. */

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /**< Page directory. */

    bool syscall;                       /**< Set to true when in syscall, for PF handler. */

    struct list children;               /**< List of all children processes. */
    struct proc_stat_slot *pss;         /**< Process status slot of current process. */

    struct fd_table *fdt;               /**< Opened file descriptor table. */
    struct file *file_self;             /**< File that the process is loaded from. */
#endif

#ifdef VM
   /* For virtual memory management. */
   struct list vma_list;                /**< List of VMAs for user memory. */     
   bool want_pinned;                    /**< Telling PF handler whether to pin the frame. */
   void *esp;                           /**< For PF handler to obtain user ESP. */
#endif

    /* Owned by thread.c. */
    unsigned magic;                     /**< Detects stack overflow. */
  };

/** If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);
void thread_schedule_init (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);
void thread_schedule_reshuffle (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);
void potential_thread_yield (void);

bool priority_greater_func (const struct list_elem *,
                            const struct list_elem *,
                            void *);

bool priority_less_func (const struct list_elem *,
                         const struct list_elem *,
                         void *);

/** Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void thread_recalc_priority (struct thread *, void *);
void thread_action_update_cpu (struct thread *, void *);
void thread_update_load_avg (void);

#endif /**< threads/thread.h */
