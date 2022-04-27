#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include <hash.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/** Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/** List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/** Multilevel feed-back queues when thread_mlfqs is set. */
static struct list mlf_queues[PRI_MAX+1];

/** Bitmap for quick navigation of mlf_queues. */
static uint64_t mlf_bitmap;

/** Macro for operating on mlf_bitmap */
#define MLFQS_MASK(N) (1ull << N)

/** System load_avg for MLFQ scheduler */
static fp_real load_avg;

/** List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/** Idle thread. */
static struct thread *idle_thread;

/** Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/** Lock used by allocate_tid(). */
static struct lock tid_lock;

/** Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /**< Return address. */
    thread_func *function;      /**< Function to call. */
    void *aux;                  /**< Auxiliary data for function. */
  };

/** Statistics. */
static long long idle_ticks;    /**< # of timer ticks spent idle. */
static long long kernel_ticks;  /**< # of timer ticks in kernel threads. */
static long long user_ticks;    /**< # of timer ticks in user programs. */

/** Scheduling. */
#define TIME_SLICE 4            /**< # of timer ticks to give each thread. */
static unsigned thread_ticks;   /**< # of timer ticks since last yield. */


/** If false (default), use priority scheduling.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (bool pop);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

/** Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&all_list);

  thread_schedule_init ();

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();

  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
}

/** Initialize data structure used by scheduling. 
    Policy controlled by flag thread_mlfqs */
void
thread_schedule_init (void)
{
  if (thread_mlfqs)
    {
      /* Initialize multi-queues */
      for (int i = PRI_MIN;i <= PRI_MAX;i++)
        list_init (&mlf_queues[i]);
      
      mlf_bitmap = (uint64_t) 0;
      load_avg = fp_to_real(0);
    }
  else
    /* Initialize ready_list */
    list_init (&ready_list);
}

/** Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/** Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;
  
  /* Update recent_cpu for the running thread */
  if (thread_mlfqs && t != idle_thread)
    t->recent_cpu_time = fp_add_int (t->recent_cpu_time, 1);

  /* Enforce preemption: expired time slice */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/** Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/** Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct thread *cur = thread_current ();
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;

  ASSERT (function != NULL);

  /* Get a new tid. */
  tid = allocate_tid ();

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);

#ifdef USERPROG
  /* Allocate process status slot. */
  struct proc_stat_slot *pss = (struct proc_stat_slot *) 
                                malloc (sizeof (struct proc_stat_slot));
  if (pss == NULL)
    /* Allocation failed. */
    {
      palloc_free_page (t);
      return TID_ERROR;
    }

  /* Initialize slot. */
  pss->tid = tid;
  sema_init (&pss->cnt, 0);
  pss->status = 0;

  /* Set up parent and child's access to PSS.
     Note that we rely on the following assumption: that thread_create() 
     do not interleave with thread_exit(). Here, parent is halfway through
     thread_create() and not exiting any time before, while child is not
     run until thread_unblock(), and no other thread should manipulate
     PSS and CHILDREN or cause parent to exit.

     If, however, certain EXTERNAL INTERRUPT causes parent to exit, then
     PSS might not be correctly freed. Luckily for what we know, external 
     interrupts only enforce termination at really bad times (e.g. machine 
     on fire), where we no longer have to care. 

     Finally, one can always turn off interrupts here if really needed. */
  t->pss = pss;
  list_push_back (&cur->children, &pss->elem);
#endif

#ifdef VM
  /* Initialize vma_list. It is then populated in load() when process
     actually runs. */
  list_init (&t->vma_list);
  t->want_pinned = false;
  t->esp = NULL;
#endif

  /* Nice and recent_cpu is inherited. */
  t->nice = thread_get_nice ();
  t->recent_cpu_time = cur->recent_cpu_time;

  t->tid = tid;

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;


  /* Add to run queue. */
  thread_unblock (t);

  /* As thread_unblock() does not preempt, check whether to
     yield here. */
  potential_thread_yield ();

  return tid;
}

/** Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  struct thread *t = thread_current ();

  /* Thread becomes blocked not because of priority change.
     In other words, the priority stays the same till now, which
     we use to update the mlf_bitmap if needed */
  if (thread_mlfqs)
    {
      int level = thread_get_priority ();
      if (list_empty (&mlf_queues[level]))
        mlf_bitmap &= ~MLFQS_MASK (level);
    }
  t->status = THREAD_BLOCKED;
  schedule ();
}

/** Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);

  t->status = THREAD_READY;

  thread_schedule_reshuffle (t);
  
  intr_set_level (old_level);
}

/** Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/** Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  /* Sanity check for priority scheduling: effective priority must
     not be lower than base priority. */
  ASSERT (thread_mlfqs || t->priority >= t->base_priority);

  return t;
}

/** Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/** Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process. That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/** Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  cur->status = THREAD_READY;

  if (cur != idle_thread) 
    thread_schedule_reshuffle (cur);
  
  schedule ();
  intr_set_level (old_level);
}


/** Wrapper routine for checking whether to yield. 
 
    This function can be called either by a normal thread or
    by an interrupt handler, providing a consistent interface. 

    Behavior is controlled by intr_context(). When in interrupt
    context, yield on return; else, yield right away. */
void
potential_thread_yield (void)
{
  enum intr_level old_level;
  if (!intr_context())
    old_level = intr_disable ();

  struct thread *next = next_thread_to_run (false);

  /* Corner case: before idle_thread is initialized, 
     early sema_up() calls will invoke this function,
     when next_thread_to_run() returns NULL. */
  if (next == NULL)
    {
      ASSERT (idle_thread == NULL);
      return;
    }
  
  if (!intr_context())
    intr_set_level (old_level);
  
  /* If not the top priority, yield */
  if (next->priority > thread_get_priority ())
    intr_context () ? intr_yield_on_return () : thread_yield ();
}

/** Reshuffle current thread into ready list(s) 
    Policy controlled by flag thread_mlfqs.
    Thread must NOT be in ready list. If relocating a thread 
    in ready list is needed, call list_remove() first. */
void
thread_schedule_reshuffle (struct thread *t)
{
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_READY);
  ASSERT (intr_get_level () == INTR_OFF);

  if (!thread_mlfqs)
    /* Priority scheduling */
    list_insert_ordered (&ready_list, &t->elem, priority_greater_func, NULL);
  else
    {
      /* Multi-level feedback queue */
      int level = t->priority;
      list_push_back (&mlf_queues[level], &t->elem);
      mlf_bitmap |= MLFQS_MASK (level);
    }
}

/** Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/** Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
  /* Ignore when using MLFQs */
  if (thread_mlfqs)
    return;
  
  struct thread *cur = thread_current ();

  cur->base_priority = new_priority;
  /* Either no donors, or new priority overrides. */
  enum intr_level old_level = intr_disable ();
  if (list_empty (&cur->donors) || cur->priority < new_priority)
    cur->priority = new_priority;
  intr_set_level (old_level);

  potential_thread_yield ();
}

/** Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->priority;
}

/** Recalculates the priority of T according to MLFQ scheduling
    policy, namely

          priority = PRI_MAX - 1/4 * recent_cpu - 2 * nice 
    
    rounded to the nearest integer. This function is formatted so
    that it can be passed to thread_foreach() as an action. */
void
thread_recalc_priority (struct thread *t, void *aux UNUSED)
{
  if (!thread_mlfqs || t == idle_thread)
    return;
  
  fp_real tmp1 = fp_to_real (PRI_MAX);
  fp_real tmp2 = fp_add (fp_div_int (t->recent_cpu_time, 4),
                         fp_mult_int (fp_to_real (t->nice), 2));
  
  int new_priority = fp_to_int_nearest (fp_sub (tmp1, tmp2));

  /* Clamp priority between PRI_MIN and PRI_MAX*/
  if (new_priority < PRI_MIN)
    new_priority = PRI_MIN;
  else if (new_priority > PRI_MAX)
    new_priority = PRI_MAX;

  int old_priority = t->priority;

  /* Priority unchanged, no more to do. */
  if (old_priority == new_priority)
    return;

  /* Else, might need to operate the ready list or yield */
  t->priority = new_priority; 

  switch (t->status)
    {
      case THREAD_RUNNING: 
          potential_thread_yield (); 
          break;      
      case THREAD_READY: 
          /* Only possible when called by timer interrupt handler */
          list_remove (&t->elem);
          if (list_empty (&mlf_queues[old_priority]))
            mlf_bitmap &= ~MLFQS_MASK (old_priority);
          thread_schedule_reshuffle (t);
          break;
      default: 
          /* No more to do for BLOCKED/DYING threads */
          break;
    }
}

/** Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice) 
{
  /* Clamp NICE between -20 and 20 */
  if (nice < -20)
    nice = -20;
  else if (nice > 20)
    nice = 20;

  struct thread *cur = thread_current ();
  cur->nice = nice;

  /* Recalculates priority. */
  thread_recalc_priority (cur, NULL);
}

/** Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  return thread_current ()->nice;
}

/** Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  return fp_to_int_nearest (fp_mult_int (load_avg, 100));
}

/** Updates system load_avg every SEC, according to the formula:
      
      load_avg  =  (59/60) * load_avg + (1/60) * ready_threads
    
    where ready_threads is the number of threads in the ready list,
    plus the running thread (if not idle_thread). */
void 
thread_update_load_avg (void)
{
  /* Not to forget the running thread, which is not in
     mlf_queues. */
  int ready_threads = (thread_current () != idle_thread);

  /* Since this update happens once a second, it is acceptable to 
     count threads using the O(n) list_size() API. Maintaining a
     *synchronized* thread number on the fly can be error prone. */
  for (int level = PRI_MIN; level <= PRI_MAX; level++)
    ready_threads += list_size (&mlf_queues[level]);
    
  fp_real tmp1 = fp_div_int (fp_mult_int (load_avg, 59), 60);
  fp_real tmp2 = fp_div_int (fp_to_real (ready_threads), 60);

  load_avg = fp_add (tmp1, tmp2);
}


/** Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  return fp_to_int_nearest (fp_mult_int (thread_current ()->recent_cpu_time, 100));
}

/** Updates each threads' recent_cpu evert SEC, with the formula: 
 
    recent_cpu = (2*load_avg)/(2*load_avg + 1) * recent_cpu + nice

    Note that the order of arithmetics is carefully chosen to avoid
    overflow. */
void thread_action_update_cpu (struct thread *t, void *aux UNUSED)
{
  if (!thread_mlfqs || t == idle_thread)
    return;

  fp_real tmp = fp_mult_int (load_avg, 2);
  fp_real coef = fp_div (tmp, (fp_add_int (tmp, 1)));

  t->recent_cpu_time = fp_add (fp_mult (t->recent_cpu_time, coef),
                               fp_to_real (t->nice));
}

/** Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */

      // More explicitly put: "sti" enables interrupts, but after
      // "hlt" (which makes CPU sleeps to save energy). After a
      // tick the timer still interrupts, and the loop starts again
      // to try letting other threads run.
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/** Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /**< The scheduler runs with interrupts off. */
  function (aux);       /**< Execute the thread function. */
  thread_exit ();       /**< If function() returns, kill the thread. */
}

/** Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/** Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/** Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  enum intr_level old_level;

  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  
  t->alarm = (int64_t) -1;
  sema_init (&t->wakeup, 0);

#ifdef USERPROG
  /* Initialize the rest of process properties. 
     This has to go here because the initial thread must 
     also have these initialized. */
  t->syscall = false;
  t->pss = NULL;
  list_init (&t->children);
  t->fdt = NULL;
  t->file_self = NULL;
#endif

  if (!thread_mlfqs)
    {
      /* Priority scheduling */
      t->base_priority = priority;
      t->priority = priority;
      t->donee_lock = NULL;
      list_init (&t->donors);
    }
  else
    {
      /* Multilevel feeback queue */
      t->base_priority = PRI_MIN;
      t->priority = PRI_MIN;
      t->nice = 0;
      t->recent_cpu_time = fp_to_int_zero (0);

      /* t is marked as BLOCKED and start with PRI_MIN, 
         so thread_recalc_priority() would neither yield, 
         not mess up mlf_queue and mlf_bitmap. */
      thread_recalc_priority (t, NULL);
    }

  t->magic = THREAD_MAGIC;

  old_level = intr_disable ();
  list_push_back (&all_list, &t->allelem);
  intr_set_level (old_level);
}

/** Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/** Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. Must be invoked with interrupts disabled. */
static struct thread *
next_thread_to_run (bool pop)
{
  if (!thread_mlfqs)
    {
      /* Priority scheduling */
      if (list_empty (&ready_list))
        return idle_thread;
      else
        {
          struct list_elem *e = pop ? list_pop_front (&ready_list) : list_front (&ready_list);
          return list_entry (e, struct thread, elem);
        }
    }
  else
    {
      /* Multilevel feedback queue */

      /* No ready threads, schedule idle_thread. */
      if (mlf_bitmap == 0)
        return idle_thread;

      /* Else, must have ready thread(s). */
      
      /* Find the highest bit set */
      
      /* http://graphics.stanford.edu/~seander/bithacks.html#IntegerLog */
      /* by Eric Cole. This code is written particularly to avoid branching. */   
      uint64_t r, shift;
      uint64_t v = mlf_bitmap;
      r     = (v > 0xFFFFFFFF) << 5; v >>= r;
      shift = (v > 0xFFFF    ) << 4; v >>= shift; r |= shift;
      shift = (v > 0xFF      ) << 3; v >>= shift; r |= shift;
      shift = (v > 0xF       ) << 2; v >>= shift; r |= shift;
      shift = (v > 0x3       ) << 1; v >>= shift; r |= shift;
                                                  r |= (v >> 1);
      int level = r;

      struct list_elem *e = pop ? list_pop_front (&mlf_queues[level]) : 
                                  list_front (&mlf_queues[level]);
      if (pop && list_empty (&mlf_queues[level]))
        mlf_bitmap &= ~MLFQS_MASK (level);
      
      return list_entry (e, struct thread, elem);
    }
}
    

/** Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/** Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run (true);
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/** Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/** Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);

/** Sort the ready_list by priority. 
    Note that list_insert_ordered() will insert before the first
    element that is SMALLER than given element, resulting in a 
    round-robin behavior. */
bool priority_greater_func (const struct list_elem *a,
                            const struct list_elem *b,
                            void *aux UNUSED)
{
  struct thread *left = list_entry (a, struct thread, elem);
  struct thread *right = list_entry (b, struct thread, elem);
  return left->priority > right->priority;
}

/** list_less_func for comparing priorities */
bool priority_less_func (const struct list_elem *a,
                         const struct list_elem *b,
                         void *aux UNUSED)
{
  struct thread *left = list_entry (a, struct thread, elem);
  struct thread *right = list_entry (b, struct thread, elem);
  return left->priority < right->priority;
}