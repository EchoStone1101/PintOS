/** This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/** Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
*/

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/** Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
     decrement it.

   - up or "V": increment the value (and wake up one waiting
     thread, if any). */
void
sema_init (struct semaphore *sema, unsigned value) 
{
  ASSERT (sema != NULL);

  sema->value = value;
  list_init (&sema->waiters);
}

/** Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. */
void
sema_down (struct semaphore *sema) 
{
  enum intr_level old_level;

  ASSERT (sema != NULL);
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  while (sema->value == 0) 
    {
      list_push_back (&sema->waiters, &thread_current ()->elem);
      //printf ("sema_down block: %d, for %x\n", thread_tid (), sema);
      thread_block ();
    }
  sema->value--;
  intr_set_level (old_level);
}

/** Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema) 
{
  enum intr_level old_level;
  bool success;

  ASSERT (sema != NULL);

  old_level = intr_disable ();
  if (sema->value > 0) 
    {
      sema->value--;
      success = true; 
    }
  else
    success = false;
  intr_set_level (old_level);

  return success;
}

/** Clears the value of the semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   cleared, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_clear (struct semaphore *sema) 
{
  enum intr_level old_level;
  bool success;

  ASSERT (sema != NULL);

  old_level = intr_disable ();
  if (sema->value > 0) 
    {
      sema->value = 0;
      success = true; 
    }
  else
    success = false;
  intr_set_level (old_level);

  return success;
}

/** Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
int
sema_up (struct semaphore *sema) 
{
  enum intr_level old_level;

  ASSERT (sema != NULL);

  old_level = intr_disable ();
  if (!list_empty (&sema->waiters))
    {
      /* Up-ing the thread with the highest priority is done by obtaining
         the MAX element in UNSORTED waiter list. This is because waiters
         can change their priority in multiple ways, where maintaining the
         waiter list sorted becomes error prone. */
      struct list_elem *max = list_max (&sema->waiters, priority_less_func, NULL);
      list_remove (max);
      thread_unblock (list_entry (max, struct thread, elem));
    }
    
  sema->value++;
  int new_value = sema->value;
  
  potential_thread_yield ();

  intr_set_level (old_level);
  return new_value;
}

static void sema_test_helper (void *sema_);

/** Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) 
{
  struct semaphore sema[2];
  int i;

  printf ("Testing semaphores...");
  sema_init (&sema[0], 0);
  sema_init (&sema[1], 0);
  thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
  for (i = 0; i < 10; i++) 
    {
      sema_up (&sema[0]);
      sema_down (&sema[1]);
    }
  printf ("done.\n");
}

/** Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_) 
{
  struct semaphore *sema = sema_;
  int i;

  for (i = 0; i < 10; i++) 
    {
      sema_down (&sema[0]);
      sema_up (&sema[1]);
    }
}

/** list_less_func for sorting locks in donors */
static bool lock_greater_func (const struct list_elem *a,
                               const struct list_elem *b,
                               void *aux UNUSED);

/** Wrapper routine for giving donation */
static void lock_give_donation (struct lock *);

/** Wrapper routine for cancelling donation */
static int lock_cancel_donation (struct lock *);

/** Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init (struct lock *lock)
{
  ASSERT (lock != NULL);

  lock->holder = NULL;
  lock->donated_priority = -1;
  sema_init (&lock->semaphore, 1);
}

/** Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
lock_acquire (struct lock *lock)
{
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (!lock_held_by_current_thread (lock));

  /* We disable interrupts here to avoid the following race condition:
     Suppose a timer interrupt comes BETWEEN a non-blocking sema_down()
     and setting lock->holder, and a higher priority thread is scheduled
     and try to donate. This donation will fill because lock->holder is 
     not yet set.
     Without turning off interrupts, we essentially have to set lock->holder
     before any other thread tries to give donation, which is impossible
     to guarantee. */
  enum intr_level old_level = intr_disable ();
  if (!thread_mlfqs)
    lock_give_donation (lock);

  /* Now actually block */
  sema_down (&lock->semaphore);

  /* Lock acquired */
  struct thread *cur = thread_current ();
  lock->holder = cur;
  
  if (!thread_mlfqs)
    {
      /* The holder is now not donating to any lock. */
      cur->donee_lock = NULL;
      /* ... but will have LOCK as its one of its own donors. */
      list_insert_ordered (&cur->donors, &lock->lockelem,
                            lock_greater_func, NULL);
    }
  intr_set_level (old_level);
}

/** Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. It also does NOT donate, since it does not
   block anyway. */
bool
lock_try_acquire (struct lock *lock)
{
  bool success;

  ASSERT (lock != NULL);
  ASSERT (!lock_held_by_current_thread (lock));

  success = sema_try_down (&lock->semaphore);
  if (success)
    lock->holder = thread_current ();
  
  return success;
}

/** Releases LOCK, which must be owned by the current thread.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void
lock_release (struct lock *lock) 
{
  ASSERT (lock != NULL);
  ASSERT (lock_held_by_current_thread (lock));

  lock->holder = NULL;
  int new_priority;

  if (!thread_mlfqs)
    new_priority = lock_cancel_donation (lock);

  sema_up (&lock->semaphore);

  /* At the time of a cancelled donation, this is where we set the new 
     priority, or we might get preempted in sema_up(). */
  if (!thread_mlfqs)
    {
      struct thread *cur = thread_current ();
      cur->priority = new_priority;
      potential_thread_yield ();
    }
}

/** Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock) 
{
  ASSERT (lock != NULL);

  return lock->holder == thread_current ();
}

/** list_less_func for sorting locks in donors */
static bool lock_greater_func (const struct list_elem *a,
                               const struct list_elem *b,
                               void *aux UNUSED)
{
  struct lock *left = list_entry (a, struct lock, lockelem);
  struct lock *right = list_entry (b, struct lock, lockelem);
  return left->donated_priority > right->donated_priority;
}

/** Wrapper rountine for giving donation. Only called when
    thread_mlfqs is false.
    Since we are not calling this function recursively to deal 
    with nested donations, we support nested donation with 
    arbitrary depth. */
static void
lock_give_donation (struct lock * lock)
{
  struct lock *cur_lock = lock;
  struct thread *donee = cur_lock->holder;
  struct thread *cur_thread = thread_current ();
  
  /* Record donee_lock even if unable to overide.
     If later the current thread is donated, nested donation 
     can pass on. */
  if(donee != NULL)
    cur_thread->donee_lock = cur_lock;

  /* (Recursively) give donation if current donation overrides */
  while (cur_lock != NULL && cur_thread->priority > cur_lock->donated_priority) 
    {
      donee = cur_lock->holder;
      if (donee == NULL)
        break;

      /* Record new priority */
      cur_lock->donated_priority = cur_thread->priority;
      //ASSERT (!list_empty (&donee->donors));
      list_remove (&cur_lock->lockelem);
      list_insert_ordered (&donee->donors, &cur_lock->lockelem,
                            lock_greater_func, NULL);

      /* donee's priority might change */
      int new_priority = list_entry (list_front (&donee->donors), 
                                     struct lock, lockelem)->donated_priority;
      if (new_priority > donee->priority)
        {
          donee->priority = new_priority;
          /* Reshuffle donee if it is READY */
          if (donee->status == THREAD_READY)
            {
              list_remove (&donee->elem);
              thread_schedule_reshuffle (donee);
            }
          /* Else, donee gets reshuffled later when ready */
        }
      
      /* Nested donation: pass it on */
      cur_thread = donee;
      cur_lock = donee->donee_lock;
    }
}

/** Wrapper rountine for cancelling donation. Only called when
    thread_mlfqs is false.
    Since we are not calling this function recursively to deal 
    with nested donations, we support nested donation with 
    arbitrary depth. */
static int
lock_cancel_donation (struct lock * lock)
{
  enum intr_level old_level = intr_disable ();

  /* Detach from current thread's donors */
  struct thread *cur = thread_current ();

  list_remove (&lock->lockelem);

  /* Clear donated priority record, so that later propagation of 
     donation will properly add lockelem to new holder of this lock. */
  lock->donated_priority = -1;

  /* Current thread priority might change */
  int donated_priority, new_priority;

  /* donee could set its priority to be higher than the donated
     priority afterwards, so we don't simply fall back to the new
     top donor's priority. */
  if (list_empty (&cur->donors) || 
      (donated_priority = list_entry (list_front (&cur->donors), 
                          struct lock, lockelem)->donated_priority)
       < cur->base_priority)
    new_priority = cur->base_priority;
  else
    new_priority = donated_priority;

  intr_set_level (old_level);
  return new_priority;
}

/** One semaphore in a list. */
struct semaphore_elem 
  {
    struct list_elem elem;              /**< List element. */
    struct semaphore semaphore;         /**< This semaphore. */
  };

/** list_less_func for comparing waiters */
static bool cond_less_func (const struct list_elem *a,
                            const struct list_elem *b,
                            void *aux);

/** Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond)
{
  ASSERT (cond != NULL);

  list_init (&cond->waiters);
}

/** Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
cond_wait (struct condition *cond, struct lock *lock) 
{
  struct semaphore_elem waiter;

  ASSERT (cond != NULL);
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (lock_held_by_current_thread (lock));
  
  sema_init (&waiter.semaphore, 0);

  list_push_back (&cond->waiters, &waiter.elem);
  lock_release (lock);
  sema_down (&waiter.semaphore);
  lock_acquire (lock);
}

/** If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_signal (struct condition *cond, struct lock *lock UNUSED) 
{
  ASSERT (cond != NULL);
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (lock_held_by_current_thread (lock));

  if (!list_empty (&cond->waiters))
    {
      struct list_elem *max = list_max (&cond->waiters, cond_less_func, NULL);
      list_remove (max);
      sema_up (&list_entry (max, struct semaphore_elem, elem)->semaphore);
    }
}

/** Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock) 
{
  ASSERT (cond != NULL);
  ASSERT (lock != NULL);

  while (!list_empty (&cond->waiters))
    cond_signal (cond, lock);
}

/** list_less_func for comapring waiters */
static bool cond_less_func (const struct list_elem *a,
                            const struct list_elem *b,
                            void *aux UNUSED)
{
  struct semaphore_elem *left = list_entry (a, struct semaphore_elem, elem);
  struct semaphore_elem *right = list_entry (b, struct semaphore_elem, elem);
  struct thread *lthread = list_entry (list_front (&left->semaphore.waiters), struct thread, elem);
  struct thread *rthread = list_entry (list_front (&right->semaphore.waiters), struct thread, elem);
  return lthread->priority < rthread->priority;
}
