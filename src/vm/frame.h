#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "mm.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include <list.h>
#include <hash.h>
#include <string.h>

// #define FRAME_DEBUG

/** Pintos frame-level synchronization.
   	
		Designing a system that provides per-frame locks, despite being enticing,
		is also extremely difficult - at least more than simply putting locks in 
		FRAME struct. We were deeply absorbed by some quirky bit-level spinlocks
		and more wacky tricks, until we realize that I/O IS ACTUALLY BOTTLENECKED
		BY CHANNEL LOCKS (see ide.c), i.e., it is not possible, even with an 
		improved file system, to have multiple frames under paging-in/out in 
		parallel. This observation renders our ideal fine-grained synchronization
		pretty much pointless. 
		(Obviously, batching I/O still helps, but we can still assume that relevant
		data structures are not concurrently modified. We do not implement I/O
		batching anyway.)

		Instead, we settle on the simple "one-lock" solution protecting the frame
		table. What that really means, we note, is protecting modifications to
		FRAME structs. As the only routines that do so are paging-in, paging-out,
		frame_free() and pinning frames, this solution actually provides the 
		most of meaningful concurrency.	*/

/** Flags for extra information of FRAME. */	
#define FRAME_FLAG_ISFILEBACKED 1
#define FRAME_FLAG_WRITE 	 		  2				
#define FRAME_FLAG_BUSY 	 			4				
#define FRAME_FLAG_PINNED 			0xFF8			

#define FRAME_FLAG_MASK 				0xFFF

/** PTE flags in AVL field, describing where to fetch the page. */
#define AVL_INVALID     0x00000000		/**< Field not properly set. */
#define AVL_INFILE      0x00000200		/**< Fetch from file. */
#define AVL_INSWAP      0x00000400 		/**< Fetch from swap. */
#define AVL_ZEROED      0x00000600 		/**< Create a zeroed page. */


/* Macros for working with a frame. */

#define frame_is_filebacked(pFRAME) ((pFRAME)->flags & FRAME_FLAG_ISFILEBACKED)
#define frame_is_anon(pFRAME) (!((pFRAME)->flags & FRAME_FLAG_ISFILEBACKED))
#define frame_is_empty(pFRAME) ((pFRAME)->mapfile == 0)

#define frame_mapfile(pFRAME) ((struct map_file *)((pFRAME)->mapfile))
#define frame_anon_vma(pFRAME) ((struct vm_area *)((pFRAME)->anon_vma))
#define frame_offset(pFRAME) ((off_t)((pFRAME)->offset & (~FRAME_FLAG_MASK)))
#define frame_flags(pFRAME) ((pFRAME)->flags & FRAME_FLAG_MASK)

#define frame_set_mapfile(pFRAME, pMAPFILE) ((pFRAME)->mapfile = (int)(pMAPFILE),\
																						(pFRAME)->flags |= FRAME_FLAG_ISFILEBACKED)
#define frame_set_anon_vma(pFRAME, pVMA) ((pFRAME)->anon_vma = (int)(pVMA),\
																					(pFRAME)->flags &= (~FRAME_FLAG_ISFILEBACKED))
#define frame_set_offset(pFRAME, OFFSET) ((pFRAME)->offset = (off_t)(OFFSET | frame_flags (pFRAME)))

#define frame_is_write(pFRAME) ((pFRAME)->flags & FRAME_FLAG_WRITE)
#define frame_is_busy(pFRAME) ((pFRAME)->flags & FRAME_FLAG_BUSY)

#define frame_set_write(pFRAME) ((pFRAME)->flags |= FRAME_FLAG_WRITE)
#define frame_clear_write(pFRAME) ((pFRAME)->flags &= (~FRAME_FLAG_WRITE))
#define frame_set_busy(pFRAME) ((pFRAME)->flags |= FRAME_FLAG_BUSY)
#define frame_clear_busy(pFRAME) ((pFRAME)->flags &= (~FRAME_FLAG_BUSY))

#define frame_pinned(pFRAME) ((pFRAME)->flags & FRAME_FLAG_PINNED)
/* Also returns whether pinning is successful. */
#define frame_set_pinned(pFRAME) (frame_pinned(pFRAME)<FRAME_FLAG_PINNED ?\
																	((pFRAME)->flags = (pFRAME)->flags + 0x8) : 0)
#define frame_clear_pinned(pFRAME) (frame_pinned(pFRAME) ? (pFRAME)->flags -= 0x8 : 0)

void *frame_to_phys (struct frame *f);
struct frame *phys_to_frame (void * phys_addr);

struct frame *frame_alloc (void);
void frame_free (struct frame *f, int aux);

bool frame_accessed (struct frame *f, struct list *rm_list, bool clear, bool hard);
bool frame_dirty (struct frame *f, struct list *rm_list, bool clear);
int frame_get_read_bytes (struct frame *f, struct list *rm_list);
void frame_invalidate (struct frame *f, struct list *rm_list, int aux, int avl_flag);
void frame_reverse_map (struct frame *f, struct list *rm_list);
void frame_reverse_map_free (struct frame *f, struct list *rm_list);

int frame_evict (size_t cnt, bool hard);

#define EVICT_MIN_CNT 2					/**< Number of frames to evict when OOM. */
#define EVICT_GRANULARITY 16		/**< Number of frames to examine before 
																		 releasing frame_table_lock */

unsigned frame_hash_func (const struct hash_elem *e, void *aux UNUSED);
bool frame_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);

#endif