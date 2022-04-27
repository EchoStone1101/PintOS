#include "mm.h"
#include "frame.h"
#include "mapfile.h"
#include "swap.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include <list.h>
#include <hash.h>
#include <string.h>

/** Global pool of existing MAP_FILEs. */
struct hash mapfile_pool;

/** Lock protecting the pool of MAP_FILEs. */
struct lock mapfile_pool_lock;

/** Array of every physical frames. 
    Malloc-ed at mm_init(). */
struct frame *frame_table;

/** Lock protecting frame_table. */
struct lock frame_table_lock;

size_t frame_table_size;
void *userpool_base;


/** Initialize the memory management system. 
    Must be invoked after palloc_init() and malloc_init(). */
void
mm_init (void)
{
	/* Initialize mapfile_pool. */
	hash_init (&mapfile_pool, mapfile_pool_hash_func, 
								  					mapfile_pool_less_func, NULL);
	lock_init (&mapfile_pool_lock);
		
	/* Initialize frame table.
		 If not enough kernel memory, panic. */
	frame_table_size = palloc_userpool_size ();
	frame_table = calloc (frame_table_size, sizeof (struct frame));
	if (frame_table == NULL)
		PANIC ("mm_init: not enough kernel memory for frame table");
	userpool_base = palloc_userpool_base ();
	lock_init (&frame_table_lock);

	/* Initialize swap space. This can fail, where Pintos then
	   run as if swap is always full. */
	swap_init ();
}