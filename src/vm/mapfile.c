#include "mm.h"
#include "mapfile.h"
#include "frame.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/thread.h"
#include <list.h>
#include <hash.h>
#include <string.h>
#include <stdio.h>

extern struct lock filesys_lock;
extern struct frame *frame_table;
extern struct lock frame_table_lock;

extern struct hash mapfile_pool;
extern struct lock mapfile_pool_lock;


/** Get existing MAP_FILE instance by BACKING_FILE. NULL is returned,
    if no such instance exists.
		Used by load() in process.c and syscall_mmap() in syscall.c to avoid 
		loading an executable that is already MMAPed as writable, or the other
		way around. */
struct map_file *
mapfile_get_by_file (struct file *backing_file)
{
	ASSERT (backing_file != NULL);
		
	struct map_file *mapfile = calloc(1, sizeof(struct map_file));
	if (mapfile == NULL)
		return NULL;

	mapfile->inode = backing_file->inode;
	lock_acquire (&mapfile_pool_lock);
	struct hash_elem *result = hash_find (&mapfile_pool, &mapfile->elem);
	struct map_file *existing = result == NULL ? NULL : 
																				hash_entry (result, struct map_file, elem);
	lock_release (&mapfile_pool_lock);
	free (mapfile);
	return existing;
}


/** Add VMA to an new instance of MAP_FILE, or an existing one,
    located by BACKING_FILE in the mapfile_pool.
    Invoked when process is loaded, or handling MMAP syscall.
		
		Locating / allocating MAP_FILE and adding VMA must be atomic
		against mapfile_remove_vma(). Otherwise, we might be adding
		to a MAP_FILE that mapfile_remove_vma() has decided to free.
		This is ensured by both functions acquiring mapfile_pool_lock.

		Might return false if malloc() failed, where the loading/mmap
		should just fail as well. */
bool
mapfile_add_vma (struct file *backing_file, struct vm_area *vma, bool writable)
{
	ASSERT (backing_file != NULL);
	ASSERT (lock_held_by_current_thread (&filesys_lock));
	ASSERT (vma != NULL);
		
	struct map_file *mapfile = calloc(1, sizeof(struct map_file));

	/* Allocation failed. */
	if (mapfile == NULL)
		return false;

	mapfile->inode = backing_file->inode;
		
	lock_acquire (&mapfile_pool_lock);
	struct hash_elem *result = hash_insert (&mapfile_pool, &mapfile->elem);
	struct map_file *existing = result == NULL ? NULL : 
																				hash_entry (result, struct map_file, elem);

	if (existing != NULL)
		{
			/* Found existing MAP_FILE instance. */
			lock_release (&mapfile_pool_lock);
			free (mapfile);

			/* Must not load an executable that was MMAPed as a normal file, 
			   nor the other way around. */
			ASSERT (existing->writable != file_is_deny_write (backing_file));

			lock_acquire (&existing->page_pool_lock);
			if (existing->file_end < (off_t)(vma->offset + vma->filesize))
				existing->file_end = vma->offset + vma->filesize;
			list_push_back (&existing->vma_list, &vma->mapfile_elem);
			lock_release (&existing->page_pool_lock);

			vma->mapfile = existing;
		}
	else
		{
			/* Initialize new MAP_FILE. */
			backing_file = file_reopen (backing_file);

			if (backing_file == NULL)
				{
					hash_delete (&mapfile_pool, &mapfile->elem);
					lock_release (&mapfile_pool_lock);
					free (mapfile);
					return false;
				}

			mapfile->backing_file = backing_file;
			mapfile->writable = writable;

			list_init (&mapfile->vma_list);
			hash_init (&mapfile->page_pool, frame_hash_func, 
																			frame_less_func, NULL);
			lock_init (&mapfile->page_pool_lock);

			list_push_back (&mapfile->vma_list, &vma->mapfile_elem);
			if (mapfile->file_end < (off_t)(vma->offset + vma->filesize))
				mapfile->file_end = vma->offset + vma->filesize;
			vma->mapfile = mapfile;
			lock_release (&mapfile_pool_lock);
		}
	return true;
}

/** Detach a VMA from the MAP_FILE.
    Invoked when process exits, or handling MUNMAP syscall.
		If the vma_list of MAP_FILE becomes empty after detaching, 
		free this MAP_FILE as well. 

		Accessing vma_list must be atomic against mapfile_add_vma(). 
		Otherwise, we might be freeing a MAP_FILE that mapfile_add_vma() 
		has decided to add to. This is ensured by both functions acquiring 
		mapfile_pool_lock. */
void
mapfile_remove_vma (struct map_file *mapfile, struct vm_area *vma)
{
	ASSERT (mapfile != NULL);
	ASSERT (vma != NULL);

	lock_acquire (&mapfile->page_pool_lock);
	lock_acquire (&mapfile_pool_lock);
	
	list_remove (&vma->mapfile_elem);
	vma->mapfile = NULL;  // Not necessary, but reassuring.

	if (list_empty (&mapfile->vma_list))
		{
			/* Free MAP_FILE. */
			ASSERT (hash_delete (&mapfile_pool, &mapfile->elem) != NULL);
			lock_release (&mapfile_pool_lock);

			lock_release (&mapfile->page_pool_lock);

			/* Free the present frames in page_pool.
			   Note that we DO NOT grab the page_pool_lock here. For one,
				 the MAP_FILE should no longer be found by VMA, so page_pool
				 is only accessed here. More importantly, frame_free() grabs
				 frame_table_lock, while the frame_evict() routine first grabs
				 frame_table_lock, then the page_pool_lock for reverse mapping.
				 Grabbing page_pool_lock here can cause a DEADLOCK. */
				
			struct hash_iterator it;
			hash_first (&it, &mapfile->page_pool);

      while (hash_next (&it))
      	{
					lock_acquire (&frame_table_lock);
					struct hash_elem *h = hash_cur (&it);
        	struct frame *f = hash_entry (h, struct frame, elem);

					int remaining = (int)(vma->filesize - frame_offset (f));
					int read_bytes = remaining > PGSIZE ? PGSIZE : remaining;
					
         	frame_free (f, read_bytes);
					/* frame_table_lock atomatically released. */
      	}
				
			lock_acquire (&filesys_lock);
			file_close (mapfile->backing_file);
			lock_release (&filesys_lock);

			free (mapfile);
		}
	else
		{
			lock_release (&mapfile->page_pool_lock);
			lock_release (&mapfile_pool_lock);
		}
}

/** Fetch the physical address of the page described by MAP_FILE, OFFSET, 
    and READ_BYTES.
  
		Invoked by PF handler to retrieve the frame to fill the faulting PTE.
		Either the page is already in memory (shared, so PTEs can be out of sync),
		and just locate it using page_pool; or that page must be fetched from 
		the backing file.
		For the latter case, a new frame is occupied, and returned as BUSY, so
		that eviction ignores it, until caller finishes subsequent handling
		(setting PTEs), and clears the BUSY bit.
		
		NULL could be returned, if page eviction fails, where the PF cannot be 
		resolved at once. Luckily this should be rare with decent memory and 
		reasonable eviction mechanism. */
void *
mapfile_get_page (struct map_file *mapfile, off_t offset, size_t read_bytes, 
									void *fault_addr)
{
	ASSERT (mapfile != NULL);
	lock_acquire (&mapfile->page_pool_lock);

	struct frame query =
		{
			mapfile: 0,
			offset: offset, // offset is enough for querying
			elem: {{NULL, NULL}},
		};

	struct hash_elem *result = hash_find (&mapfile->page_pool, &query.elem);
	struct frame *existing = result == NULL ? NULL : 
																		 hash_entry (result, struct frame, elem);
		
	if (existing != NULL)
		{
			/* Page is already in memory. 
			   Set the PTE before releasing page_pool_lock. */
			
			if (frame_is_busy (existing))
				goto done;
			
			if (thread_current ()->want_pinned)
				{
					if (!frame_set_pinned (existing))
						goto done;
				}

			void *page = frame_to_phys (existing);
			struct thread *cur = thread_current ();

			bool writable = pagedir_is_writable (cur->pagedir, fault_addr);
			pagedir_set_page (cur->pagedir, pg_round_down (fault_addr), 
							 					page, writable);
			pagedir_set_accessed (cur->pagedir, fault_addr, true);
#ifdef FRAME_DEBUG
			printf ("%d Shared content on address %p, to frame %p\n", 
              thread_tid(), fault_addr, page);
#endif
			done:
			lock_release (&mapfile->page_pool_lock);
			return NULL;
		}
	else
		{
			/* Page not resident. Read from backing file. */
			struct frame *f;
			f = frame_alloc ();
			if (f != NULL)
				{
					/* NOTE: This section involves difficult synchronization. 
						 Before releasing page_pool_lock, we set the frame busy, and
						 add it to page_pool. After releasing, subsequent PFs using this
						 pool can happen, and if they fetch this very frame, they fail
						 the BUSY bit check and start again. 

						 In principle, frame_table_lock should be grabbed before modifying
						 frame table (setting BUSY bit). However, as the frame is newly 
						 allocated, frame_is_empty(f) is true until we actually set f->mapfile
						 below, so frame_evict() will never choose to evict this frame.
						 Moreover, frame_table_lock cannot be held before we release 
						 page_pool_lock: frame_evict() has to hold these two locks in 
						 reversed order, causing a DEADLOCK! */
						
					frame_set_busy (f);
					/* Not until here could frame_evict() find this frame not empty. But
					   it is still BUSY, and not possibly evicted. */
					if (thread_current ()->want_pinned)
						frame_set_pinned (f);
					frame_set_mapfile (f, mapfile);
					frame_set_offset (f, offset);
					frame_clear_write (f);
					hash_insert (&mapfile->page_pool,&f->elem);
					lock_release (&mapfile->page_pool_lock);
					/* By now PF can come in, and will busy wait fetching this frame. */

					void *phys_addr = frame_to_phys (f);
					/* Read ONE PAGE at OFFSET from backing file, instead of READ_BYTES.
					   This is because for executables, segments can be broken up in
						 middle of a page. If the rest bytes are zeroed, access to the 
						 second segment sees zeros instead of actual data. Try the
						 userprog/read-normal test to this see in action. */
					if (offset + PGSIZE <= mapfile->file_end)
						read_bytes = PGSIZE;
					
					lock_acquire (&filesys_lock);
					size_t bytes_read = file_read_at (mapfile->backing_file, phys_addr, read_bytes, offset);
					lock_release (&filesys_lock);

					ASSERT (bytes_read == read_bytes);

					/* The rest bytes are zeroed. */
					memset (phys_addr + read_bytes, 0, PGSIZE - read_bytes);

					return phys_addr;
				}
			else
				{
					/* Must evict an existing page. 
					   First try sort eviction, then hard. */
					lock_release (&mapfile->page_pool_lock);
					if (frame_evict (EVICT_MIN_CNT, false) == 0)
						frame_evict (EVICT_MIN_CNT, true);
					return NULL;
				}
		}
	NOT_REACHED ();
}

/** Get one zeroed page, set frame pointed to VMA with proper OFFSET, and
		return the physical address of allocated frame.
  
		Invoked by PF handler to fill PTE with a newly allocated, zeroed page.
		This initialization of a page should only happen once, i.e. the first 
		time an anonymous page is accessed. Later, if evicted, the page should
		be found in swap.

		This function involves no I/O, but may cause page eviction. The frame
		returned is left as BUSY.
		NULL could be returned, if page eviction fails, where the PF cannot be 
		resolved at once. */
void *
anon_get_page (struct vm_area *vma, off_t offset)
{
	ASSERT (vma != NULL);
	struct frame *f; 
	retry:
	f = frame_alloc ();
	if (f != NULL)
		{
			frame_set_busy (f);
			if (thread_current ()->want_pinned)
				frame_set_pinned (f);
			/* Note that VMA may not actually be anonymous, like .bss pages sharing
			   a VMA with .data pages. The former should always be paged in with
				 anon_get_page() and swap_get_page(), and not registered into page_pool,
				 while the latter should be paged in with mapfile_get_page(). */
			frame_set_anon_vma (f, vma);
			frame_set_offset (f, offset);
			frame_set_write (f);

			return frame_to_phys (f);
		}
	else
		{
			/* Must evict an existing page. 
				 First try sort eviction, then hard. */
			if (frame_evict (EVICT_MIN_CNT, false) == 0 &&
					frame_evict (EVICT_MIN_CNT, true) == 0)
				return NULL;
			goto retry;
		}
	NOT_REACHED ();
}


/** Hash funcs for MAP_FILES in mapfile_pool. */
unsigned 
mapfile_pool_hash_func (const struct hash_elem *e, void *aux UNUSED)
{
	struct map_file *mapfile = hash_entry (e, struct map_file, elem);
	return hash_int ((int) mapfile->inode);
}

bool 
mapfile_pool_less_func (const struct hash_elem *a,
                        const struct hash_elem *b,
                        void *aux UNUSED)
{
	return hash_entry (a, struct map_file, elem)->inode <
				 hash_entry (b, struct map_file, elem)->inode;	
}