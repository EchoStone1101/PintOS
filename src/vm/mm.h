#ifndef VM_MM_H
#define VM_MM_H

#include "threads/thread.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/off_t.h"
#include <list.h>
#include <hash.h>

/** Pintos virtual memory management for processes. 
    Heavily inspired by Linux. 
		This header file contains the declaration of relevant data structures
		(other than those concerning swap), and is more of a documentation. For
		the actual implementation, see mapfile.h, frame.h and swap.h.
		
		This system uses VM_AREAs as segment-based management for Supplementary
		Page Table, array of FRAMEs as Frame Table. The MAP_FILE exists as an
		intermediate to (1) simply the logical mapping from VMA to frames (2) 
		implement sharing. Refer to header comments down below for detailed 
		explanations.
		
		For a comparison with Linux memory management:
		 - Page cache (and swap cache) is not explicitly implemented. The
		 	 MAP_FILE layer is argubly caching the pages from files, but we 
			 do not currently cache anonymous pages or regular files.

		 - Reverse mapping is implemented, by traversing FRAME->MAP_FILE->
		   VMA->PTE. This helps swapping out shared pages with out using 
			 swap cache. We believe the runtime overhead is acceptable at
			 the Pintos scale. 

		 - Anonymous pages are NEVER SHARED in Pintos, because there is neither
		   FORK syscall, nor MMAP option to map anonymous page. This realization
			 simplifies the handling of anonymous pages, and convinces us that
			 explicit page cache (swap cache) is more awkward than useful in Pintos. 

		 - COW is of course available. It is handled by setting PTE read-only,
		   while the VMA as MAP_PRIVATE | MAP_WRITE. PF handler will recognize
			 this as COW, and creates an ANONYMOUS page to hold the new data. 
			 Note that while the occupied frame will be anonymous type, its anon_vma 
			 will be set to a file-backed VMA. Somewhat ad-hoc but works fine.
			 However, with out FORK and even MMAP with MAP_PRIVATE option, COW in
			 Pintos only takes effect when loading and accessing .data section
			 in executables. */



/** The abstraction for a mapped area in a process. 
    There can be multiple VM_AREAs for one process, chained by its 
		vma_list member in struct thread. Upon loading, one VM_AREA is 
		created for each segment. MMAP syscall also creates new VM_AREAs.
		The VMA holds lower and upper bound for valid virtual addresses 
		in the area. It also records type of the area: file-backed or
		anonymous; in the former case, VMA contains pointer to a MAP_FILE
		struct and the offset into the backing file.
		At page faults, the handler will first look into VMAs to see if
		the address is valid (falls into one VMA). If so, the information
		stored helps to fetch the non-present page. 
		At page eviction, all relevant VMAs are also walked, gathering the 
		PTEs that reference the page, so that they can be invalidated. 
		When the process exits, all its VMAs are freed. */
struct vm_area
	{
		void *lower_bound;								/**< The lower bound of valid virtual address. */
		void *upper_bound;								/**< The upper bound of valid virtual address. */
		struct list_elem proc_elem;				/**< List element for owner process. */
		struct thread *proc;		 					/**< Owner process of this VMA. */

		int flags;												/**< Flags: private or shared, read-only or writable. */

		/* Only relevant for file-backed area. */
		struct map_file *mapfile;					/**< Pointer to backing file.	NULL indicates anonymous area. */
		struct list_elem mapfile_elem;		/**< List element for map_file struct. 
																					 Also used by frame_reverse_map(). */
		off_t offset;											/**< Offset into backing file. */
		uint32_t filesize;								/**< Size of file-segment. */
	};


/** Describes a unique memory mapped file (called address_space in
		Linux).
		For each different running executable and MMAPed file, exists 
		one MAP_FILE. Whenever a new process is loaded or a new file is
		MMAPed, a hash table containing existing MAP_FILEs is searched
		to see if an instance for that file already exists. If so, relevant
		VMA points to the existing MAP_FILE.

		Sharing is essentially implemented by VMAs in different processes 
		pointing to the same MAP_FILE. There's also aliasing, when VMAs 
		in the same process point to the same MAP_FILE, which happens with 
		repeated MMAP syscalls. When no VMA is pointing to this struct, it 
		is freed.
		
		A MAP_FILE importantly contains two one-to-many mappings: a list of 
		VMAs that points to it, and a hash table of frames for data pages in
		the file that are currently resident in physical memory. Without 
		MAP_FILE as an intermediate, the logical many-to-many mapping from 
		VMAs to frames is hard to implement without space overhead. */
struct map_file
	{
		struct file *backing_file;		/**< The backing file pointer. */
		off_t file_end;								/**< Marks the end of the mapped area of the file. */
		bool writable;								/**< Whether the backing file is writable.
																			 Useful when freeing map_file, where dirty pages
																			 should be written back if writable. */

		struct hash_elem elem;				/**< Hash element for global pool of MAP_FILEs. */
		void *inode;									/**< Inode pointer for backing file. */

		struct list vma_list;					/**< The list of VMAs that point to this struct. */
		struct hash page_pool;				/**< Contains all data pages from the file that are 
																			 currently in memory. */

		/* Synchronization. */
		struct lock page_pool_lock;		/**< Lock for page_pool. */
	};


/** Describes a physical frame in memory. 
    One such struct exists for EVERY frames available in user memory pool.
		In Pintos default settings, that is 367 frames. It is obviously crucial
		that this struct is as small as possible, and we manage to compress it
		to 16 bytes: 8 bytes for hash_elem, 4 bytes for a pointer to MAP_FILE
		or VM_AREA, and 4 bytes for offset packed with flags. We believe these
		are the bare minimum required.
		
		A non-empty frame either holds a file-backed page, or an anonymous page.
		Here, a frame holding anonymous data can point directly to ONE VMA, 
		because anonymous pages are NOT SHARED in Pintos. */
struct frame
	{
		union
		{
			int32_t mapfile;		 				/**< Pointer to the backing MAP_FILE instance. */
			int32_t anon_vma;						/**< ...or, pointer to an anonymous VMA. */
		};
		union
		{
			off_t offset;					 			/**< Offset in the backing file. 
																		   This is crucial for reverse mapping: 
																			 in tandem with offset in VMAs, we can
																			 craft all user PTEs that map into this 
																			 frame. */	 																
			int16_t flags;							/**< ...and use low bits for flags. Works because
																			 OFFSET is always page aligned. 
																			 Bit 0: Frame is file-backed or anonymous. 
																			 Bit 1: Frame needs write-back at eviction. 
																			 Bit 2: Frame is busy (under I/O).
																			 Bit 3-11: Frame is pinned (used by syscall handler).
																			 Up to 512 processes can pin this frame. Note that this
																			 does not impose restrictions on how many processes can
																			 reference this frame - pinning is not frequent, and 
																			 only one process gets to do I/O anyway. */
		};
		struct hash_elem elem;			 	 /**< Hash element for page_pool. */
	};

void mm_init (void);

#endif