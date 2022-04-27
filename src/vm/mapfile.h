#ifndef VM_MAPFILE_H
#define VM_MAPFILE_H

#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include <list.h>
#include <hash.h>
#include <string.h>

/** Flags for VM mappings. */
#define MAP_PRIVATE 1					/**< Private mapping, with COW. */
#define MAP_SHARED  2					/**< Shared mapping, by using the same physical frame.
																	 Pintos has no FORK syscall, nor MMAP option to 
																	 alias or share anonymous memory. So MAP_SHARED
																	 indicates file-backed memory. */
#define MAP_READ   	4					/**< Read-only mapping. */
#define MAP_WRITE   8					/**< Writable mapping. */

/* Macro for determining type of a VMA. */
#define vma_is_anon(pVMA) (pVMA->mapfile == NULL)
#define vma_is_filebacked(pVMA) (pVMA->mapfile != NULL)

struct map_file * mapfile_get_by_file (struct file *backing_file);

bool mapfile_add_vma (struct file *backing_file, struct vm_area *vma, bool writable);
void mapfile_remove_vma (struct map_file *mapfile, struct vm_area *vma);
void * mapfile_get_page (struct map_file *mapfile, off_t offset, size_t read_bytes, void *fault_addr);

void * anon_get_page (struct vm_area *vma, off_t offset);

unsigned mapfile_pool_hash_func (const struct hash_elem *e, void *aux UNUSED);
bool mapfile_pool_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);

#endif