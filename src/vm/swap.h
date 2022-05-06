#ifndef VM_SWAP_H
#define VM_SWAP_H

/** Pintos swap area management.
    
    One dedicated disk partition is used as the swap area. Pintos
    does not currently support multiple swap areas (Linux does),
    but it should be straightforward to add that feature. 
    
    On disk, the storage is simply organized as page sized slots,
    and the indice of slots are used as unique identifiers for 
    swapped pages: their PTEs will have PA (highest 20 bits) set
    to their on-disk indices, thus enabling the PF handler to
    page in data. This also limits the size area to be 4GB at
    most, which is acceptable in a 32-bit system.

    The allocation of a slot index is basically "smallest free",
    with a twist. To speed up finding the smallest free slot, slots 
    are grouped into clusters in size of SWAP_CLUSTER_SIZE. Each 
    allocation moves forward in clusters until one with free slot is 
    found. This way, scanning the slots becomes more efficient. */

#include "mm.h"
#include "devices/block.h"
#include "threads/vaddr.h"

typedef uint32_t cluster_t;
typedef uint32_t* bitmap_t;

#define SECTOR_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)
#define SWAP_CLUSTER_SIZE 32
#define SWAP_SLOT_INVALID 0

void swap_init (void);
int swap_reserve_slot (void);
void swap_free_slot (int slot_idx);
void * swap_get_page (struct vm_area *vma, off_t offset, int slot_idx);
void swap_put_page (int slot_idx, void *page);
bool swap_is_busy (int slot_idx);
void swap_set_busy (int slot_idx);
void swap_clear_busy (int slot_idx);

void swap_check (void);

#endif