#include "mm.h"
#include "swap.h"
#include "frame.h"
#include "devices/block.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "devices/timer.h"
#include "threads/thread.h"
#include <stdio.h>

/** Swap disk device. */
struct block *swap_space;

/** Size of swap, in terms of number of pages. */
size_t swap_size;

/** Bitmaps for managing swap slots. 
    We build our own version of bitmap on top of clusters, instead of 
    the default bitmap implementation in Pintos, in pursuit of 
    efficiency. */
bitmap_t swap_table;
bitmap_t swap_table_busy;

/** Lock protecting SWAP_TABLE. 
    This lock is actually only used when allocating swap slots, and
    can be replaced by atomic memory addition and bit-test-and-set
    instructions. */
struct lock swap_table_lock;

static inline bool bitmap_cluster_none (bitmap_t b, size_t clu_idx);
static inline int bitmap_cluster_first (bitmap_t b, size_t clu_idx);
static inline void bitmap_cluster_set (bitmap_t b, size_t clu_idx, int bit_idx);
static inline void bitmap_cluster_clear (bitmap_t b, size_t clu_idx, int bit_idx);


/** Initializes the swap space. Claim a block device exclusively
    for swapping, and allocate SWAP_TABLE for managing swap slots.
    If either fails, print a warning message, and the memory system
    runs as if swap space is ALWAYS FULL. */
void 
swap_init (void)
{
  lock_init (&swap_table_lock);
  if ((swap_space = block_get_role (BLOCK_SWAP)) == NULL)
    goto no_swap;
  
  swap_size = block_size (swap_space) * BLOCK_SECTOR_SIZE / PGSIZE;
  swap_size -= swap_size % SWAP_CLUSTER_SIZE;
  if (swap_size == 0)
    goto no_swap;
  /* Pintos only support one swap disk up to 4GB. */
  if (swap_size > (1 << 20))
    swap_size = 1<<20;

  /* Allocate bitmaps as SWAP_TABLE. */
  swap_table = calloc (swap_size / SWAP_CLUSTER_SIZE, sizeof (cluster_t));
  swap_table_busy = calloc (swap_size / SWAP_CLUSTER_SIZE, sizeof (cluster_t));
  if (swap_table == NULL || swap_table_busy == NULL)
    {
      if (swap_table != NULL)
        free (swap_table);
      if (swap_table_busy != NULL)
        free (swap_table_busy);
      goto no_swap;
    }
  
  /* Reserve slot 0 (SWAP_SLOT_INVALID), so that swap index 0 is always 
     not allocated for swapped pages. 
     Helps debugging; besides, that page might also be used to store 
     meta data on disk. */
  swap_table[0] = 1;
  return;

  no_swap:
  swap_size = 0;
  swap_space = NULL;
  printf ("swap_init: warning - swap space unavailable\n");
}

/** Reserve a free slot in swap space, return the swap slot index.
    If no slot is available, SWAP_SLOT_INVALID is returned.
    This is the only routine that must be synced using swap_table_lock. */
int
swap_reserve_slot (void)
{
  /** Current cluser index, protected by swap_table_lock. */
  static size_t clu_idx = 0;

  lock_acquire (&swap_table_lock);
  size_t scanned = 0;
  int slot_idx = SWAP_SLOT_INVALID;
  while (scanned < swap_size)
    {
      scanned++;
      if (!bitmap_cluster_none (swap_table, clu_idx))
        {
          int offset = bitmap_cluster_first (swap_table, clu_idx);
          bitmap_cluster_set (swap_table, clu_idx, offset);
          slot_idx = offset + SWAP_CLUSTER_SIZE * clu_idx;
          ASSERT (!swap_is_busy (slot_idx));

          clu_idx = (clu_idx + 1) % (swap_size / SWAP_CLUSTER_SIZE);
          break;
        }
      clu_idx = (clu_idx + 1) % (swap_size / SWAP_CLUSTER_SIZE);
    }
  lock_release (&swap_table_lock);
  return slot_idx;
}

/** Free the slot SLOT_IDX in swap table. 
    The specified slot must not be already free. It can however be 
    BUSY, when frame_free() is halfway swapping a page that belongs
    to a dying process, freeing its slots in swap. In that case, this
    rountine busy waits until it is no longer BUSY, to ensure data 
    written later to this slot is not corrupted. */
void
swap_free_slot (int slot_idx)
{
  ASSERT (slot_idx != SWAP_SLOT_INVALID && slot_idx < (int)swap_size);
  int clu_idx = slot_idx / SWAP_CLUSTER_SIZE;
  int offset = slot_idx % SWAP_CLUSTER_SIZE;
  ASSERT (swap_table[clu_idx] & (1<<offset));
#ifdef FRAME_DEBUG
  printf ("%d freed SWAP slot %d\n", thread_tid (), slot_idx);
#endif
  while (swap_is_busy (slot_idx))
    timer_msleep (10);
  swap_table[clu_idx] &= ~(1<<offset);
}

/** Swap in page specified by SLOT_IDX, set frame pointed to VMA with proper 
    OFFSET, and return the physical address of allocated frame. Once swapping
    in is done, the slot is also freed.
    Invoked by PF handler to fill PTE with a frame that contains swapped in
    data. The frame is left as BUSY.

		NULL could be returned, if page eviction fails, or the wanted page is BUSY
    (i.e. it is still halfway swapping out), where the PF cannot be resolved 
    at once. */
void *
swap_get_page (struct vm_area *vma, off_t offset, int slot_idx)
{
  ASSERT (slot_idx != SWAP_SLOT_INVALID && slot_idx < (int)swap_size);
	ASSERT (vma != NULL);
  /* Busy waits for BUSY slot. */
  if (swap_is_busy (slot_idx))
    return NULL;

	struct frame *f; 
	retry:
	f = frame_alloc ();
	if (f != NULL)
		{
      frame_set_busy (f);
      if (thread_current ()->want_pinned)
        frame_set_pinned (f);
			frame_set_anon_vma (f, vma);
			frame_set_offset (f, offset);
			frame_set_write (f);
      
      swap_set_busy (slot_idx);

      /* Start I/O to swap-in data. Synchronization is done within block_read. */
      
      void *phys_addr = frame_to_phys (f);
      for (int sec = 0; sec < SECTOR_PER_PAGE; sec++)
        block_read (swap_space, slot_idx * SECTOR_PER_PAGE + sec,
                    phys_addr + BLOCK_SECTOR_SIZE * sec);
      
      swap_clear_busy (slot_idx);
      swap_free_slot (slot_idx);
      return phys_addr;
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

/** Swap out PAGE to SLOT_IDX, which must be reserved and has its bit set
    in swap_table, and already set as BUSY. */
void
swap_put_page (int slot_idx, void *page)
{
  ASSERT (slot_idx != SWAP_SLOT_INVALID && slot_idx < (int)swap_size);
  ASSERT (swap_is_busy (slot_idx));

  for (int sec = 0; sec < SECTOR_PER_PAGE; sec++)
    block_write (swap_space, slot_idx * SECTOR_PER_PAGE + sec,
                 page + BLOCK_SECTOR_SIZE * sec);
}

/** Returns whether the slot SLOT_IDX is busy. */
bool 
swap_is_busy (int slot_idx)
{
  ASSERT (slot_idx != SWAP_SLOT_INVALID && slot_idx < (int)swap_size);
  int offset = slot_idx % SWAP_CLUSTER_SIZE;
  return swap_table_busy[slot_idx / SWAP_CLUSTER_SIZE] & (1<<offset);
}

/** Set the slot SLOT_IDX busy in SWAP_TABLE_BUSY. */
void 
swap_set_busy (int slot_idx)
{
  ASSERT (slot_idx != SWAP_SLOT_INVALID && slot_idx < (int)swap_size);
  bitmap_cluster_set (swap_table_busy, slot_idx / SWAP_CLUSTER_SIZE, 
                                       slot_idx % SWAP_CLUSTER_SIZE);
}

/** Clear BUSY bit in SWAP_TABLE_BUSY for the slot SLOT_IDX. */
void 
swap_clear_busy (int slot_idx)
{
  ASSERT (slot_idx != SWAP_SLOT_INVALID && slot_idx < (int)swap_size);
  bitmap_cluster_clear (swap_table_busy, slot_idx / SWAP_CLUSTER_SIZE, 
                                         slot_idx % SWAP_CLUSTER_SIZE);
}

/** Prints status of swap space, for debugging. */
void
swap_check (void)
{
  if (swap_space == NULL)
    {
      printf ("swap check: swap space is invalid\n");
      return;
    }
  printf ("swap check (size = %lu):\n", swap_size);
  hex_dump (0, swap_table, swap_size / sizeof(cluster_t), false);
}

/** Tests if a cluster is full. */
static inline bool 
bitmap_cluster_none (bitmap_t b, size_t clu_idx)
{
  return b[clu_idx] == 0xFFFFFFFF;
}

/** Returns the first clear bit in a cluster. */
static inline int bitmap_cluster_first (bitmap_t b, size_t clu_idx)
{
  /** Code by Andrew Shapira, see 
      https://graphics.stanford.edu/~seander/bithacks.html#ZerosOnRightMultLookup. */
  uint32_t v = ~b[clu_idx]; 
  static const int MultiplyDeBruijnBitPosition[32] = 
    {
      0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8, 
      31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9
    };
  return MultiplyDeBruijnBitPosition[((uint32_t)((v & -v) * 0x077CB531U)) >> 27];
}

/** Set the BIT_IDX bit of cluster CLU_IDX in BITMAP. */
static inline void bitmap_cluster_set (bitmap_t b, size_t clu_idx, 
                                      int bit_idx)
{
  b[clu_idx] |= (1<<bit_idx);
}

/** Clear the BIT_IDX bit of cluster CLU_IDX in BITMAP. */
static inline void bitmap_cluster_clear (bitmap_t b, size_t clu_idx, 
                                        int bit_idx)
{
  b[clu_idx] &= ~(1<<bit_idx);
}