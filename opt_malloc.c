
#include "xmalloc.h"
#include <string.h>
#include <sys/mman.h>
#include <pthread.h>
#include "stdio.h"
#include <stdlib.h>

#define EXIT_FAILURE 1

#define handle_error(msg) \
  do { perror(msg); exit(EXIT_FAILURE); } while (0)


// Flag to check for mutex init done or not . 
int isInitDone = 0;

// Below api initialises a single mutex to protect
// all the memory related ops for xv6 OS as below . 
void xmutex_init(pthread_mutex_t* lock)
{
  if(pthread_mutex_init(lock,NULL)!=0)
  {
    handle_error("pthread_mutex_init!");	  
  }	  
}

// Grabs the lock for xv6 memory operations
void xmutex_lock(pthread_mutex_t* lock)
{
  if(pthread_mutex_lock(lock)!=0)
  {
    handle_error("pthread_mutex_lock!");	  
  }	  	
}

// Unlocks the mutex for xv6 memory operations
void xmutex_unlock(pthread_mutex_t* lock)
{
  if(pthread_mutex_unlock(lock)!=0)
  {
    handle_error("pthread_mutex_unlock!");	  
  }	  	
}

// Data structures used for advanced arenas technique

#define NUM_SIZES 11

// TODO : This need to come from an existent kernel define 
#define PAGE_TABLE_SIZE 4096

// It is kinda magic number dont worry about it much . 
#define HEADER_FRAGMENT_OVERFLOW 4096

// 128 bytes is sufficient to hold for 4 bytes size arena 
#define BMSK_HEADER_SIZE 128

#define NUM_FREE_FRAGMENT_BMSK_WORDS (PAGE_TABLE_SIZE / (8*sizeof(uint)))
#define PAGE_TABLE_SIZE_WORDS        (PAGE_TABLE_SIZE  / sizeof(uint)) 

#define MIN_ARENA_SIZE 4
#define MAX_ARENA_SIZE 4096

// Header [ free fragments bitmask | data - payload ] in the end
// Note whenever you encounter header in the code it is header + payload . 
typedef struct
{
  uint free_fragments_bitmask[NUM_FREE_FRAGMENT_BMSK_WORDS];
  uint count_alloc_free;
  uint data_ptr[PAGE_TABLE_SIZE_WORDS];  
} arena_free_list_header_t; 

// Header for a block of memory which serves to disclose 
// useful information like header , fragment position etc.., 
typedef struct
{
  uint size;
  arena_free_list_header_t* header_ptr;
  uint index_page;  
} block_header_t; 

#define BYTES_PADDING 20

int arenas_sizelist[NUM_SIZES] = {4+BYTES_PADDING,8+BYTES_PADDING, 16+BYTES_PADDING, 32+BYTES_PADDING, 64+BYTES_PADDING, 128+BYTES_PADDING, 256+BYTES_PADDING, \
                                     512+BYTES_PADDING, 1024+BYTES_PADDING, 2048+BYTES_PADDING, 4096+BYTES_PADDING};


// List of headers of arena that would be used in optimized malloc
struct arena_free_list_t
{
  arena_free_list_header_t header_ptr;
  struct arena_free_list_t* next;  
}; 

// Final structure that would embed the size , lock and list for an arena 
typedef struct 
{
  uint size;
  pthread_mutex_t lock;
  struct arena_free_list_t* free_list; 	
}arena_struct_t;

arena_struct_t free_lists[NUM_SIZES] = {0}; 

// Api to initialise arena lists , size and lock for the same
void init_arena_lists()
{
  for(int i=0;i<NUM_SIZES;i++)
  {
    free_lists[i].size = arenas_sizelist[i];
    xmutex_init(&free_lists[i].lock);
    free_lists[i].free_list = NULL;
  }	  
}

// Get an arena based on the size of allocation
// Note that if size is 2 bytes it would be approximated
// to 4 bytes . 
arena_struct_t* get_arena_list(uint size_bytes)
{
  for(int i=0;i<NUM_SIZES;i++)
  {
    if(size_bytes <= arenas_sizelist[i])
	{
	  return &free_lists[i];	
	}		
  }
  return NULL;
}

// Get a page to spawn a new free list header only .
struct arena_free_list_t* alloc_free_list(uint size)
{
  struct arena_free_list_t* free_list_ptr = mmap(NULL,sizeof(struct arena_free_list_t),PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_SHARED,-1,0);
  if((char*)free_list_ptr == MAP_FAILED)
    handle_error("alloc_free_list - mmap_malloc");
 
  arena_free_list_header_t* free_list_header_ptr = (arena_free_list_header_t*)&free_list_ptr->header_ptr;

  for(int j=0;j<NUM_FREE_FRAGMENT_BMSK_WORDS;j++)
  {
    free_list_header_ptr->free_fragments_bitmask[j] = 0;	
  }
  free_list_header_ptr->free_fragments_bitmask[0] = 1;
  return free_list_ptr;
}

// Get a '0' bit on the bitmask which would indicate
// a free fragment .
uint get_free_fragment_index(uint bitmask)
{
  int index = 0;	
  for(;index<8*sizeof(uint);index++)
  {
    if(((bitmask >> index) & 0x1) == 0)
	{
	  return index;	
	}		
  }
  return index;  
}

uint get_free_fragment_index_header(arena_free_list_header_t* free_list_header_ptr , uint arena_list_size)
{
  int num_max_fragments = ((PAGE_TABLE_SIZE / arena_list_size) - 1);

  for(uint bmsk_array_index=0;bmsk_array_index<NUM_FREE_FRAGMENT_BMSK_WORDS;bmsk_array_index++)
  {
	uint num_fragment   = bmsk_array_index * (8*sizeof(uint));  
    uint fragment_index = get_free_fragment_index(free_list_header_ptr->free_fragments_bitmask[bmsk_array_index]);
    uint index_factor   = (num_fragment+fragment_index);
	if(fragment_index < 8*sizeof(uint))
	{
	  uint index = 0;	
      if(index_factor < num_max_fragments)
	  {
		free_list_header_ptr->free_fragments_bitmask[bmsk_array_index] = free_list_header_ptr->free_fragments_bitmask[bmsk_array_index] | ( 1 << fragment_index );  
	    index = (index_factor*arena_list_size)/sizeof(uint); 	  
	  }
      else
	  {
	    index = HEADER_FRAGMENT_OVERFLOW; 	  
	  }
      return index;	  
	}    	
  }	
  return HEADER_FRAGMENT_OVERFLOW;  
}

// Custom api that allocates a page
// nn : size in bytes , based on which it would allocate
// number of required pages
// offset : Distance from start of page where the address
// need to be returned 
void* mmap_palloc(int nn)
{
  char *addr = mmap(NULL,nn,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_SHARED,-1,0);
  if(addr == MAP_FAILED)
    handle_error("mmap_malloc");

  return (void*)addr;  
}

// Find a fragment in arena and return a pointer to it 
void* find_fragment_ptr(arena_struct_t* arena_list)
{
  // Put an arena lock as we would be doing global ops on arena
  //xmutex_lock(arena_list->lock);	
  if(arena_list->free_list == NULL)
  {
	// Alloc a page for free list and adjoin  it to this pointer . 
	// return the first fragment directly . 
    arena_list->free_list = alloc_free_list(arena_list->size);
	
	block_header_t* block_header = (block_header_t*)&arena_list->free_list->header_ptr.data_ptr[0];
	
	block_header->header_ptr = (arena_free_list_header_t*)&arena_list->free_list->header_ptr;
	block_header->size = arena_list->size;
	block_header->index_page = 0;
    
	arena_list->free_list->header_ptr.count_alloc_free = 1;

	return (void*)&arena_list->free_list->header_ptr.data_ptr[0];
  }	  
  else
  {
	struct arena_free_list_t* free_list_ptr = arena_list->free_list;
    
	while(free_list_ptr != NULL)
	{
	  // Search for a fragment , if it exceed maximum number of fragments then allocate a new page 
      // return it's first fragment . Or else just go onto next free list and checkout for a free fragment . 
	  uint index_page = get_free_fragment_index_header(&free_list_ptr->header_ptr,arena_list->size);
	  if(index_page == HEADER_FRAGMENT_OVERFLOW)
	  {   
		if(free_list_ptr->next == NULL)
		{			
          free_list_ptr->next = alloc_free_list(arena_list->size);
		  free_list_ptr       = free_list_ptr->next;
		  free_list_ptr->next = NULL;

		  void* alloc_ptr = (void*)&free_list_ptr->header_ptr.data_ptr[0];
		  
		  block_header_t* block_header = (block_header_t*)alloc_ptr;
		  
		  block_header->header_ptr = (arena_free_list_header_t*)&free_list_ptr->header_ptr;
		  block_header->size = arena_list->size;
		  block_header->index_page = 0;
		  
		  free_list_ptr->header_ptr.count_alloc_free = 1;
		  
		  return alloc_ptr;		  
	    }
		else
		{	
		  free_list_ptr = free_list_ptr->next;
		}			
	  }
      else
      {
        void* alloc_ptr = (void*)&free_list_ptr->header_ptr.data_ptr[index_page];
		
		free_list_ptr->header_ptr.count_alloc_free = free_list_ptr->header_ptr.count_alloc_free + 1;
		
		block_header_t* block_header = (block_header_t*)alloc_ptr;
		  
		block_header->header_ptr = (arena_free_list_header_t*)&free_list_ptr->header_ptr;
		block_header->size = arena_list->size;
		block_header->index_page = index_page;
		  
		return alloc_ptr;
      }		
    }	  
  }
  // Never come here , if it comes here then there is a serious bug !!!
  return NULL;  
}

// Check for all bitmask words , if they happen to be zero then we can unmap the free list 
// to release pages 
// Not a thread safe api 
void check_bmsk_words_arena_list_unmap(arena_struct_t* arena_list)
{
  int check_bmsk = 0;
  struct arena_free_list_t* free_list_ptr = arena_list->free_list; 
  struct arena_free_list_t* free_list_ptr_prev = free_list_ptr;

  while(free_list_ptr != NULL)
  {
    for(int j=0;j<NUM_FREE_FRAGMENT_BMSK_WORDS;j++)
    {
      if(free_list_ptr->header_ptr.free_fragments_bitmask[j] != 0)
      {
        check_bmsk = check_bmsk + 1;	
      }		
    }
  
    if(check_bmsk == 0)
    {  
      void* unmap_ptr = free_list_ptr; 
      if(free_list_ptr->next == NULL)
	  {	
        if(free_list_ptr_prev == free_list_ptr)  	
        {
		  arena_list->free_list = NULL;
		}
		else
		{
		  free_list_ptr_prev->next = NULL;	
		}
		free_list_ptr = NULL;  
	  }
	  else
	  {
		// First node was the one toggled with next node still in action , 
        // so perform a patch or stitch here . 		
		
		if(free_list_ptr_prev == free_list_ptr)
		{
		  arena_list->free_list = arena_list->free_list->next;	  		
		  free_list_ptr = arena_list->free_list;
		  free_list_ptr_prev = free_list_ptr;
    	}
		else
		{	
	      free_list_ptr = free_list_ptr->next;
          free_list_ptr_prev->next = free_list_ptr;
    	}	    	
	  }
	  munmap(unmap_ptr,sizeof(struct arena_free_list_t));
    }
	else
	{
	  free_list_ptr_prev = free_list_ptr;  
	  free_list_ptr = free_list_ptr->next;
      	  
	}
  }	
}

// Free the fragment index ( basically unset that particular bit )
void free_fragment(arena_struct_t* arena_list,arena_free_list_header_t* arena_list_header,uint index)
{
  uint size_list_factor           = arena_list->size / (sizeof(uint));
  uint scaled_down_index          = index / size_list_factor;  
  uint bitmask_table_index        = scaled_down_index / (8*sizeof(uint));
  uint bitmask_table_index_offset = scaled_down_index % (8*sizeof(uint));
  uint bitmask_offset = ~(1 << bitmask_table_index_offset);
  arena_list_header->free_fragments_bitmask[bitmask_table_index] = arena_list_header->free_fragments_bitmask[bitmask_table_index] & bitmask_offset;  
  arena_list_header->count_alloc_free = arena_list_header->count_alloc_free - 1;
  //if(arena_list_header->count_alloc_free == 0)
  //{
    check_bmsk_words_arena_list_unmap(arena_list);
  //}
}

void*
xmalloc(size_t bytes)
{
  if(isInitDone == 0)
  {
    init_arena_lists();
	isInitDone = 1;
  }
  
  size_t adjusted_bytes = bytes + BYTES_PADDING;
  arena_struct_t* arena_list =  get_arena_list(adjusted_bytes);  
  void* malloc_ptr = NULL;
  
  if(arena_list != NULL)
  {
	xmutex_lock(&arena_list->lock);  
	malloc_ptr = (void*)find_fragment_ptr(arena_list);
    xmutex_unlock(&arena_list->lock);
    
  }
  else
  {
	// Push the buffer down by a BYTES_PAD then stash the size there and 
    // return the pushed buffer as an allocated one . 
    malloc_ptr = (void*)mmap_palloc(adjusted_bytes);
  }

  block_header_t* alloc_ptr_int = (block_header_t*)malloc_ptr;

  //printf("xmalloc : header_p : %p , i_pg : %d , size : %d , a_ptr : %p " , alloc_ptr_int->header_ptr , alloc_ptr_int->index_page , alloc_ptr_int->size , alloc_ptr_int);
 
  alloc_ptr_int->size = adjusted_bytes;
  uint* alloc_ptr_uint = (uint*)alloc_ptr_int;
  alloc_ptr_uint       = alloc_ptr_uint + (BYTES_PADDING/(sizeof(uint)));
  malloc_ptr          = (void*)alloc_ptr_uint;
 
  //printf("xmalloc : f_ptr : %p \n" , malloc_ptr);

  return malloc_ptr;
}

void
xfree(void* ptr)
{
  
  uint* ptr_int = (uint*) ptr;
  //printf("xfree ptr_i : %p " , ptr_int);
  ptr_int = ptr_int - (BYTES_PADDING/(sizeof(uint)));	
  block_header_t* free_ptr_int = (block_header_t*)ptr_int;
  int adjusted_size = free_ptr_int->size;

  //printf("f_ptr : %p, header_p : %p , i_pg : %d , size : %d \n" , free_ptr_int , free_ptr_int->header_ptr , free_ptr_int->index_page , free_ptr_int->size);
 
  arena_struct_t* arena_list = get_arena_list(adjusted_size);	 	
	
  if(arena_list == NULL)
  {

	if(adjusted_size == 0)
	{
	  printf("Error Unmap! , ptr : %p \n" , ptr_int);
      handle_error(" Error! Look Above \n");	  
	}
    munmap(ptr_int,adjusted_size);	  
  }
  else
  {	
    xmutex_lock(&arena_list->lock);  
    arena_free_list_header_t* header_ptr = free_ptr_int->header_ptr;  
    free_fragment(arena_list , header_ptr , free_ptr_int->index_page);  
    xmutex_unlock(&arena_list->lock);
  } 
}

void*
xrealloc(void* prev, size_t bytes)
{
  // Write an optimized realloc
  xfree(prev);
  return xmalloc(bytes);
}
