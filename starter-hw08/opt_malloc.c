
#include "xmalloc.h"
#include <string.h>
#include <sys/mman.h>

#define EXIT_FAILURE 1

#define handle_error(msg) \
  do { perror(msg); exit(EXIT_FAILURE); } while (0)


// Below lock would be used for common mutex operations like 
// get an arena . 
pthread_mutex_t common_mutex_lock;

// Flag to check for mutex init done or not . 
int isInitDone = 0;

// Below api initialises a single mutex to protect
// all the memory related ops for xv6 OS as below . 
void xmutex_init(pthread_mutex_t lock)
{
  if(pthread_mutex_init(&lock,NULL)!=0)
  {
    handle_error("pthread_mutex_init!");	  
  }	  
}

// Grabs the lock for xv6 memory operations
void xmutex_lock(pthread_mutex_t lock)
{
  if(pthread_mutex_lock(&lock)!=0)
  {
    handle_error("pthread_mutex_lock!");	  
  }	  	
}

// Unlocks the mutex for xv6 memory operations
void xmutex_unlock(pthread_mutex_t lock)
{
  if(pthread_mutex_unlock(&lock)!=0)
  {
    handle_error("pthread_mutex_unlock!");	  
  }	  	
}

// Data structures used for advanced arenas technique

#define NUM_SIZES 20

// TODO : This need to come from an existent kernel define 
#define PAGE_TABLE_SIZE 4096

// 128 bytes is sufficient to hold for 4 bytes size arena 
#define BMSK_HEADER_SIZE 128

#define NUM_FREE_FRAGMENT_BMSK_WORDS (BMSK_HEADER_SIZE / sizeof(uint))
#define PAGE_TABLE_SIZE_WORDS        (PAGE_TABLE_SIZE  / sizeof(uint)) 

#define MIN_ARENA_SIZE 4
#define MAX_ARENA_SIZE 4096

int arenas_sizelist[NUM_SIZES] = {4, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 
384, 512, 768, 1024, 1536, 2048, 3192, 4096};

// Header [ free fragments bitmask | data - payload ] in the end
// Note whenever you encounter header in the code it is header + payload . 
typedef struct
{
  uint free_fragments_bitmask[NUM_FREE_FRAGMENT_BMSK_WORDS];
  uint data_ptr[PAGE_TABLE_SIZE_WORDS];  
} arena_free_list_header_t; 

// List of headers of arena that would be used in optimized malloc
struct arena_free_list_t
{
  arena_free_list_header_t* header_ptr;
  struct arena_free_list_t* next;  
}; 

// Final structure that would embed the size , lock and list for an arena 
typedef struct 
{
  uint size;
  pthread_mutex_t lock;
  struct arena_free_list_t free_list; 	
}arena_struct_t;

arena_struct_t free_lists[NUM_SIZES]; 

// Api to initialise arena lists , size and lock for the same
void init_arena_lists()
{
  xmutex_init(common_mutex_lock);
  
  for(int i=0;i<NUM_SIZES;i++)
  {
    free_lists[i].size = arenas_sizelist[i];
    xmutex_init(free_lists[i].lock);
    free_lists[i].free_list.header_ptr = NULL;		
  }	  
}

// Get an arena based on the size of allocation
// Note that if size is 2 bytes it would be approximated
// to 4 bytes . 
arena_struct_t* get_arena_list(uint size_bytes)
{
  xmutex_lock(common_mutex_lock);
  for(int i=0;i<NUM_SIZES;i++)
  {
    if(size_bytes <= arenas_sizelist[i])
	{
	  xmutex_unlock(common_mutex_lock);
	  return &free_lists[i];	
	}		
  }
  xmutex_unlock(common_mutex_lock);  
  return NULL;
}

// Get a page to spawn a new free list header only .
arena_free_list_header_t* alloc_free_list(uint size)
{
  arena_free_list_header_t* free_list_header_ptr = mmap(NULL,(size + BMSK_HEADER_SIZE + sizeof(uint)),PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_SHARED,-1,0);
  if((char*)free_list_header_ptr == MAP_FAILED)
    handle_error("alloc_free_list - mmap_malloc");
 
  for(int j=0;j<NUM_FREE_FRAGMENT_BMSK_WORDS;j++)
  {
    free_list_header_ptr->free_fragments_bitmask[j] = 0;	
  }
  free_list_header_ptr->free_fragments_bitmask[0] = 1;
  return free_list_header_ptr;
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
  xmutex_lock(arena_list->lock);	
  if(arena_list->free_list.header_ptr == NULL)
  {
	// Alloc a page for free list and adjoin  it to this pointer . 
	// return the first fragment directly . 
    arena_list->free_list.header_ptr = alloc_free_list(arena_list->size);
	xmutex_unlock(arena_list->lock);
	return (void*)&arena_list->free_list.header_ptr->data_ptr[0];
  }	  
  else
  {
    int num_max_fragments = PAGE_TABLE_SIZE / arena_list->size ;
	int num_fragment = 0;
	struct arena_free_list_t* free_list_ptr = (struct arena_free_list_t*)&arena_list->free_list;
    for(int j=0;j<NUM_FREE_FRAGMENT_BMSK_WORDS;j++)
	{
	  // Search for a fragment , if it exceed maximum number of fragments then allocate a new page 
      // return it's first fragment . Or else just go onto next free list and checkout for a free fragment . 	  
	  uint fragment_index = get_free_fragment_index(free_list_ptr->header_ptr->free_fragments_bitmask[j]);
	  if((num_fragment+fragment_index) > num_max_fragments)
	  {
		if(free_list_ptr->next == NULL)
		{			
          free_list_ptr->next = (struct arena_free_list_t*)alloc_free_list(arena_list->size);
		  free_list_ptr->next->header_ptr = (arena_free_list_header_t*)free_list_ptr->next; 
		  free_list_ptr->next->next = NULL;
		  xmutex_unlock(arena_list->lock);
		  printf("xmalloc - num_fragment : %d , fragment_index : %d , list_size : %d , page_used_ptr : %p , idx : 0 , m_ptr : %p \n" , num_fragment \
		        ,fragment_index , arena_list->size , arena_list->free_list.header_ptr , (void*)&free_list_ptr->header_ptr->data_ptr[0] );
          return (void*)&free_list_ptr->header_ptr->data_ptr[0];		  
	    }
		else
		{
		  free_list_ptr = (struct arena_free_list_t*)&free_list_ptr->next;
          j = 0;
          num_fragment = 0;		  
        }			
	  }
      else if(fragment_index < 8*sizeof(uint))
      {
        uint index = ((fragment_index+num_fragment)*arena_list->size)/sizeof(uint);
        free_list_ptr->header_ptr->free_fragments_bitmask[j] = free_list_ptr->header_ptr->free_fragments_bitmask[j] | ( 1 << fragment_index );
        xmutex_unlock(arena_list->lock);
	    printf("xmalloc - num_fragment : %d , fragment_index : %d , list_size : %d , page_used_ptr : %p , index : %d , m_ptr : %p \n" , num_fragment 
		  ,fragment_index , arena_list->size , arena_list->free_list.header_ptr , index , (void*)&free_list_ptr->header_ptr->data_ptr[index]);
        return (void*)&free_list_ptr->header_ptr->data_ptr[index];	  
      }
	  else
	  {
        num_fragment = num_fragment + 8*sizeof(uint);  
	  }    	
    }		
  }	  
   
  // Never come here , if it comes here then there is a serious bug !!!
  xmutex_unlock(arena_list->lock);
  return NULL;  
}

// APi : When an address is passed to free api , to fetch the corresponding
// arena list . 
// Check by the address range in which arena list it falls .
// Once such a range is found then thats the list !
arena_struct_t* find_arena_list(void* addr , arena_free_list_header_t** header_ptr_arg)
{
  xmutex_lock(common_mutex_lock);
  
  for(int i=0;i<NUM_SIZES;i++)
  {
	struct arena_free_list_t* free_list_ptr = (struct arena_free_list_t*)&free_lists[i].free_list;
	arena_free_list_header_t* free_list_header_ptr = free_list_ptr->header_ptr;
      
	while(free_list_header_ptr != NULL)
	{		
      size_t lower_bound_address = (size_t)&free_list_header_ptr->data_ptr[0];
      size_t upper_bound_address = (size_t)&free_list_header_ptr->data_ptr[PAGE_TABLE_SIZE_WORDS];	
      if(((size_t)addr < upper_bound_address) & ((size_t)addr >= lower_bound_address))
      {
	    xmutex_unlock(common_mutex_lock);
        *header_ptr_arg = free_list_header_ptr;		
        return (arena_struct_t*)&free_lists[i];  		
      }
	  free_list_ptr = free_list_ptr->next;
	  if(free_list_ptr != NULL)
	  {
		free_list_header_ptr = free_list_ptr->header_ptr;
      }
	  else
	  {
		free_list_header_ptr = NULL;  
	  }
	}	
  }
  xmutex_unlock(common_mutex_lock);
  // if code reaches here that indicates it aint part of any list , simply return NULL
  return NULL;  
}

// Perform a pointer arithmetic on the address to get the fragment index .
// Not a thread safe api 
uint get_fragment_index_address(void* addr ,arena_free_list_header_t* arena_list_header,uint arena_list_size)
{	
  size_t lower_bound_address = (size_t)&arena_list_header->data_ptr[0];
  uint addr_int = (size_t)addr;
  uint offset_base_bytes = addr_int - lower_bound_address;
  uint fragment_index = offset_base_bytes / arena_list_size;
  return fragment_index;
}

// Check for all bitmask words , if they happen to be zero then we can unmap the free list 
// to release pages 
// Not a thread safe api 
void check_bmsk_words_arena_list_unmap(arena_struct_t* arena_list)
{
  int check_bmsk = 0;
  struct arena_free_list_t* free_list_ptr      = (struct arena_free_list_t*)&arena_list->free_list;
  struct arena_free_list_t* free_list_ptr_prev = (struct arena_free_list_t*)&arena_list->free_list;
  
  while(free_list_ptr != NULL)
  {	  
    for(int j=0;j<NUM_FREE_FRAGMENT_BMSK_WORDS;j++)
    {
      if(free_list_ptr->header_ptr->free_fragments_bitmask[j] != 0)
      {
        check_bmsk = check_bmsk + 1;	
      }		
    }
  
    if(check_bmsk == 0)
    {  
      munmap(free_list_ptr->header_ptr,(arena_list->size+BMSK_HEADER_SIZE+sizeof(uint)));
	  printf("check_bmsk_words_arena_list_unmap : fl_ptr : %p \n" , free_list_ptr->header_ptr); 
	  free_list_ptr->header_ptr = NULL;
	  free_list_ptr_prev->next = free_list_ptr->next;
	  if(free_list_ptr->next == NULL)
	  {
        free_list_ptr_prev = free_list_ptr;  
		free_list_ptr = free_list_ptr->next;
	  }
	  else
	  {
		// First node was the one toggled with next node still in action , 
        // so perform a patch or stitch here . 		
	    if(free_list_ptr_prev == free_list_ptr)
		{
          free_list_ptr->header_ptr = free_list_ptr->next->header_ptr;
          free_list_ptr->next = free_list_ptr->next->next;  		  
		}
		else
		{	
	      free_list_ptr = free_list_ptr->next;	  	
		}
		free_list_ptr_prev = free_list_ptr;
	  }
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
  uint bitmask_table_index        = index / (8*sizeof(uint));
  uint bitmask_table_index_offset = index % (8*sizeof(uint));
  uint bitmask_offset = ~(1 << bitmask_table_index_offset);
  printf("free_frag , bt_idx : %d , bt_idx_ofs : %d , index : %d , size : %d \n" , bitmask_table_index , bitmask_table_index_offset , index , arena_list->size);
  arena_list_header->free_fragments_bitmask[bitmask_table_index] = arena_list_header->free_fragments_bitmask[bitmask_table_index] & bitmask_offset;  
  check_bmsk_words_arena_list_unmap(arena_list);
}

void*
xmalloc(uint bytes)
{
  if(isInitDone == 0)
  {
    init_arena_lists();
	isInitDone = 1;
  }
  
  arena_struct_t* arena_list =  get_arena_list(bytes);  
  void* malloc_ptr = NULL;
  
  if(arena_list != NULL)
  {
	malloc_ptr = (void*)find_fragment_ptr(arena_list);  
	//printf("xmalloc ent - bytes : %d , size_al : %d , malloc_ptr : %p , fl_ptr : %p , hdr_ptr : %p \n" , bytes , arena_list->size , malloc_ptr , arena_list , arena_list->free_list.header_ptr);
  }
  else
  {
	// Push the buffer down by a "uint" then stash the size there and 
    // return the pushed buffer as an allocated one . 
    
    malloc_ptr = (void*)mmap_palloc(bytes+sizeof(uint));
	uint* alloc_ptr_int = (uint*)malloc_ptr;
    *alloc_ptr_int = bytes;
	alloc_ptr_int = alloc_ptr_int + 1;
	printf("xmalloc : palloc , m_ptr : %p , a_i_ptr : %p , bytes : %d \n" , alloc_ptr_int , malloc_ptr , bytes);	
    malloc_ptr = (void*)alloc_ptr_int;	
  }
  
  return malloc_ptr;
}

void
xfree(void* ptr)
{
  printf("xfree - ptr : %p " , ptr);
  arena_free_list_header_t* header_ptr = NULL;
  arena_struct_t* arena_list = find_arena_list(ptr,&header_ptr);
  xmutex_lock(arena_list->lock);
  if(arena_list == NULL)
  {
	uint* ptr_int = (uint*) ptr;
    ptr_int = ptr_int - 1;	
	int size = *ptr_int;
    printf(" munmap : ptr : %p , size : %d \n " , ptr , size);
    munmap(ptr,size);	  
  }
  else
  {	  
    free_fragment(arena_list , header_ptr , get_fragment_index_address(ptr,header_ptr,arena_list->size));  
  }
  
  xmutex_unlock(arena_list->lock);
}

void*
xrealloc(void* prev, size_t bytes)
{
    // TODO: write an optimized realloc
    return 0;
}
