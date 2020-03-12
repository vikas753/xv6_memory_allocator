/*
#include "types.h"
#include "stat.h"
#include "user.h"
#include "param.h"
*/
#include "xmalloc.h"
#include <string.h>
#include <sys/mman.h>


#define EXIT_FAILURE 1

#define handle_error(msg) \
  do { perror(msg); exit(EXIT_FAILURE); } while (0)


// Memory allocator by Kernighan and Ritchie,
// The C programming Language, 2nd ed.  Section 8.7.
//
// Then copied from xv6.

// Custom api that allocates a page
// nn : size in bytes , based on which it would allocate
// number of required pages
// offset : Distance from start of page where the address
// need to be returned 
static char* mmap_palloc(int nn)
{
  char *addr = mmap(NULL,nn,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_SHARED,-1,0);
  if(addr == MAP_FAILED)
    handle_error("mmap_malloc");

  return addr;  
}

typedef long Align;

union header {
  struct {
    union header *ptr;
    uint size;
  } s;
  Align x;
};

typedef union header Header;

#define NUM_LOCKS 2

pthread_mutex_t lock_array[NUM_LOCKS];

#define MALLOC_LOCK_INDEX 0
#define FREE_LOCK_INDEX   1

// Flag to check for mutex init done or not . 
int isInitDone[NUM_LOCKS] = {0};

// Below api initialises a single mutex to protect
// all the memory related ops for xv6 OS as below . 
void xmutex_init(int lock_index)
{
  if(pthread_mutex_init(&lock_array[lock_index],NULL)!=0)
  {
    handle_error("pthread_mutex_init!");	  
  }	  
}

// Grabs the lock for xv6 memory operations
void xmutex_lock(int lock_index)
{

  // If flag is zero then initialise it and forget it :P
  // so that process exit can destroy it.  
  if(isInitDone[lock_index] == 0)
  {
	xmutex_init(lock_index);
    isInitDone[lock_index] = 1;	
  }
  
  if(pthread_mutex_lock(&lock_array[lock_index])!=0)
  {
    handle_error("pthread_mutex_lock!");	  
  }	  	
}

// Unlocks the mutex for xv6 memory operations
void xmutex_unlock(int lock_index)
{
  if(pthread_mutex_unlock(&lock_array[lock_index])!=0)
  {
    handle_error("pthread_mutex_unlock!");	  
  }	  	
}


// This is shared global data.
// You're going to want a mutex to protect this.
static Header base;
static Header *freep;

void
xfree(void *ap)
{
  
  Header *bp, *p;

  bp = (Header*)ap - 1;
  xmutex_lock(MALLOC_LOCK_INDEX);
  
  for(p = freep; !(bp > p && bp < p->s.ptr); p = p->s.ptr)
    if(p >= p->s.ptr && (bp > p || bp < p->s.ptr))
      break;
  if(bp + bp->s.size == p->s.ptr){
    bp->s.size += p->s.ptr->s.size;
    bp->s.ptr = p->s.ptr->s.ptr;
  } else
    bp->s.ptr = p->s.ptr;
  if(p + p->s.size == bp){
    p->s.size += bp->s.size;
    p->s.ptr = bp->s.ptr;
  } else
    p->s.ptr = bp;
  freep = p; 
  xmutex_unlock(MALLOC_LOCK_INDEX);	
} 

static Header*
morecore(uint nu)
{
  char *p;
  Header *hp;

  uint nbytes = nu * sizeof(Header);

  if(nbytes < 4096)
    nbytes = 4096;
  
  p = mmap_palloc(nbytes);

  hp = (Header*)p;
  hp->s.size = nu;
  xfree((void*)(hp + 1));	
  return freep;
}

void*
xmalloc(uint nbytes)
{
  xmutex_lock(MALLOC_LOCK_INDEX);	

  Header *p, *prevp;
  uint nunits;

  nunits = (nbytes + sizeof(Header) - 1)/sizeof(Header) + 1;

  if((prevp = freep) == 0)
  {
    base.s.ptr = freep = prevp = &base;
    base.s.size = 0;
  }
  for(p = prevp->s.ptr; ; prevp = p, p = p->s.ptr){
    if(p->s.size >= nunits){
      if(p->s.size == nunits)
        prevp->s.ptr = p->s.ptr;
      else {
        p->s.size -= nunits;
        p += p->s.size;
        p->s.size = nunits;
      }
      freep = prevp;
	  xmutex_unlock(MALLOC_LOCK_INDEX);
      return (void*)(p + 1);
    }
    if(p == freep)
    {
	  xmutex_unlock(MALLOC_LOCK_INDEX);
	  if((p = morecore(nunits)) == 0)
      {  
        
        return 0;
      }
	  xmutex_lock(MALLOC_LOCK_INDEX);
	}
  }	
}

void*
xrealloc(void* prev, size_t nn)
{
  Header *bp;

  bp = (Header*)prev - 1;

  // Allocate a buffer of that size , copy the contents of existing buffer
  // into that and return the pointer to the same
  void* allocPtr = (void*)xmalloc(nn);
  // Below math is just a reverse engineer of calculation of number of units
  // of buffer 
  size_t bufferSizeBytes = (bp->s.size - 1) * sizeof(Header);
  
  memcpy(allocPtr , prev , bufferSizeBytes);
  xfree((Header*)prev);
  prev = allocPtr;
  return prev;
}
