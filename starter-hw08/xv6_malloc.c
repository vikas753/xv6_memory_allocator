/*
#include "types.h"
#include "stat.h"
#include "user.h"
#include "param.h"
*/
#include "xmalloc.h"
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
static char* mmap_palloc(int nn,int offset)
{
  char *addr = mmap(NULL,nn,PROT_WRITE,MAP_ANONYMOUS,-1,offset);
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

pthread_mutex_t malloc_lock; 

// Flag to check for mutex init done or not . 
int isInitDone = 0;

// Below api initialises a single mutex to protect
// all the memory related ops for xv6 OS as below . 
void xmutex_init()
{
  if(pthread_mutex_init(&malloc_lock,NULL)!=0)
  {
    handle_error("pthread_mutex_init!");	  
  }	  
}

// Grabs the lock for xv6 memory operations
void xmutex_lock()
{

  // If flag is zero then initialise it and forget it :P
  // so that process exit can destroy it.  
  if(isInitDone == 0)
  {
    xmutex_init();
    isInitDone = 1;	
  }
  
  if(pthread_mutex_lock(&malloc_lock)!=0)
  {
    handle_error("pthread_mutex_lock!");	  
  }	  	
}

// Unlocks the mutex for xv6 memory operations
void xmutex_unlock()
{
  if(pthread_mutex_unlock(&malloc_lock)!=0)
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
  xmutex_lock();	
  Header *bp, *p;

  bp = (Header*)ap - 1;
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
  xmutex_unlock();	
} 

static Header*
morecore(uint nu)
{
  xmutex_lock();	
  char *p;
  Header *hp;

  if(nu < 4096)
    nu = 4096;
  
  p = mmap_palloc(nu*sizeof(Header),0);

  if(p == (char*)-1)
    return 0;
  hp = (Header*)p;
  hp->s.size = nu;
  xfree((void*)(hp + 1));
  xmutex_unlock();	
  return freep;
}

void*
xmalloc(uint nbytes)
{
  xmutex_lock();	

  Header *p, *prevp;
  uint nunits;

  nunits = (nbytes + sizeof(Header) - 1)/sizeof(Header) + 1;
  if((prevp = freep) == 0){
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
      return (void*)(p + 1);
    }
    if(p == freep)
      if((p = morecore(nunits)) == 0)
        return 0;
  }
  xmutex_unlock();	
 
}

void*
xrealloc(void* prev, size_t nn)
{
  // TODO: Actually build realloc.
  return prev;
}
