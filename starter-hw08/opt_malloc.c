#include "stdio.h"
#include "xmalloc.h"
#include "sys/mman.h"
#include "string.h"
#include "pthread.h"

#include <sys/mman.h>

#define EXIT_FAILURE 1

#define handle_error(msg) \
  do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define NUM_OF_BUCKETS 20
#define NUM_LOCKS NUM_OF_BUCKETS

pthread_mutex_t lock_array[NUM_LOCKS] = { PTHREAD_MUTEX_INITIALIZER };


// Grabs the lock for xv6 memory operations
void xmutex_lock(int lock_index)
{
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

typedef long Align;

union header {
  struct {
    union header *ptr;
    uint size;
	uint size_bytes;
  } s;
  Align x;
};

typedef union header Header;

static Header base[NUM_OF_BUCKETS];
static Header *freep[NUM_OF_BUCKETS];
size_t bucket_size[NUM_OF_BUCKETS] = {5, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3193, 4097};

size_t mini(size_t x, size_t y)
{
  if(x > y)
    return y;
  else
  {
    return x;
  }
}

size_t find_size(size_t nunits)
{
    int i;

    for(i = 0; i < NUM_OF_BUCKETS; i++)
    {
      if(bucket_size[i] >= nunits)
      {
        return i;
      }
    }
    return NUM_OF_BUCKETS + 1;
}

void append_free_list(void* ap, size_t bucket_num)
{
    Header *bp, *p;

    //printf("free\n");
    bp = (Header*)ap - 1;
    pthread_mutex_lock(&lock_array[bucket_num]);
  
    for(p = freep[bucket_num]; !(bp > p && bp < p->s.ptr); p = p->s.ptr)
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

    freep[bucket_num] = p;

    pthread_mutex_unlock(&lock_array[bucket_num]);
}

void
xfree(void *ap)
{
  size_t bucket_num;
  Header *bp = (Header*)ap - 1;
  bucket_num = find_size((bp->s.size-1)*sizeof(header));
  append_free_list(ap, bucket_num);
}

static Header*
morecore(uint nu, size_t bucket_num)
{
  char *p;
  Header *hp;

  if(nu < 4096)
    nu = 4096;
  
  p = mmap(0, nu * sizeof(Header), (PROT_EXEC | PROT_READ | PROT_WRITE), MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  
  if(p == (char*)-1)
  {
    return 0;
  }
  hp = (Header*)p;
  hp->s.size = nu;
  append_free_list((void*)(hp + 1), bucket_num);
  return freep[bucket_num];
}

void*
xmalloc(uint nbytes)
{
  Header *p, *prevp;
  size_t nunits, bucket_num;

  
  nunits = (nbytes + sizeof(Header) - 1)/sizeof(Header) + 1;
  bucket_num = find_size(nunits);
  pthread_mutex_lock(&lock_array[bucket_num]);
  if((prevp = freep[bucket_num]) == 0){
    base[bucket_num].s.ptr = freep[bucket_num] = prevp = &base[bucket_num];
    base[bucket_num].s.size = 0;
  }
  
  for(p = prevp->s.ptr; ; prevp = p, p = p->s.ptr)
  {
    if(p->s.size >= bucket_size[bucket_num]){
      if(p->s.size == bucket_size[bucket_num])
        prevp->s.ptr = p->s.ptr;
      else {
        p->s.size -= bucket_size[bucket_num];
        p += p->s.size;
        p->s.size = bucket_size[bucket_num];
      }
      freep[bucket_num] = prevp;
      pthread_mutex_unlock(&lock_array[bucket_num]);
      return (void*)(p + 1);
    }
    if(p == freep[bucket_num])
    {
      pthread_mutex_unlock(&lock_array[bucket_num]);
      if((p = morecore(nunits, bucket_num)) == 0)
      {
        return 0;
      }
      pthread_mutex_lock(&lock_array[bucket_num]);
    }
  }   
}

void*
xrealloc(void* prev, size_t nn)
{
  //Header *prevp, *p;
  Header *new_p, *old_p;
  size_t old_size, bucket_num;

  //printf("realloc\n");
  //prevp = freep;
  new_p = xmalloc(nn);
  old_p = (Header*)prev;
  old_size = ((old_p - 1)->s.size) - 1;
  old_size *= sizeof(Header);
  old_size += 1;
  old_size -= sizeof(Header);
  memcpy(new_p, old_p, mini(old_size, nn));
  bucket_num = find_size((old_p - 1)->s.size);
  append_free_list((Header*)old_p, bucket_num);

  return new_p;
}
