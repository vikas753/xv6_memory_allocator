
#include "xmalloc.h"

#define EXIT_FAILURE 1

#define handle_error(msg) \
  do { perror(msg); exit(EXIT_FAILURE); } while (0)


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


void*
xmalloc(uint bytes)
{
    // TODO: write an optimized malloc
    return 0;
}

void
xfree(void* ptr)
{
    // TODO: write an optimized free
}

void*
xrealloc(void* prev, size_t bytes)
{
    // TODO: write an optimized realloc
    return 0;
}
