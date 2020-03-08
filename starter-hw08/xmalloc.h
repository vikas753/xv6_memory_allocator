#ifndef XMALLOC_H
#define XMALLOC_H

#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

void* xmalloc(uint bytes);
void  xfree(void* ptr);
void* xrealloc(void* prev, size_t bytes);

#endif
