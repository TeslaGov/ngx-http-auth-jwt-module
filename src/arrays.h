#ifndef _ARRAYS_H
#define _ARRAYS_H
#include <ngx_core.h>

void merge_array(ngx_pool_t *pool, ngx_array_t **dest, const ngx_array_t *src, size_t size);

#endif