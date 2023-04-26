#include "arrays.h"
#include <ngx_core.h>

void merge_array(ngx_pool_t *pool, ngx_array_t **dest, const ngx_array_t *src, size_t size)
{
  // only merge if dest is non-null and src is null
  if (src != NULL && *dest == NULL)
  {
    *dest = ngx_array_create(pool, src->nelts, size);

    ngx_memcpy((*dest)->elts, src->elts, src->nelts * size);
    (*dest)->nelts = src->nelts;
  }
}
