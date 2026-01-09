#include "ngx_http_auth_jwt_args_processing.h"

/* Creates a new version of args without token present.
 *  Writes length of new args to `*write_args_len`.
 */
u_char *create_args_without_token(
    ngx_pool_t *pool,
    ngx_str_t *args,
    size_t token_key_start,
    size_t token_end,
    size_t *write_args_len
) {
  *write_args_len = args->len - token_end + token_key_start;
  u_char *args_ptr = ngx_palloc(pool, *write_args_len);
  
  if (args_ptr == NULL)
  {
    return NULL;
  }
  else
  {
    if (token_key_start > 0) {
      ngx_memcpy(args_ptr, args->data, token_key_start);
    }
    if (token_end < (args->len - 1)) {
      ngx_memcpy(
        args_ptr + token_key_start,
        args->data + token_end,
        *write_args_len - token_key_start
      );
    }
  
    return args_ptr;
  }
}

/* Tries to extract token from query string. Returns true if found, false otherwise.
     
  Searches for the string contained in *jwt_location in *args. If it finds the token
  in question it writes the location of the start of key to *write_to_token_key_start, 
  start of token itself to *write_to_token_value_start and end of token to *write_to_token_end.
*/
bool search_token_from_args(
    const ngx_str_t *jwt_location,
    const ngx_str_t *args,
    size_t *write_to_token_key_start,
    size_t *write_to_token_value_start,
    size_t *write_to_token_end
) {
  size_t i = 0, j = 0;
  size_t max_i = args->len > jwt_location->len ? args->len - jwt_location->len : 0;

  while (i < max_i) 
  {
    j = 0;
    if (i == 0 || *(args->data + i - 1) == '&')
    {
      while (j < jwt_location->len && *(args->data + i + j) == *(jwt_location->data + j))
      {
        if (j == (jwt_location->len - 1))
        {
          *write_to_token_key_start = i;
          i++;
          if (i >= max_i || *(args->data + i + j) != '=')
          {
            // key doesn't match
            break;
          }
          *write_to_token_value_start = i + j + 1;
          while (i < args->len && *(args->data + i) != '&')
          {
            i++;
          }
          *write_to_token_end = i;
          return true;
        }
        j++;
      }
    }
    i++;
  }
  return false;
}
