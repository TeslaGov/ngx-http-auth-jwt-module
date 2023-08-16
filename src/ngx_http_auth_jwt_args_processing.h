#ifndef _NGX_HTTP_AUTH_JWT_ARGS_PROCESSING_H
#define _NGX_HTTP_AUTH_JWT_ARGS_PROCESSING_H

#include <ngx_core.h>
#include <stdbool.h>

u_char *create_args_without_token(
    ngx_pool_t *pool,
    ngx_str_t *args,
    size_t token_key_start,
    size_t token_end,
    size_t *write_mutated_args_len
);

bool search_token_from_args(
    const ngx_str_t *jwt_location,
    const ngx_str_t *args,
    size_t *write_to_token_key_start,
    size_t *write_to_token_value_start,
    size_t *write_to_token_end
);

#endif /* _NGX_HTTP_AUTH_JWT_ARGS_PROCESSING_H */