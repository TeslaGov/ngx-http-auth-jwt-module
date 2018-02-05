/*
 * Copyright (C) 2018 Tesla Government
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 *
 * https://github.com/TeslaGov/ngx-http-auth-jwt-module
 */

#ifndef _NGX_HTTP_AUTH_JWT_STRING_H
#define _NGX_HTTP_AUTH_JWT_STRING_H

#include <ngx_core.h>

char* ngx_str_t_to_char_ptr(ngx_pool_t *pool, ngx_str_t str);
ngx_str_t ngx_char_ptr_to_str_t(ngx_pool_t *pool, char* char_ptr);

#endif /* _NGX_HTTP_AUTH_JWT_STRING_H */