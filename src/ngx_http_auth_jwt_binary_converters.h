/*
 * Copyright (C) 2018 Tesla Government
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 *
 * https://github.com/TeslaGov/ngx-http-auth-jwt-module
 */

#ifndef _NGX_HTTP_AUTH_JWT_BINARY_CONVERTERS_H
#define _NGX_HTTP_AUTH_JWT_BINARY_CONVERTERS_H

#include <ngx_core.h>

int hex_char_to_binary( char ch, char* ret );
int hex_to_binary( const char* str, u_char* buf, int len );

#endif /* _NGX_HTTP_AUTH_JWT_BINARY_CONVERTERS_H */