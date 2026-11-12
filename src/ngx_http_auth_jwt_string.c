/*
 * Copyright (C) 2018 Tesla Government
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 *
 * https://github.com/TeslaGov/ngx-http-auth-jwt-module
 */
#include <ngx_core.h>

#include "ngx_http_auth_jwt_string.h"

/** copies an nginx string structure to a newly allocated character pointer */
char* ngx_str_t_to_char_ptr(ngx_pool_t *pool, ngx_str_t str)
{
	char* char_ptr = ngx_palloc(pool, str.len + 1);

	if (char_ptr == NULL)
	{
		return NULL;
	}

	ngx_memcpy(char_ptr, str.data, str.len);

	*(char_ptr + str.len) = '\0';

	return char_ptr;
}

/** copies a character pointer string to an nginx string structure */
ngx_str_t char_ptr_to_ngx_str_t(ngx_pool_t *pool, const char* char_ptr)
{
	const int len = strlen(char_ptr);
	ngx_str_t str_t;

	// allocate len + 1 and NUL-terminate so str_t.data is safe to use with "%s"-style
	// formatting (e.g. ngx_log_debug), not just with its explicit .len
	str_t.data = ngx_palloc(pool, len + 1);

	if (str_t.data == NULL)
	{
		// return type can't signal failure with NULL, so fall back to a safe,
		// statically-allocated empty string rather than leaving data unset
		str_t.len = 0;
		str_t.data = (u_char *) "";

		return str_t;
	}

	str_t.len = len;
	ngx_memcpy(str_t.data, char_ptr, len);
	str_t.data[len] = '\0';

	return str_t;
}
