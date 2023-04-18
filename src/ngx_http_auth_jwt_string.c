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
	ngx_memcpy(char_ptr, str.data, str.len);

	*(char_ptr + str.len) = '\0';

	return char_ptr;
}

/** copies a character pointer string to an nginx string structure */
ngx_str_t char_ptr_to_ngx_str_t(ngx_pool_t *pool, const char* char_ptr)
{
	const int len = strlen(char_ptr);
	ngx_str_t str_t;

	str_t.len = len;
	str_t.data = ngx_palloc(pool, len);

	ngx_memcpy(str_t.data, char_ptr, len);

	return str_t;
}

/** extracts an element from an ngx_array_t variable */
char *get_ngx_array_element(ngx_pool_t *pool, ngx_array_t *arr, uint index) {
	if (arr == NULL || index >= arr->nelts) {
		return NULL;
	}
	else {
		char *elementPtr = ((char *) arr->elts) + (arr->size * index);
		char *data = ngx_palloc(pool, arr->size);
		
		ngx_memcpy(data, elementPtr, arr->size);

		return data;
	}
}