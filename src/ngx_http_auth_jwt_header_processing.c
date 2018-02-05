/*
 * Copyright (C) 2018 Tesla Government
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 *
 * https://github.com/TeslaGov/ngx-http-auth-jwt-module
 */

#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_auth_jwt_header_processing.h"

/**
 * Sample code from nginx.
 * https://www.nginx.com/resources/wiki/start/topics/examples/headers_management/?highlight=http%20settings
 */
ngx_table_elt_t* search_headers_in(ngx_http_request_t *r, u_char *name, size_t len)
{
	ngx_list_part_t            *part;
	ngx_table_elt_t            *h;
	ngx_uint_t                  i;

	// Get the first part of the list. There is usual only one part.
	part = &r->headers_in.headers.part;
	h = part->elts;

	// Headers list array may consist of more than one part, so loop through all of it
	for (i = 0; /* void */ ; i++)
	{
		if (i >= part->nelts)
		{
			if (part->next == NULL)
			{
				/* The last part, search is done. */
				break;
			}

			part = part->next;
			h = part->elts;
			i = 0;
		}

		//Just compare the lengths and then the names case insensitively.
		if (len != h[i].key.len || ngx_strcasecmp(name, h[i].key.data) != 0)
		{
			/* This header doesn't match. */
			continue;
		}

		/*
		* Ta-da, we got one!
		* Note, we've stopped the search at the first matched header
		* while more then one header may match.
		*/
		return &h[i];
	}

	/* No headers was found */
	return NULL;
}

/**
 * Sample code from nginx
 * https://www.nginx.com/resources/wiki/start/topics/examples/headers_management/#how-can-i-set-a-header
 */
ngx_int_t set_custom_header_in_headers_out(ngx_http_request_t *r, ngx_str_t *key, ngx_str_t *value) {
    ngx_table_elt_t   *h;

    /*
    All we have to do is just to allocate the header...
    */
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    /*
    ... setup the header key ...
    */
    h->key = *key;

    /*
    ... and the value.
    */
    h->value = *value;

    /*
    Mark the header as not deleted.
    */
    h->hash = 1;

    return NGX_OK;
}