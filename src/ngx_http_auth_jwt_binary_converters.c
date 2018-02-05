/*
 * Copyright (C) 2018 Tesla Government
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 *
 * https://github.com/TeslaGov/ngx-http-auth-jwt-module
 */

#include "ngx_http_auth_jwt_binary_converters.h"

#include <ngx_core.h>

int hex_char_to_binary( char ch, char* ret )
{
	ch = tolower( ch );
	if( isdigit( ch ) )
		*ret = ch - '0';
	else if( ch >= 'a' && ch <= 'f' )
		*ret = ( ch - 'a' ) + 10;
	else if( ch >= 'A' && ch <= 'F' )
		*ret = ( ch - 'A' ) + 10;
	else
		return *ret = 0;
	return 1;
}

int hex_to_binary( const char* str, u_char* buf, int len ) 
{
	u_char	
		*cpy = buf;
	char
		low,
		high;
	int
		odd = len % 2;
	
	if (odd) {
		return -1;
	}

	for (int i = 0; i < len; i += 2) {
		hex_char_to_binary( *(str + i), &high );
		hex_char_to_binary( *(str + i + 1 ), &low );
		
		*cpy++ = low | (high << 4);
	}
	return 0;
}