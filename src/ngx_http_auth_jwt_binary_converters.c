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

int hex_char_to_binary(char ch, char *ret)
{
	ch = tolower(ch);

	if (isdigit(ch))
	{
		*ret = ch - '0';
	}
	else if (ch >= 'a' && ch <= 'f')
	{
		*ret = (ch - 'a') + 10;
	}
	else if (ch >= 'A' && ch <= 'F')
	{
		*ret = (ch - 'A') + 10;
	}
	else
	{
		return -1;
	}

	return 0;
}

int hex_to_binary(const char *str, u_char *buf, int len)
{
	int odd = len % 2;

	if (odd)
	{
		return -1;
	}
	else
	{
		u_char *cpy = buf;
		char low;
		char high;
		
		for (int i = 0; i < len; i += 2)
		{
			if (hex_char_to_binary(*(str + i), &high) != 0 || hex_char_to_binary(*(str + i + 1), &low) != 0)
			{
				return -2;
			}

			*cpy++ = low | (high << 4);
		}

		return 0;
	}
}