/*
 * Tesla Government
 * @author joefitz
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <jwt.h>

#include <jansson.h>

typedef struct {
	ngx_str_t   auth_jwt_loginurl;
	ngx_str_t   auth_jwt_key;
	ngx_flag_t  auth_jwt_enabled;
} ngx_http_auth_jwt_loc_conf_t;

static ngx_int_t ngx_http_auth_jwt_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r);
static void * ngx_http_auth_jwt_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_auth_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static int hex_char_to_binary( char ch, char* ret );
static int hex_to_binary( const char* str, u_char* buf, int len );
static char * ngx_str_t_to_char_ptr(ngx_pool_t *pool, ngx_str_t str);
static ngx_table_elt_t* search_headers_in(ngx_http_request_t *r, u_char *name, size_t len);

static ngx_command_t ngx_http_auth_jwt_commands[] = {

	{ ngx_string("auth_jwt_loginurl"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_jwt_loc_conf_t, auth_jwt_loginurl),
		NULL },

	{ ngx_string("auth_jwt_key"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_jwt_loc_conf_t, auth_jwt_key),
		NULL },

	{ ngx_string("auth_jwt_enabled"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_jwt_loc_conf_t, auth_jwt_enabled),
		NULL },

	ngx_null_command
};


static ngx_http_module_t ngx_http_auth_jwt_module_ctx = {
	NULL,                        /* preconfiguration */
	ngx_http_auth_jwt_init,      /* postconfiguration */

	NULL,                        /* create main configuration */
	NULL,                        /* init main configuration */

	NULL,                        /* create server configuration */
	NULL,                        /* merge server configuration */

	ngx_http_auth_jwt_create_loc_conf,      /* create location configuration */
	ngx_http_auth_jwt_merge_loc_conf       /* merge location configuration */
};


ngx_module_t ngx_http_auth_jwt_module = {
	NGX_MODULE_V1,
	&ngx_http_auth_jwt_module_ctx,     /* module context */
	ngx_http_auth_jwt_commands,        /* module directives */
	NGX_HTTP_MODULE,                   /* module type */
	NULL,                              /* init master */
	NULL,                              /* init module */
	NULL,                              /* init process */
	NULL,                              /* init thread */
	NULL,                              /* exit thread */
	NULL,                              /* exit process */
	NULL,                              /* exit master */
	NGX_MODULE_V1_PADDING
};


static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r)
{
	static const int BEARER_LEN = 7; // strlen("Bearer ");
	
	ngx_str_t jwtCookieName = ngx_string("rampartjwt");
	ngx_str_t passportKeyCookieName = ngx_string("PassportKey");
	ngx_str_t authorizationHeaderName = ngx_string("Authorization");
	ngx_int_t n;
	ngx_str_t jwtCookieVal;
	char* jwtCookieValChrPtr;
	char* return_url;
	ngx_http_auth_jwt_loc_conf_t *jwtcf;
	u_char *keyBinary;
	jwt_t *jwt;
	int jwtParseReturnCode;
	jwt_alg_t alg;
	time_t exp;
	time_t now;
	ngx_table_elt_t *authorizationHeader;
	
	jwtcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_jwt_module);
	
	if (!jwtcf->auth_jwt_enabled) 
	{
		return NGX_DECLINED;
	}
	
//	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Key: %s, Enabled: %d", 
//			jwtcf->auth_jwt_key.data, 
//			jwtcf->auth_jwt_enabled);

	// If request URI ends with "/rampart", it's a login page, so no JWT necessary.
	if (r->uri.data &&
		((r->uri.len >= 8 && !ngx_strncmp(r->uri.data + r->uri.len - 8, "/rampart", 8)) ||
		 (r->uri.len >= 9 && !ngx_strncmp(r->uri.data + r->uri.len - 9, "/rampart/", 9))))
	{
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Skipping JWT check for Rampart login page");
		return NGX_OK;
	}

	// get the cookie
	// TODO: the cookie name could be passed in dynamicallly
	n = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &jwtCookieName, &jwtCookieVal);
	if (n == NGX_DECLINED) 
	{
		// if we can't find the first cookie, check the legacy location
		n = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &passportKeyCookieName, &jwtCookieVal);
		if (n == NGX_DECLINED)
		{
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to find a jwt");
			goto redirect;
		}
	}
	
	// the cookie data is not necessarily null terminated... we need a null terminated character pointer
	jwtCookieValChrPtr = ngx_str_t_to_char_ptr(r->pool, jwtCookieVal);

//	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "rampartjwt: %s %d", jwtCookieValChrPtr, jwtCookieVal.len);
	
	// convert key from hex to binary
	keyBinary = ngx_palloc(r->pool, jwtcf->auth_jwt_key.len / 2);
	if (0 != hex_to_binary((char *)jwtcf->auth_jwt_key.data, keyBinary, jwtcf->auth_jwt_key.len))
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to turn hex key into binary");
		goto redirect;
	}
	
	// validate the jwt
	jwtParseReturnCode = jwt_decode(&jwt, jwtCookieValChrPtr, keyBinary, jwtcf->auth_jwt_key.len / 2);
	if (jwtParseReturnCode != 0)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to parse jwt");
		goto redirect;
	}
	
//	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "parsed jwt:\n%s", jwt_dump_str(jwt, 1));
	
	// validate the algorithm
	alg = jwt_get_alg(jwt);
	if (alg != JWT_ALG_HS256)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "invalid algorithm in jwt %d", alg);
		goto redirect;
	}
	
	// validate the exp date of the JWT
	exp = (time_t)jwt_get_grant_int(jwt, "exp");
	now = time(NULL);
	if (exp < now)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "the jwt has expired");
		goto redirect;
	}
	
	// if an Authorization header exists, it must match the cookie
	authorizationHeader = search_headers_in(r, authorizationHeaderName.data, authorizationHeaderName.len);
	if (authorizationHeader != NULL)
	{
		// compare lengths first
		if (authorizationHeader->value.len != jwtCookieVal.len + BEARER_LEN)
		{
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Authorization and Cookie do not match lengths");
			goto redirect;
		}

		// compare content
		if (0 != strncmp((const char *)(authorizationHeader->value.data + BEARER_LEN), (const char *)jwtCookieVal.data, jwtCookieVal.len)) 
		{
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Authorization and Cookie do not match content");
			goto redirect;
		}
	}

	return NGX_OK;
	
	redirect:
		r->headers_out.location = ngx_list_push(&r->headers_out.headers);
		
		if (r->headers_out.location == NULL) 
		{
			ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		}

		r->headers_out.location->hash = 1;
		r->headers_out.location->key.len = sizeof("Location") - 1;
		r->headers_out.location->key.data = (u_char *) "Location";

		if (r->method == NGX_HTTP_GET)
		{
			int loginlen;
			char * scheme;
			ngx_str_t server;
			ngx_str_t uri_variable_name = ngx_string("request_uri");
			ngx_int_t uri_variable_hash;
			ngx_http_variable_value_t * request_uri_var;
			ngx_str_t uri;
			ngx_str_t uri_escaped;
			uintptr_t escaped_len;

			loginlen = jwtcf->auth_jwt_loginurl.len;

			scheme = (r->connection->ssl) ? "https" : "http";
			server = r->headers_in.server;

			// get the URI
			uri_variable_hash = ngx_hash_key(uri_variable_name.data, uri_variable_name.len);
			request_uri_var = ngx_http_get_variable(r, &uri_variable_name, uri_variable_hash);

			// get the URI
			if(request_uri_var && !request_uri_var->not_found && request_uri_var->valid)
			{
				// ideally we would like the uri with the querystring parameters
				uri.data = ngx_palloc(r->pool, request_uri_var->len);
				uri.len = request_uri_var->len;
				ngx_memcpy(uri.data, request_uri_var->data, request_uri_var->len);

				// ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "found uri with querystring %s", ngx_str_t_to_char_ptr(r->pool, uri));
			}
			else
			{
				// fallback to the querystring without params
				uri = r->uri;

				// ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "fallback to querystring without params");
			}

			// escape the URI
			escaped_len = 2 * ngx_escape_uri(NULL, uri.data, uri.len, NGX_ESCAPE_ARGS) + uri.len;
			uri_escaped.data = ngx_palloc(r->pool, escaped_len);
			uri_escaped.len = escaped_len;
			ngx_escape_uri(uri_escaped.data, uri.data, uri.len, NGX_ESCAPE_ARGS);

			r->headers_out.location->value.len = loginlen + sizeof("?return_url=") - 1 + strlen(scheme) + sizeof("://") - 1 + server.len + uri_escaped.len;
			return_url = ngx_palloc(r->pool, r->headers_out.location->value.len);
			ngx_memcpy(return_url, jwtcf->auth_jwt_loginurl.data, jwtcf->auth_jwt_loginurl.len);
			int return_url_idx = jwtcf->auth_jwt_loginurl.len;
			ngx_memcpy(return_url+return_url_idx, "?return_url=", sizeof("?return_url=") - 1);
			return_url_idx += sizeof("?return_url=") - 1;
			ngx_memcpy(return_url+return_url_idx, scheme, strlen(scheme));
			return_url_idx += strlen(scheme);
			ngx_memcpy(return_url+return_url_idx, "://", sizeof("://") - 1);
			return_url_idx += sizeof("://") - 1;
			ngx_memcpy(return_url+return_url_idx, server.data, server.len);
			return_url_idx += server.len;
			ngx_memcpy(return_url+return_url_idx, uri_escaped.data, uri_escaped.len);
			return_url_idx += uri_escaped.len;
			r->headers_out.location->value.data = (u_char *)return_url;

			// ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "return_url: %s", ngx_str_t_to_char_ptr(r->pool, r->headers_out.location->value));
		}
		else
		{
			// for non-get requests, redirect to the login page without a return URL
			r->headers_out.location->value.len = jwtcf->auth_jwt_loginurl.len;
			r->headers_out.location->value.data = jwtcf->auth_jwt_loginurl.data;
		}

		return NGX_HTTP_MOVED_TEMPORARILY;
}


static ngx_int_t ngx_http_auth_jwt_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt        *h;
	ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (h == NULL) 
	{
		return NGX_ERROR;
	}

	*h = ngx_http_auth_jwt_handler;

	return NGX_OK;
}


static void *
ngx_http_auth_jwt_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_auth_jwt_loc_conf_t *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_jwt_loc_conf_t));
	if (conf == NULL) 
	{
		return NULL;
	}
	
	// set the flag to unset
	conf->auth_jwt_enabled = (ngx_flag_t) -1;

	ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "Created Location Configuration");
	
	return conf;
}


static char *
ngx_http_auth_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_auth_jwt_loc_conf_t *prev = parent;
	ngx_http_auth_jwt_loc_conf_t *conf = child;

	ngx_conf_merge_str_value(conf->auth_jwt_loginurl, prev->auth_jwt_loginurl, "");
	ngx_conf_merge_str_value(conf->auth_jwt_key, prev->auth_jwt_key, "");
	
	
	if (conf->auth_jwt_enabled == ((ngx_flag_t) -1)) 
	{
		conf->auth_jwt_enabled = (prev->auth_jwt_enabled == ((ngx_flag_t) -1)) ? 0 : prev->auth_jwt_enabled;
	}
	
	ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "Merged Location Configuration");

//	ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "Key: %s, Enabled: %d", 
//			conf->auth_jwt_key.data, 
//			conf->auth_jwt_enabled);
	return NGX_CONF_OK;
}

static int
hex_char_to_binary( char ch, char* ret )
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

static int
hex_to_binary( const char* str, u_char* buf, int len ) 
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

/** copies an nginx string structure to a newly allocated character pointer */
static char* ngx_str_t_to_char_ptr(ngx_pool_t *pool, ngx_str_t str)
{
	char* char_ptr = ngx_palloc(pool, str.len + 1);
	ngx_memcpy(char_ptr, str.data, str.len);
	*(char_ptr + str.len) = '\0';
	return char_ptr;
}

static ngx_table_elt_t* search_headers_in(ngx_http_request_t *r, u_char *name, size_t len)
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

