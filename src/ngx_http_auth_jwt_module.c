/*
 * Copyright (C) 2018 Tesla Government
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 *
 * https://github.com/TeslaGov/ngx-http-auth-jwt-module
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <jwt.h>

#include <jansson.h>

#include "ngx_http_auth_jwt_header_processing.h"
#include "ngx_http_auth_jwt_binary_converters.h"
#include "ngx_http_auth_jwt_string.h"

#include <stdio.h>

typedef struct {
	ngx_str_t    auth_jwt_loginurl;
	ngx_str_t    auth_jwt_key;
	ngx_flag_t   auth_jwt_enabled;
	ngx_flag_t   auth_jwt_redirect;
	ngx_str_t    auth_jwt_validation_type;
	ngx_str_t    auth_jwt_algorithm;
	ngx_flag_t   auth_jwt_validate_email;
	ngx_str_t    auth_jwt_keyfile_path;
	ngx_flag_t   auth_jwt_use_keyfile;
	// Private field for keyfile data
	ngx_str_t    _auth_jwt_keyfile;
} ngx_http_auth_jwt_loc_conf_t;

static ngx_int_t ngx_http_auth_jwt_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r);
static void * ngx_http_auth_jwt_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_auth_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char * getJwt(ngx_http_request_t *r, ngx_str_t auth_jwt_validation_type);

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

	{ ngx_string("auth_jwt_redirect"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_jwt_loc_conf_t, auth_jwt_redirect),
		NULL },

	{ ngx_string("auth_jwt_validation_type"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_jwt_loc_conf_t, auth_jwt_validation_type),
		NULL },

	{ ngx_string("auth_jwt_algorithm"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_jwt_loc_conf_t, auth_jwt_algorithm),
		NULL },

	{ ngx_string("auth_jwt_validate_email"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_jwt_loc_conf_t, auth_jwt_validate_email),
		NULL },

	{ ngx_string("auth_jwt_keyfile_path"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_jwt_loc_conf_t, auth_jwt_keyfile_path),
		NULL },

	{ ngx_string("auth_jwt_use_keyfile"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_jwt_loc_conf_t, auth_jwt_use_keyfile),
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
	ngx_str_t useridHeaderName = ngx_string("x-userid");
	ngx_str_t emailHeaderName = ngx_string("x-email");
	char* jwtCookieValChrPtr;
	char* return_url;
	ngx_http_auth_jwt_loc_conf_t *jwtcf;
	u_char *keyBinary;
	// For clearing it later on
	jwt_t *jwt = NULL;
	int jwtParseReturnCode;
	jwt_alg_t alg;
	const char* sub;
	const char* email;
	ngx_str_t sub_t;
	ngx_str_t email_t;
	time_t exp;
	time_t now;
	ngx_str_t auth_jwt_algorithm;
	int keylen;
	
	jwtcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_jwt_module);
	
	if (!jwtcf->auth_jwt_enabled) 
	{
		return NGX_DECLINED;
	}

	// pass through options requests without token authentication
	if (r->method == NGX_HTTP_OPTIONS)
	{
		return NGX_DECLINED;
	}
	
	jwtCookieValChrPtr = getJwt(r, jwtcf->auth_jwt_validation_type);
	if (jwtCookieValChrPtr == NULL)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to find a jwt");
		goto redirect;
	}
	
	// convert key from hex to binary, if a symmetric key

	auth_jwt_algorithm = jwtcf->auth_jwt_algorithm;
	if (auth_jwt_algorithm.len == 0 || (auth_jwt_algorithm.len == sizeof("HS256") - 1 && ngx_strncmp(auth_jwt_algorithm.data, "HS256", sizeof("HS256") - 1)==0))
	{
		keylen = jwtcf->auth_jwt_key.len / 2;
		keyBinary = ngx_palloc(r->pool, keylen);
		if (0 != hex_to_binary((char *)jwtcf->auth_jwt_key.data, keyBinary, jwtcf->auth_jwt_key.len))
		{
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to turn hex key into binary");
			goto redirect;
		}
	}
	else if ( auth_jwt_algorithm.len == sizeof("RS256") - 1 && ngx_strncmp(auth_jwt_algorithm.data, "RS256", sizeof("RS256") - 1) == 0 )
	{
		// in this case, 'Binary' is a misnomer, as it is the public key string itself
		if (jwtcf->auth_jwt_use_keyfile == 1)
		{
			// Set to global variables
			// NOTE: check for keyBin == NULL skipped, unnecessary check; nginx should fail to start
			keyBinary = (u_char*)jwtcf->_auth_jwt_keyfile.data;
			keylen = jwtcf->_auth_jwt_keyfile.len;
		}
		else
		{
			keyBinary = jwtcf->auth_jwt_key.data;
			keylen = jwtcf->auth_jwt_key.len;
		}
	}
	else
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "unsupported algorithm");
		goto redirect;
	}
	
	// validate the jwt
	jwtParseReturnCode = jwt_decode(&jwt, jwtCookieValChrPtr, keyBinary, keylen);
	if (jwtParseReturnCode != 0)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to parse jwt");
		goto redirect;
	}
	
	// validate the algorithm
	alg = jwt_get_alg(jwt);
	if (alg != JWT_ALG_HS256 && alg != JWT_ALG_RS256)
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

	// extract the userid
	sub = jwt_get_grant(jwt, "sub");
	if (sub == NULL)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "the jwt does not contain a subject");
	}
	else
	{
		sub_t = ngx_char_ptr_to_str_t(r->pool, (char *)sub);
		set_custom_header_in_headers_out(r, &useridHeaderName, &sub_t);
	}

	if (jwtcf->auth_jwt_validate_email == 1)
	{
		email = jwt_get_grant(jwt, "emailAddress");
		if (email == NULL)
		{
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "the jwt does not contain an email address");
		}
		else
		{
			email_t = ngx_char_ptr_to_str_t(r->pool, (char *)email);
			set_custom_header_in_headers_out(r, &emailHeaderName, &email_t);
		}
	}

	jwt_free(jwt);

	
	return NGX_OK;
	
	redirect:

		if (jwt)
		{
			jwt_free(jwt);
		}

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

		if (jwtcf->auth_jwt_redirect)
		{
			return NGX_HTTP_MOVED_TEMPORARILY;
		}
		else
		{
			return NGX_HTTP_UNAUTHORIZED;
		}
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
	conf->auth_jwt_redirect = (ngx_flag_t) -1;
	conf->auth_jwt_validate_email = (ngx_flag_t) -1;
	conf->auth_jwt_use_keyfile = (ngx_flag_t) -1;

	ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "Created Location Configuration");
	
	return conf;
}

// Loads the RSA256 public key into the location config struct
static ngx_int_t
loadAuthKey(ngx_conf_t *cf, ngx_http_auth_jwt_loc_conf_t* conf) {
	FILE *keyFile = fopen((const char*)conf->auth_jwt_keyfile_path.data, "rb");

	// Check if file exists or is correctly opened
	if (keyFile == NULL)
	{
		ngx_log_error(NGX_LOG_ERR, cf->log, 0, "failed to open pub key file");
		return NGX_ERROR;
	}

	// Read file length
	fseek(keyFile, 0, SEEK_END);
	long keySize = ftell(keyFile);
	fseek(keyFile, 0, SEEK_SET);
	
	if (keySize == 0)
	{
		ngx_log_error(NGX_LOG_ERR, cf->log, 0, "invalid key file size, check the key file");
		return NGX_ERROR;
	}

	conf->_auth_jwt_keyfile.data = ngx_palloc(cf->pool, keySize);
	fread(conf->_auth_jwt_keyfile.data, 1, keySize, keyFile);
	conf->_auth_jwt_keyfile.len = (int)keySize;

	fclose(keyFile);
	return NGX_OK;
}

static char *
ngx_http_auth_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_auth_jwt_loc_conf_t *prev = parent;
	ngx_http_auth_jwt_loc_conf_t *conf = child;

	ngx_conf_merge_str_value(conf->auth_jwt_loginurl, prev->auth_jwt_loginurl, "");
	ngx_conf_merge_str_value(conf->auth_jwt_key, prev->auth_jwt_key, "");
	ngx_conf_merge_str_value(conf->auth_jwt_validation_type, prev->auth_jwt_validation_type, "");
	ngx_conf_merge_str_value(conf->auth_jwt_algorithm, prev->auth_jwt_algorithm, "HS256");
	ngx_conf_merge_str_value(conf->auth_jwt_keyfile_path, prev->auth_jwt_keyfile_path, "");
	ngx_conf_merge_off_value(conf->auth_jwt_validate_email, prev->auth_jwt_validate_email, 1);
	
	if (conf->auth_jwt_enabled == ((ngx_flag_t) -1)) 
	{
		conf->auth_jwt_enabled = (prev->auth_jwt_enabled == ((ngx_flag_t) -1)) ? 0 : prev->auth_jwt_enabled;
	}

	if (conf->auth_jwt_redirect == ((ngx_flag_t) -1))
	{
		conf->auth_jwt_redirect = (prev->auth_jwt_redirect == ((ngx_flag_t) -1)) ? 0 : prev->auth_jwt_redirect;
	}

	if (conf->auth_jwt_use_keyfile == ((ngx_flag_t) -1))
	{
		conf->auth_jwt_use_keyfile = (prev->auth_jwt_use_keyfile == ((ngx_flag_t) -1)) ? 0 : prev->auth_jwt_use_keyfile;
	}

	// If the usage of the keyfile is specified, check if the key_path is also configured
	if (conf->auth_jwt_use_keyfile == 1)
	{
		if (ngx_strcmp(conf->auth_jwt_keyfile_path.data, "") != 0)
		{
			if (loadAuthKey(cf, conf) != NGX_OK)
				return NGX_CONF_ERROR;
		}
		else
		{
			ngx_log_error(NGX_LOG_ERR, cf->log, 0, "auth_jwt_keyfile_path not specified");
			return NGX_CONF_ERROR;
		}
	}

	return NGX_CONF_OK;
}

static char * getJwt(ngx_http_request_t *r, ngx_str_t auth_jwt_validation_type)
{
	static const ngx_str_t authorizationHeaderName = ngx_string("Authorization");
	ngx_table_elt_t *authorizationHeader;
	char* jwtCookieValChrPtr = NULL;
	ngx_str_t jwtCookieVal;
	ngx_int_t n;
	ngx_int_t bearer_length;
	ngx_str_t authorizationHeaderStr;

	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "auth_jwt_validation_type.len %d", auth_jwt_validation_type.len);

	if (auth_jwt_validation_type.len == 0 || (auth_jwt_validation_type.len == sizeof("AUTHORIZATION") - 1 && ngx_strncmp(auth_jwt_validation_type.data, "AUTHORIZATION", sizeof("AUTHORIZATION") - 1)==0))
	{
		// using authorization header
		authorizationHeader = search_headers_in(r, authorizationHeaderName.data, authorizationHeaderName.len);
		if (authorizationHeader != NULL)
		{
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Found authorization header len %d", authorizationHeader->value.len);

			bearer_length = authorizationHeader->value.len - (sizeof("Bearer ") - 1);

			if (bearer_length > 0) 
			{
				authorizationHeaderStr.data = authorizationHeader->value.data + sizeof("Bearer ") - 1;
				authorizationHeaderStr.len = bearer_length;

				jwtCookieValChrPtr = ngx_str_t_to_char_ptr(r->pool, authorizationHeaderStr);

				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Authorization header: %s", jwtCookieValChrPtr);
			}
		}
	}
	else if (auth_jwt_validation_type.len > sizeof("COOKIE=") && ngx_strncmp(auth_jwt_validation_type.data, "COOKIE=", sizeof("COOKIE=") - 1)==0)
	{
		auth_jwt_validation_type.data += sizeof("COOKIE=") - 1;
		auth_jwt_validation_type.len -= sizeof("COOKIE=") - 1;

		// get the cookie
		// TODO: the cookie name could be passed in dynamicallly
		n = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &auth_jwt_validation_type, &jwtCookieVal);
		if (n != NGX_DECLINED) 
		{
			jwtCookieValChrPtr = ngx_str_t_to_char_ptr(r->pool, jwtCookieVal);
		}
	}

	return jwtCookieValChrPtr;
}




