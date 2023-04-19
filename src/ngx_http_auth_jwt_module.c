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

typedef struct
{
	ngx_str_t auth_jwt_loginurl;
	ngx_str_t auth_jwt_key;
	ngx_flag_t auth_jwt_enabled;
	ngx_flag_t auth_jwt_redirect;
	ngx_str_t auth_jwt_validation_type;
	ngx_str_t auth_jwt_algorithm;
	ngx_flag_t auth_jwt_validate_sub;
	ngx_array_t *auth_jwt_extract_request_claims;
	ngx_str_t auth_jwt_keyfile_path;
	ngx_flag_t auth_jwt_use_keyfile;
	ngx_str_t _auth_jwt_keyfile;
} ngx_http_auth_jwt_loc_conf_t;

static ngx_int_t ngx_http_auth_jwt_init(ngx_conf_t *cf);
static void *ngx_http_auth_jwt_create_conf(ngx_conf_t *cf);
static char *ngx_http_auth_jwt_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char *merge_extract_request_claims(ngx_conf_t *cf, ngx_command_t *cmd, void *c);
static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r);
static int validate_alg(ngx_http_auth_jwt_loc_conf_t *jwtcf, jwt_t *jwt);
static int validate_exp(ngx_http_auth_jwt_loc_conf_t *jwtcf, jwt_t *jwt);
static int validate_sub(ngx_http_auth_jwt_loc_conf_t *jwtcf, jwt_t *jwt);
static void extract_request_claims(ngx_http_request_t *r, ngx_http_auth_jwt_loc_conf_t *jwtcf, jwt_t *jwt);
static ngx_int_t free_jwt_and_redirect(ngx_http_request_t *r, ngx_http_auth_jwt_loc_conf_t *jwtcf, jwt_t *jwt);
static ngx_int_t redirect(ngx_http_request_t *r, ngx_http_auth_jwt_loc_conf_t *jwtcf);
static ngx_int_t load_public_key(ngx_conf_t *cf, ngx_http_auth_jwt_loc_conf_t *conf);
static char *get_jwt(ngx_http_request_t *r, ngx_str_t auth_jwt_validation_type);

static char *JWT_HEADER_PREFIX = "JWT-";

static ngx_command_t ngx_http_auth_jwt_commands[] = {
		{ngx_string("auth_jwt_loginurl"),
		 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		 ngx_conf_set_str_slot,
		 NGX_HTTP_LOC_CONF_OFFSET,
		 offsetof(ngx_http_auth_jwt_loc_conf_t, auth_jwt_loginurl),
		 NULL},

		{ngx_string("auth_jwt_key"),
		 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		 ngx_conf_set_str_slot,
		 NGX_HTTP_LOC_CONF_OFFSET,
		 offsetof(ngx_http_auth_jwt_loc_conf_t, auth_jwt_key),
		 NULL},

		{ngx_string("auth_jwt_enabled"),
		 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
		 ngx_conf_set_flag_slot,
		 NGX_HTTP_LOC_CONF_OFFSET,
		 offsetof(ngx_http_auth_jwt_loc_conf_t, auth_jwt_enabled),
		 NULL},

		{ngx_string("auth_jwt_redirect"),
		 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
		 ngx_conf_set_flag_slot,
		 NGX_HTTP_LOC_CONF_OFFSET,
		 offsetof(ngx_http_auth_jwt_loc_conf_t, auth_jwt_redirect),
		 NULL},

		{ngx_string("auth_jwt_validation_type"),
		 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		 ngx_conf_set_str_slot,
		 NGX_HTTP_LOC_CONF_OFFSET,
		 offsetof(ngx_http_auth_jwt_loc_conf_t, auth_jwt_validation_type),
		 NULL},

		{ngx_string("auth_jwt_algorithm"),
		 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		 ngx_conf_set_str_slot,
		 NGX_HTTP_LOC_CONF_OFFSET,
		 offsetof(ngx_http_auth_jwt_loc_conf_t, auth_jwt_algorithm),
		 NULL},

		{ngx_string("auth_jwt_validate_sub"),
		 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
		 ngx_conf_set_flag_slot,
		 NGX_HTTP_LOC_CONF_OFFSET,
		 offsetof(ngx_http_auth_jwt_loc_conf_t, auth_jwt_validate_sub),
		 NULL},

		{ngx_string("auth_jwt_extract_request_claims"),
		 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
		 merge_extract_request_claims,
		 NGX_HTTP_LOC_CONF_OFFSET,
		 offsetof(ngx_http_auth_jwt_loc_conf_t, auth_jwt_extract_request_claims),
		 NULL},

		{ngx_string("auth_jwt_keyfile_path"),
		 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		 ngx_conf_set_str_slot,
		 NGX_HTTP_LOC_CONF_OFFSET,
		 offsetof(ngx_http_auth_jwt_loc_conf_t, auth_jwt_keyfile_path),
		 NULL},

		{ngx_string("auth_jwt_use_keyfile"),
		 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
		 ngx_conf_set_flag_slot,
		 NGX_HTTP_LOC_CONF_OFFSET,
		 offsetof(ngx_http_auth_jwt_loc_conf_t, auth_jwt_use_keyfile),
		 NULL},

		ngx_null_command};

static ngx_http_module_t ngx_http_auth_jwt_module_ctx = {
		NULL,													 /* preconfiguration */
		ngx_http_auth_jwt_init,				 /* postconfiguration */
		NULL,													 /* create main configuration */
		NULL,													 /* init main configuration */
		NULL,													 /* create server configuration */
		NULL,													 /* merge server configuration */
		ngx_http_auth_jwt_create_conf, /* create location configuration */
		ngx_http_auth_jwt_merge_conf	 /* merge location configuration */
};

ngx_module_t ngx_http_auth_jwt_module = {
		NGX_MODULE_V1,
		&ngx_http_auth_jwt_module_ctx, /* module context */
		ngx_http_auth_jwt_commands,		 /* module directives */
		NGX_HTTP_MODULE,							 /* module type */
		NULL,													 /* init master */
		NULL,													 /* init module */
		NULL,													 /* init process */
		NULL,													 /* init thread */
		NULL,													 /* exit thread */
		NULL,													 /* exit process */
		NULL,													 /* exit master */
		NGX_MODULE_V1_PADDING};

static ngx_int_t ngx_http_auth_jwt_init(ngx_conf_t *cf)
{
	ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
	ngx_http_handler_pt *h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);

	if (h == NULL)
	{
		return NGX_ERROR;
	}
	else
	{
		*h = ngx_http_auth_jwt_handler;

		return NGX_OK;
	}
}

static void *ngx_http_auth_jwt_create_conf(ngx_conf_t *cf)
{
	ngx_http_auth_jwt_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_jwt_loc_conf_t));

	if (conf == NULL)
	{
		return NULL;
	}
	else
	{
		// ngx_str_t fields are initialized by the ngx_palloc call above -- only need to init flags and arrays here
		conf->auth_jwt_enabled = NGX_CONF_UNSET;
		conf->auth_jwt_redirect = NGX_CONF_UNSET;
		conf->auth_jwt_validate_sub = NGX_CONF_UNSET;
		conf->auth_jwt_redirect = NGX_CONF_UNSET;
		conf->auth_jwt_validate_sub = NGX_CONF_UNSET;
		conf->auth_jwt_extract_request_claims = NULL;
		conf->auth_jwt_use_keyfile = NGX_CONF_UNSET;

		return conf;
	}
}

static char *ngx_http_auth_jwt_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
	const ngx_http_auth_jwt_loc_conf_t *prev = parent;
	ngx_http_auth_jwt_loc_conf_t *conf = child;

	ngx_conf_merge_str_value(conf->auth_jwt_loginurl, prev->auth_jwt_loginurl, "");
	ngx_conf_merge_str_value(conf->auth_jwt_key, prev->auth_jwt_key, "");
	ngx_conf_merge_str_value(conf->auth_jwt_validation_type, prev->auth_jwt_validation_type, "");
	ngx_conf_merge_str_value(conf->auth_jwt_algorithm, prev->auth_jwt_algorithm, "HS256");
	ngx_conf_merge_str_value(conf->auth_jwt_keyfile_path, prev->auth_jwt_keyfile_path, "");
	ngx_conf_merge_off_value(conf->auth_jwt_validate_sub, prev->auth_jwt_validate_sub, 0);
	ngx_conf_merge_ptr_value(conf->auth_jwt_extract_request_claims, prev->auth_jwt_extract_request_claims, NULL);

	if (conf->auth_jwt_enabled == NGX_CONF_UNSET)
	{
		conf->auth_jwt_enabled = prev->auth_jwt_enabled == NGX_CONF_UNSET ? 0 : prev->auth_jwt_enabled;
	}

	if (conf->auth_jwt_redirect == NGX_CONF_UNSET)
	{
		conf->auth_jwt_redirect = prev->auth_jwt_redirect == NGX_CONF_UNSET ? 0 : prev->auth_jwt_redirect;
	}

	if (conf->auth_jwt_use_keyfile == NGX_CONF_UNSET)
	{
		conf->auth_jwt_use_keyfile = prev->auth_jwt_use_keyfile == NGX_CONF_UNSET ? 0 : prev->auth_jwt_use_keyfile;
	}

	// If the usage of the keyfile is specified, check if the key_path is also configured
	if (conf->auth_jwt_use_keyfile == 1)
	{
		if (ngx_strcmp(conf->auth_jwt_keyfile_path.data, "") != 0)
		{
			if (load_public_key(cf, conf) != NGX_OK)
			{
				return NGX_CONF_ERROR;
			}
		}
		else
		{
			ngx_log_error(NGX_LOG_ERR, cf->log, 0, "auth_jwt_keyfile_path not specified");

			return NGX_CONF_ERROR;
		}
	}

	return NGX_CONF_OK;
}

static char *merge_extract_request_claims(ngx_conf_t *cf, ngx_command_t *cmd, void *c)
{
	ngx_http_auth_jwt_loc_conf_t *conf = c;
	ngx_array_t *claims = conf->auth_jwt_extract_request_claims;
	ngx_str_t *values = cf->args->elts;

	if (claims == NULL)
	{
		claims = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
		conf->auth_jwt_extract_request_claims = claims;
	}

	// start at 1 because the first element is the directive (auth_jwt_extract_X_claims)
	for (ngx_uint_t i = 1; i < cf->args->nelts; i++)
	{
		ngx_str_t *element = ngx_array_push(claims);

		*element = values[i];
	}

	return NGX_CONF_OK;
}

static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r)
{
	ngx_http_auth_jwt_loc_conf_t *jwtcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_jwt_module);

	if (!jwtcf->auth_jwt_enabled)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_auth_jwt_handler -- disabled");
		return NGX_DECLINED;
	}
	else
	{
		// pass through options requests without token authentication
		if (r->method == NGX_HTTP_OPTIONS)
		{
			return NGX_DECLINED;
		}
		else
		{
			char *jwtPtr = get_jwt(r, jwtcf->auth_jwt_validation_type);

			if (jwtPtr == NULL)
			{
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to find a JWT");
				return redirect(r, jwtcf);
			}
			else
			{
				ngx_str_t auth_jwt_algorithm = jwtcf->auth_jwt_algorithm;
				int keyLength;
				u_char *key;
				jwt_t *jwt = NULL;

				if (auth_jwt_algorithm.len == 0 || (auth_jwt_algorithm.len == 5 && ngx_strncmp(auth_jwt_algorithm.data, "HS", 2) == 0))
				{
					keyLength = jwtcf->auth_jwt_key.len / 2;
					key = ngx_palloc(r->pool, keyLength);

					if (0 != hex_to_binary((char *)jwtcf->auth_jwt_key.data, key, jwtcf->auth_jwt_key.len))
					{
						ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to turn hex key into binary");
						return redirect(r, jwtcf);
					}
				}
				else if (auth_jwt_algorithm.len == 5 && ngx_strncmp(auth_jwt_algorithm.data, "RS", 2) == 0)
				{
					if (jwtcf->auth_jwt_use_keyfile == 1)
					{
						keyLength = jwtcf->_auth_jwt_keyfile.len;
						key = (u_char *)jwtcf->_auth_jwt_keyfile.data;
					}
					else
					{
						keyLength = jwtcf->auth_jwt_key.len;
						key = jwtcf->auth_jwt_key.data;
					}
				}
				else
				{
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "unsupported algorithm %s", auth_jwt_algorithm);
					return redirect(r, jwtcf);
				}

				if (jwt_decode(&jwt, jwtPtr, key, keyLength) != 0)
				{
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to parse JWT");
					return redirect(r, jwtcf);
				}

				if (validate_alg(jwtcf, jwt) != 0)
				{
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_auth_jwt_handler -- validate_alg failed");
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "invalid algorithm specified");
					return free_jwt_and_redirect(r, jwtcf, jwt);
				}
				else if (validate_exp(jwtcf, jwt) != 0)
				{
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_auth_jwt_handler -- validate_exp failed");
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "the JWT has expired");
					return free_jwt_and_redirect(r, jwtcf, jwt);
				}
				else if (validate_sub(jwtcf, jwt) != 0)
				{
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_auth_jwt_handler -- validate_sub failed");
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "the JWT does not contain a subject");
					return free_jwt_and_redirect(r, jwtcf, jwt);
				}
				else
				{
					extract_request_claims(r, jwtcf, jwt);
					jwt_free(jwt);

					return NGX_OK;
				}
			}
		}
	}
}

static int validate_alg(ngx_http_auth_jwt_loc_conf_t *jwtcf, jwt_t *jwt)
{
	const jwt_alg_t alg = jwt_get_alg(jwt);

	if (alg != JWT_ALG_HS256 && alg != JWT_ALG_HS384 && alg != JWT_ALG_HS512 && alg != JWT_ALG_RS256 && alg != JWT_ALG_RS384 && alg != JWT_ALG_RS512)
	{
		return 1;
	}

	return 0;
}

static int validate_exp(ngx_http_auth_jwt_loc_conf_t *jwtcf, jwt_t *jwt)
{
	const time_t exp = (time_t)jwt_get_grant_int(jwt, "exp");
	const time_t now = time(NULL);

	if (exp < now)
	{
		return 1;
	}

	return 0;
}

static int validate_sub(ngx_http_auth_jwt_loc_conf_t *jwtcf, jwt_t *jwt)
{
	if (jwtcf->auth_jwt_validate_sub == 1)
	{
		const char *sub = jwt_get_grant(jwt, "sub");

		if (sub == NULL)
		{
			return 1;
		}
	}

	return 0;
}

static void extract_request_claims(ngx_http_request_t *r, ngx_http_auth_jwt_loc_conf_t *jwtcf, jwt_t *jwt)
{
	if (jwtcf->auth_jwt_extract_request_claims != NULL && jwtcf->auth_jwt_extract_request_claims->nelts > 0)
	{
		const ngx_str_t *claims = jwtcf->auth_jwt_extract_request_claims->elts;

		for (uint i = 0; i < jwtcf->auth_jwt_extract_request_claims->nelts; i++)
		{
			const ngx_str_t claim = claims[i];
			const char *value = jwt_get_grant(jwt, (char *)claim.data);

			if (value != NULL && strlen(value) > 0)
			{
				ngx_uint_t claimHeaderLen = strlen(JWT_HEADER_PREFIX) + claim.len;
				ngx_str_t claimHeader = ngx_null_string;
				ngx_str_t claimValue = char_ptr_to_ngx_str_t(r->pool, value);

				claimHeader.data = ngx_palloc(r->pool, claimHeaderLen);
				claimHeader.len = claimHeaderLen;
				ngx_snprintf(claimHeader.data, claimHeaderLen, "%s%V", JWT_HEADER_PREFIX, &claim);

				set_request_header(r, &claimHeader, &claimValue);
			}
		}
	}
}

static ngx_int_t free_jwt_and_redirect(ngx_http_request_t *r, ngx_http_auth_jwt_loc_conf_t *jwtcf, jwt_t *jwt)
{
	if (jwt)
	{
		jwt_free(jwt);
	}

	return redirect(r, jwtcf);
}

static ngx_int_t redirect(ngx_http_request_t *r, ngx_http_auth_jwt_loc_conf_t *jwtcf)
{
	if (jwtcf->auth_jwt_redirect)
	{
		r->headers_out.location = ngx_list_push(&r->headers_out.headers);

		if (r->headers_out.location == NULL)
		{
			ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		}

		r->headers_out.location->hash = 1;
		r->headers_out.location->key.len = sizeof("Location") - 1;
		r->headers_out.location->key.data = (u_char *)"Location";

		if (r->method == NGX_HTTP_GET)
		{
			const int loginlen = jwtcf->auth_jwt_loginurl.len;
			const char *scheme = (r->connection->ssl) ? "https" : "http";
			const ngx_str_t server = r->headers_in.server;
			ngx_str_t uri_variable_name = ngx_string("request_uri");
			ngx_int_t uri_variable_hash = ngx_hash_key(uri_variable_name.data, uri_variable_name.len);
			ngx_http_variable_value_t *request_uri_var = ngx_http_get_variable(r, &uri_variable_name, uri_variable_hash);
			ngx_str_t uri;
			ngx_str_t uri_escaped;
			uintptr_t escaped_len;
			char *return_url;
			int return_url_idx;

			// get the URI
			if (request_uri_var && !request_uri_var->not_found && request_uri_var->valid)
			{
				// ideally we would like the URI with the querystring parameters
				uri.data = ngx_palloc(r->pool, request_uri_var->len);
				uri.len = request_uri_var->len;
				ngx_memcpy(uri.data, request_uri_var->data, request_uri_var->len);
			}
			else
			{
				// fallback to the querystring without params
				uri = r->uri;
			}

			// escape the URI
			escaped_len = 2 * ngx_escape_uri(NULL, uri.data, uri.len, NGX_ESCAPE_ARGS) + uri.len;
			uri_escaped.data = ngx_palloc(r->pool, escaped_len);
			uri_escaped.len = escaped_len;
			ngx_escape_uri(uri_escaped.data, uri.data, uri.len, NGX_ESCAPE_ARGS);

			r->headers_out.location->value.len = loginlen + sizeof("?return_url=") - 1 + strlen(scheme) + sizeof("://") - 1 + server.len + uri_escaped.len;

			return_url = ngx_palloc(r->pool, r->headers_out.location->value.len);
			ngx_memcpy(return_url, jwtcf->auth_jwt_loginurl.data, jwtcf->auth_jwt_loginurl.len);

			return_url_idx = jwtcf->auth_jwt_loginurl.len;
			ngx_memcpy(return_url + return_url_idx, "?return_url=", sizeof("?return_url=") - 1);

			return_url_idx += sizeof("?return_url=") - 1;
			ngx_memcpy(return_url + return_url_idx, scheme, strlen(scheme));

			return_url_idx += strlen(scheme);
			ngx_memcpy(return_url + return_url_idx, "://", sizeof("://") - 1);

			return_url_idx += sizeof("://") - 1;
			ngx_memcpy(return_url + return_url_idx, server.data, server.len);

			return_url_idx += server.len;
			ngx_memcpy(return_url + return_url_idx, uri_escaped.data, uri_escaped.len);

			r->headers_out.location->value.data = (u_char *)return_url;
		}
		else
		{
			// for non-get requests, redirect to the login page without a return URL
			r->headers_out.location->value.len = jwtcf->auth_jwt_loginurl.len;
			r->headers_out.location->value.data = jwtcf->auth_jwt_loginurl.data;
		}

		return NGX_HTTP_MOVED_TEMPORARILY;
	}

	// When no redirect is needed, no "Location" header construction is needed, and we can respond with a 401
	return NGX_HTTP_UNAUTHORIZED;
}

// Loads the public key into the location config struct
static ngx_int_t load_public_key(ngx_conf_t *cf, ngx_http_auth_jwt_loc_conf_t *conf)
{
	FILE *keyFile = fopen((const char *)conf->auth_jwt_keyfile_path.data, "rb");

	// Check if file exists or is correctly opened
	if (keyFile == NULL)
	{
		ngx_log_error(NGX_LOG_ERR, cf->log, 0, "failed to open public key file");
		return NGX_ERROR;
	}
	else
	{
		u_long keySize;
		u_long keySizeRead;

		// Read file length
		fseek(keyFile, 0, SEEK_END);
		keySize = ftell(keyFile);
		fseek(keyFile, 0, SEEK_SET);

		if (keySize == 0)
		{
			ngx_log_error(NGX_LOG_ERR, cf->log, 0, "invalid public key file size of 0");
			return NGX_ERROR;
		}
		else
		{
			conf->_auth_jwt_keyfile.data = ngx_palloc(cf->pool, keySize);
			keySizeRead = fread(conf->_auth_jwt_keyfile.data, 1, keySize, keyFile);
			fclose(keyFile);

			if (keySizeRead == keySize)
			{
				conf->_auth_jwt_keyfile.len = (int)keySize;

				return NGX_OK;
			}
			else
			{
				ngx_log_error(NGX_LOG_ERR, cf->log, 0, "public key size %i does not match expected size of %i", keySizeRead, keySize);
				return NGX_ERROR;
			}
		}
	}
}

static char *get_jwt(ngx_http_request_t *r, ngx_str_t auth_jwt_validation_type)
{
	char *jwtPtr = NULL;

	ngx_log_debug(NGX_LOG_DEBUG, r->connection->log, 0, "auth_jwt_validation_type.len %d", auth_jwt_validation_type.len);

	if (auth_jwt_validation_type.len == 0 || (auth_jwt_validation_type.len == sizeof("AUTHORIZATION") - 1 && ngx_strncmp(auth_jwt_validation_type.data, "AUTHORIZATION", sizeof("AUTHORIZATION") - 1) == 0))
	{
		static const ngx_str_t authorizationHeaderName = ngx_string("Authorization");
		const ngx_table_elt_t *authorizationHeader = search_headers_in(r, authorizationHeaderName.data, authorizationHeaderName.len);

		if (authorizationHeader != NULL)
		{
			ngx_int_t bearer_length = authorizationHeader->value.len - (sizeof("Bearer ") - 1);

			ngx_log_debug(NGX_LOG_DEBUG, r->connection->log, 0, "Found authorization header len %d", authorizationHeader->value.len);

			if (bearer_length > 0)
			{
				ngx_str_t authorizationHeaderStr;

				authorizationHeaderStr.data = authorizationHeader->value.data + sizeof("Bearer ") - 1;
				authorizationHeaderStr.len = bearer_length;

				jwtPtr = ngx_str_t_to_char_ptr(r->pool, authorizationHeaderStr);

				ngx_log_debug(NGX_LOG_DEBUG, r->connection->log, 0, "Authorization header: %s", jwtPtr);
			}
		}
	}
	else if (auth_jwt_validation_type.len > sizeof("COOKIE=") && ngx_strncmp(auth_jwt_validation_type.data, "COOKIE=", sizeof("COOKIE=") - 1) == 0)
	{
		ngx_int_t n;
		ngx_str_t jwtCookieVal;

		auth_jwt_validation_type.data += sizeof("COOKIE=") - 1;
		auth_jwt_validation_type.len -= sizeof("COOKIE=") - 1;

		n = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &auth_jwt_validation_type, &jwtCookieVal);

		if (n != NGX_DECLINED)
		{
			jwtPtr = ngx_str_t_to_char_ptr(r->pool, jwtCookieVal);
		}
	}

	return jwtPtr;
}
