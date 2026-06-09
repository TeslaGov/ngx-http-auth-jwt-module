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

#include "arrays.h"
#include "ngx_http_auth_jwt_header_processing.h"
#include "ngx_http_auth_jwt_binary_converters.h"
#include "ngx_http_auth_jwt_string.h"

#include <stdio.h>
#include <stdbool.h>

// Structure to hold a parsed JWK key
typedef struct {
  ngx_str_t kid;       // Key ID
  ngx_str_t kty;       // Key type (oct, RSA, EC)
  ngx_str_t alg;       // Algorithm
  ngx_str_t k;         // Symmetric key (for oct)
  ngx_str_t n;         // RSA modulus
  ngx_str_t e;         // RSA exponent
  ngx_str_t pem_key;   // Converted PEM key for RSA/EC
} auth_jwt_key_t;

// Structure to hold multiple JWK keys
typedef struct {
  auth_jwt_key_t *keys;
  ngx_uint_t nkeys;
} auth_jwt_jwks_t;

typedef struct
{
  ngx_str_t loginurl;
  ngx_str_t key;
  ngx_http_complex_value_t *enabled;
  ngx_flag_t redirect;
  ngx_str_t jwt_location;
  ngx_str_t algorithm;
  ngx_flag_t validate_sub;
  ngx_array_t *extract_var_claims;
  ngx_array_t *extract_request_claims;
  ngx_array_t *extract_response_claims;
  ngx_str_t keyfile_path;
  ngx_flag_t use_keyfile;
  ngx_str_t _keyfile;
  ngx_str_t key_file;  // Path to JWK/JWKS file
  ngx_flag_t key_file_missing_skip;  // Skip auth if key file is missing (on/off), default: off
  ngx_int_t key_file_missing_error;  // HTTP error code when file not found (only used if skip is off)
  ngx_str_t key_file_missing_message;  // Optional error message when file not found
  ngx_str_t key_file_missing_content_type;  // Optional content-type for error response
  auth_jwt_jwks_t *jwks;  // Parsed JWKS
} auth_jwt_conf_t;

typedef struct
{
  ngx_int_t validation_status;
  ngx_array_t *claim_values;
} auth_jwt_ctx_t;

static ngx_int_t init(ngx_conf_t *cf);
static void *create_conf(ngx_conf_t *cf);
static char *merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char *merge_extract_var_claims(ngx_conf_t *cf, ngx_command_t *cmd, void *c);
static ngx_int_t get_jwt_var_claim(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static char *merge_extract_request_claims(ngx_conf_t *cf, ngx_command_t *cmd, void *c);
static char *merge_extract_response_claims(ngx_conf_t *cf, ngx_command_t *cmd, void *c);
static auth_jwt_ctx_t *get_or_init_jwt_module_ctx(ngx_http_request_t *r, auth_jwt_conf_t *jwtcf);
static auth_jwt_ctx_t *get_request_jwt_ctx(ngx_http_request_t *r);
static ngx_int_t handle_request(ngx_http_request_t *r);
static int validate_alg(auth_jwt_conf_t *jwtcf, jwt_t *jwt);
static int validate_exp(auth_jwt_conf_t *jwtcf, jwt_t *jwt);
static int validate_sub(auth_jwt_conf_t *jwtcf, jwt_t *jwt);
static ngx_int_t extract_var_claims(ngx_http_request_t *r, auth_jwt_conf_t *jwtcf, jwt_t *jwt, auth_jwt_ctx_t *ctx);
static void extract_request_claims(ngx_http_request_t *r, auth_jwt_conf_t *jwtcf, jwt_t *jwt);
static void extract_response_claims(ngx_http_request_t *r, auth_jwt_conf_t *jwtcf, jwt_t *jwt);
static ngx_int_t redirect(ngx_http_request_t *r, auth_jwt_conf_t *jwtcf);
static ngx_int_t load_public_key(ngx_conf_t *cf, auth_jwt_conf_t *conf);
static ngx_int_t load_jwk_file(ngx_conf_t *cf, auth_jwt_conf_t *conf);
static auth_jwt_key_t *find_jwk_key(auth_jwt_conf_t *jwtcf, const char *kid);
static char *get_jwt(ngx_http_request_t *r, ngx_str_t jwt_location);
static ngx_int_t base64url_decode(ngx_pool_t *pool, ngx_str_t *src, ngx_str_t *dst);
static char *set_key_file_missing_error(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static const char *JWT_HEADER_PREFIX = "JWT-";

static ngx_command_t auth_jwt_directives[] = {
    {ngx_string("auth_jwt_loginurl"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(auth_jwt_conf_t, loginurl),
     NULL},

    {ngx_string("auth_jwt_key"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(auth_jwt_conf_t, key),
     NULL},

    {ngx_string("auth_jwt_enabled"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_http_set_complex_value_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(auth_jwt_conf_t, enabled),
     NULL},

    {ngx_string("auth_jwt_redirect"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(auth_jwt_conf_t, redirect),
     NULL},

    {ngx_string("auth_jwt_location"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(auth_jwt_conf_t, jwt_location),
     NULL},

    {ngx_string("auth_jwt_algorithm"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(auth_jwt_conf_t, algorithm),
     NULL},

    {ngx_string("auth_jwt_validate_sub"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(auth_jwt_conf_t, validate_sub),
     NULL},

    {ngx_string("auth_jwt_extract_var_claims"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
     merge_extract_var_claims,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(auth_jwt_conf_t, extract_var_claims),
     NULL},

    {ngx_string("auth_jwt_extract_request_claims"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
     merge_extract_request_claims,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(auth_jwt_conf_t, extract_request_claims),
     NULL},

    {ngx_string("auth_jwt_extract_response_claims"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
     merge_extract_response_claims,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(auth_jwt_conf_t, extract_response_claims),
     NULL},

    {ngx_string("auth_jwt_keyfile_path"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(auth_jwt_conf_t, keyfile_path),
     NULL},

    {ngx_string("auth_jwt_use_keyfile"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(auth_jwt_conf_t, use_keyfile),
     NULL},

    {ngx_string("auth_jwt_key_file"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(auth_jwt_conf_t, key_file),
     NULL},

    {ngx_string("auth_jwt_key_file_missing_skip"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(auth_jwt_conf_t, key_file_missing_skip),
     NULL},

    {ngx_string("auth_jwt_key_file_missing_error"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE123,
     set_key_file_missing_error,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},

    ngx_null_command};

static ngx_http_module_t auth_jwt_context = {
    NULL,        /* preconfiguration */
    init,        /* postconfiguration */
    NULL,        /* create main configuration */
    NULL,        /* init main configuration */
    NULL,        /* create server configuration */
    NULL,        /* merge server configuration */
    create_conf, /* create location configuration */
    merge_conf   /* merge location configuration */
};

ngx_module_t ngx_http_auth_jwt_module = {
    NGX_MODULE_V1,
    &auth_jwt_context,   /* module context */
    auth_jwt_directives, /* module directives */
    NGX_HTTP_MODULE,     /* module type */
    NULL,                /* init master */
    NULL,                /* init module */
    NULL,                /* init process */
    NULL,                /* init thread */
    NULL,                /* exit thread */
    NULL,                /* exit process */
    NULL,                /* exit master */
    NGX_MODULE_V1_PADDING};

static ngx_int_t init(ngx_conf_t *cf)
{
  ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
  ngx_http_handler_pt *h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);

  if (h == NULL)
  {
    return NGX_ERROR;
  }
  else
  {
    *h = handle_request;

    return NGX_OK;
  }
}

static void *create_conf(ngx_conf_t *cf)
{
  auth_jwt_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(auth_jwt_conf_t));

  if (conf == NULL)
  {
    return NULL;
  }
  else
  {
    // ngx_str_t fields are initialized by the ngx_palloc call above -- only need to init flags and arrays here
    conf->enabled = NULL;
    conf->redirect = NGX_CONF_UNSET;
    conf->validate_sub = NGX_CONF_UNSET;
    conf->extract_var_claims = NULL;
    conf->extract_request_claims = NULL;
    conf->extract_response_claims = NULL;
    conf->use_keyfile = NGX_CONF_UNSET;
    conf->jwks = NULL;
    conf->key_file_missing_skip = NGX_CONF_UNSET;
    conf->key_file_missing_error = NGX_CONF_UNSET;

    return conf;
  }
}

static char *merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
  const auth_jwt_conf_t *prev = parent;
  auth_jwt_conf_t *conf = child;

  ngx_conf_merge_str_value(conf->loginurl, prev->loginurl, "");
  ngx_conf_merge_str_value(conf->key, prev->key, "");
  ngx_conf_merge_str_value(conf->jwt_location, prev->jwt_location, "HEADER=Authorization");
  ngx_conf_merge_str_value(conf->algorithm, prev->algorithm, "HS256");
  ngx_conf_merge_str_value(conf->keyfile_path, prev->keyfile_path, "");
  ngx_conf_merge_off_value(conf->validate_sub, prev->validate_sub, 0);
  merge_array(cf->pool, &conf->extract_var_claims, prev->extract_var_claims, sizeof(ngx_str_t));
  merge_array(cf->pool, &conf->extract_request_claims, prev->extract_request_claims, sizeof(ngx_str_t));
  merge_array(cf->pool, &conf->extract_response_claims, prev->extract_response_claims, sizeof(ngx_str_t));

  if (conf->enabled == NULL) {
    conf->enabled = prev->enabled;
  }

  ngx_conf_merge_off_value(conf->redirect, prev->redirect, 0);
  ngx_conf_merge_off_value(conf->use_keyfile, prev->use_keyfile, 0);
  ngx_conf_merge_str_value(conf->key_file, prev->key_file, "");
  ngx_conf_merge_off_value(conf->key_file_missing_skip, prev->key_file_missing_skip, 0);  // Default: off (don't skip)
  ngx_conf_merge_value(conf->key_file_missing_error, prev->key_file_missing_error, NGX_HTTP_UNAUTHORIZED);  // Default: 401
  ngx_conf_merge_str_value(conf->key_file_missing_message, prev->key_file_missing_message, "");
  ngx_conf_merge_str_value(conf->key_file_missing_content_type, prev->key_file_missing_content_type, "");

  // Inherit JWKS from parent if not set
  if (conf->jwks == NULL) {
    conf->jwks = prev->jwks;
  }

  // If the usage of the keyfile is specified, check if the key_path is also configured
  if (conf->use_keyfile == 1)
  {
    if (conf->keyfile_path.len > 0)
    {
      if (load_public_key(cf, conf) != NGX_OK)
      {
        return NGX_CONF_ERROR;
      }
    }
    else
    {
      ngx_log_error(NGX_LOG_ERR, cf->log, 0, "keyfile_path not specified");

      return NGX_CONF_ERROR;
    }
  }

  // If auth_jwt_key_file is specified, try to load and parse the JWK/JWKS file
  if (conf->key_file.len > 0 && conf->jwks == NULL)
  {
    ngx_int_t rc = load_jwk_file(cf, conf);
    if (rc != NGX_OK)
    {
      // File not loaded - log warning, will handle at runtime based on key_file_missing_skip
      if (conf->key_file_missing_skip == 1)
      {
        ngx_log_error(NGX_LOG_WARN, cf->log, 0, "JWK file not loaded, will skip auth at runtime per auth_jwt_key_file_missing_skip=on");
      }
      else
      {
        ngx_log_error(NGX_LOG_WARN, cf->log, 0, "JWK file not loaded, will return %d at runtime per auth_jwt_key_file_missing_error", conf->key_file_missing_error);
      }
    }
  }

  return NGX_CONF_OK;
}

static char *merge_extract_var_claims(ngx_conf_t *cf, ngx_command_t *cmd, void *c)
{
  auth_jwt_conf_t *conf = c;
  ngx_array_t *claims = conf->extract_var_claims;

  if (claims == NULL)
  {
    claims = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
    conf->extract_var_claims = claims;
  }

  ngx_str_t *values = cf->args->elts;

  // start at 1 because the first element is the directive (auth_jwt_extract_var_claims)
  for (ngx_uint_t i = 1; i < cf->args->nelts; ++i)
  {
    // add this claim's name to the config struct
    ngx_str_t *element = ngx_array_push(claims);

    if (element == NULL)
    {
      return NGX_CONF_ERROR;
    }

    *element = values[i];

    // add an http variable for this claim
    size_t var_name_len = 10 + element->len;
    u_char *buf = ngx_palloc(cf->pool, sizeof(u_char) * var_name_len);

    if (buf == NULL)
    {
      return NGX_CONF_ERROR;
    }
    else
    {
      ngx_sprintf(buf, "jwt_claim_%V", element);
      ngx_str_t *var_name = ngx_palloc(cf->pool, sizeof(ngx_str_t));

      if (var_name == NULL)
      {
        return NGX_CONF_ERROR;
      }
      else
      {
        var_name->data = buf;
        var_name->len = var_name_len;

        // NGX_HTTP_VAR_CHANGEABLE simplifies the required logic by assuming a JWT claim will always be the same for a given request
        ngx_http_variable_t *http_var = ngx_http_add_variable(cf, var_name, NGX_HTTP_VAR_CHANGEABLE);

        if (http_var == NULL)
        {
          ngx_log_error(NGX_LOG_ERR, cf->log, 0, "failed to add variable %V", var_name);

          return NGX_CONF_ERROR;
        }
        else
        {
          http_var->get_handler = get_jwt_var_claim;

          // store the index of this new claim in the claims array as the "data" that will be passed to the getter
          ngx_uint_t *claim_idx = ngx_palloc(cf->pool, sizeof(ngx_uint_t));

          if (claim_idx == NULL)
          {
            return NGX_CONF_ERROR;
          }
          else
          {
            *claim_idx = claims->nelts - 1;
            http_var->data = (uintptr_t)claim_idx;
          }
        }
      }
    }
  }

  return NGX_CONF_OK;
}

static ngx_int_t get_jwt_var_claim(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
  ngx_uint_t *claim_idx = (ngx_uint_t *)data;
  auth_jwt_ctx_t *ctx = get_request_jwt_ctx(r);

  ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "getting jwt var claim for var at index %l", *claim_idx);

  if (ctx == NULL || ctx->validation_status != NGX_OK)
  {
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "no module context found while getting jwt value");

    return NGX_ERROR;
  }
  else if (ctx->claim_values == NULL || ctx->claim_values->nelts == 0 ||
           *claim_idx >= ctx->claim_values->nelts)
  {
    // No claims extracted (e.g., auth_jwt_key_file_missing_skip=on with no key file)
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "no claims available for jwt var");

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 1;
    v->len = 0;
    v->data = NULL;

    return NGX_OK;
  }
  else
  {
    ngx_str_t claim_value = ((ngx_str_t *)ctx->claim_values->elts)[*claim_idx];

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = claim_value.len;
    v->data = claim_value.data;

    return NGX_OK;
  }
}

static char *merge_extract_claims(ngx_conf_t *cf, ngx_array_t *claims)
{
  ngx_str_t *values = cf->args->elts;

  // start at 1 because the first element is the directive (auth_jwt_extract_X_claims)
  for (ngx_uint_t i = 1; i < cf->args->nelts; ++i)
  {
    ngx_str_t *element = ngx_array_push(claims);

    if (element == NULL)
    {
      return NGX_CONF_ERROR;
    }

    *element = values[i];
  }

  return NGX_CONF_OK;
}

static char *merge_extract_request_claims(ngx_conf_t *cf, ngx_command_t *cmd, void *c)
{
  auth_jwt_conf_t *conf = c;
  ngx_array_t *claims = conf->extract_request_claims;

  if (claims == NULL)
  {
    claims = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
    conf->extract_request_claims = claims;
  }

  return merge_extract_claims(cf, claims);
}

static char *merge_extract_response_claims(ngx_conf_t *cf, ngx_command_t *cmd, void *c)
{
  auth_jwt_conf_t *conf = c;
  ngx_array_t *claims = conf->extract_response_claims;

  if (claims == NULL)
  {
    claims = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
    conf->extract_response_claims = claims;
  }

  return merge_extract_claims(cf, claims);
}

static auth_jwt_ctx_t *get_or_init_jwt_module_ctx(ngx_http_request_t *r, auth_jwt_conf_t *jwtcf)
{
  auth_jwt_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_auth_jwt_module);

  if (ctx != NULL)
  {
    return ctx;
  }
  else
  {
    ctx = ngx_pcalloc(r->pool, sizeof(auth_jwt_ctx_t));

    if (ctx == NULL)
    {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "error allocating jwt module context");
      return ctx;
    }
    else
    {
      if (jwtcf->extract_var_claims != NULL)
      {
        ctx->claim_values = ngx_array_create(r->pool, jwtcf->extract_var_claims->nelts, sizeof(ngx_str_t));

        if (ctx->claim_values == NULL)
        {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "error initializing jwt module context");
          return NULL;
        }
      }

      ctx->validation_status = NGX_AGAIN;
      ngx_http_set_ctx(r, ctx, ngx_http_auth_jwt_module);

      return ctx;
    }
  }
}

// this creates the module's context struct and extracts claim vars the first time it is called,
// either from the access-phase handler or an http var getter
static auth_jwt_ctx_t *get_request_jwt_ctx(ngx_http_request_t *r)
{
  auth_jwt_conf_t *jwtcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_jwt_module);
  ngx_int_t enabled = 1;

  if (jwtcf->enabled != NULL) {
    ngx_str_t cv;
    if (ngx_http_complex_value(r, jwtcf->enabled, &cv) == NGX_OK && cv.len > 0) {
      if (ngx_strncmp(cv.data, "off", 3) == 0) {
        enabled = 0;
      }
    }
  }

  if (!enabled) {
    return NULL;
  }
  else {
    auth_jwt_ctx_t *ctx = get_or_init_jwt_module_ctx(r, jwtcf);

    if (ctx == NULL) {
      return NULL;
    }
    else if (ctx->validation_status != NGX_AGAIN)
    {
      // we already validated and extacted everything we care about, so we just return the already-complete context
      return ctx;
    }
    else {
      // Check if key_file was specified but not loaded (handle at runtime)
      if (jwtcf->key_file.len > 0 && (jwtcf->jwks == NULL || jwtcf->jwks->nkeys == 0))
      {
        // Key file is missing at runtime
        if (jwtcf->key_file_missing_skip == 1)
        {
          // Skip authentication
          ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWK file not available, skipping auth per auth_jwt_key_file_missing_skip=on");
          ctx->validation_status = NGX_OK;
          return ctx;
        }
        else
        {
          // Return error code specified by auth_jwt_key_file_missing_error
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWK file not available, returning %d per auth_jwt_key_file_missing_error", jwtcf->key_file_missing_error);
          ctx->validation_status = jwtcf->key_file_missing_error;
          return ctx;
        }
      }

      char *jwtPtr = get_jwt(r, jwtcf->jwt_location);

      if (jwtPtr == NULL)
      {
        // JWT is required - deny request
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to find a JWT");
        ctx->validation_status = NGX_ERROR;

        return ctx;
      }
      else
      {
        ngx_str_t algorithm = jwtcf->algorithm;
        int keyLength;
        u_char *key;
        jwt_t *jwt = NULL;

        // Check if we have JWK keys available
        if (jwtcf->jwks != NULL && jwtcf->jwks->nkeys > 0)
        {
          // Use key from JWK file
          // First, try to find key by kid from JWT header (if present)
          // For now, use the first key or match by algorithm
          auth_jwt_key_t *jwk_key = find_jwk_key(jwtcf, NULL);

          if (jwk_key == NULL)
          {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no suitable key found in JWK file");
            ctx->validation_status = NGX_ERROR;
            return ctx;
          }

          if (jwk_key->kty.len == 3 && ngx_strncmp(jwk_key->kty.data, "oct", 3) == 0)
          {
            // Symmetric key - decode from base64url
            ngx_str_t decoded_key;
            if (base64url_decode(r->pool, &jwk_key->k, &decoded_key) != NGX_OK)
            {
              ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to decode JWK symmetric key");
              ctx->validation_status = NGX_ERROR;
              return ctx;
            }
            keyLength = decoded_key.len;
            key = decoded_key.data;
          }
          else if (jwk_key->kty.len == 3 && ngx_strncmp(jwk_key->kty.data, "RSA", 3) == 0)
          {
            // RSA key - use PEM key if stored, otherwise error
            if (jwk_key->pem_key.len > 0)
            {
              keyLength = jwk_key->pem_key.len;
              key = jwk_key->pem_key.data;
            }
            else
            {
              ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "RSA JWK key requires PEM conversion (not yet supported). Use auth_jwt_keyfile_path for RSA keys.");
              ctx->validation_status = NGX_ERROR;
              return ctx;
            }
          }
          else if (jwk_key->kty.len == 2 && ngx_strncmp(jwk_key->kty.data, "EC", 2) == 0)
          {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "EC JWK key requires PEM conversion (not yet supported). Use auth_jwt_keyfile_path for EC keys.");
            ctx->validation_status = NGX_ERROR;
            return ctx;
          }
          else
          {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "unsupported JWK key type: %V", &jwk_key->kty);
            ctx->validation_status = NGX_ERROR;
            return ctx;
          }
        }
        else if (algorithm.len == 0 || (algorithm.len == 5 && ngx_strncmp(algorithm.data, "HS", 2) == 0))
        {
          keyLength = jwtcf->key.len / 2;
          key = ngx_palloc(r->pool, keyLength);

          if (key == NULL)
          {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to allocate memory for key");
            ctx->validation_status = NGX_ERROR;
            return ctx;
          }

          if (0 != hex_to_binary((char *)jwtcf->key.data, key, jwtcf->key.len))
          {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to turn hex key into binary");
            ctx->validation_status = NGX_ERROR;

            return ctx;
          }
        }
        else if (algorithm.len == 5 && (ngx_strncmp(algorithm.data, "RS", 2) == 0 || ngx_strncmp(algorithm.data, "ES", 2) == 0))
        {
          if (jwtcf->use_keyfile == 1)
          {
            keyLength = jwtcf->_keyfile.len;
            key = (u_char *)jwtcf->_keyfile.data;
          }
          else
          {
            keyLength = jwtcf->key.len;
            key = jwtcf->key.data;
          }
        }
        else
        {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "unsupported algorithm %s", algorithm);
          ctx->validation_status = NGX_ERROR;

          return ctx;
        }

        if (jwt_decode(&jwt, jwtPtr, key, keyLength) != 0 || !jwt)
        {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to parse JWT");
          ctx->validation_status = NGX_ERROR;
        }
        else if (validate_alg(jwtcf, jwt) != 0)
        {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "invalid algorithm specified");
          ctx->validation_status = NGX_ERROR;
        }
        else if (validate_exp(jwtcf, jwt) != 0)
        {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "the JWT has expired");
          ctx->validation_status = NGX_ERROR;
        }
        else if (validate_sub(jwtcf, jwt) != 0)
        {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "the JWT does not contain a subject");
          ctx->validation_status = NGX_ERROR;
        }
        else
        {
          extract_request_claims(r, jwtcf, jwt);
          extract_response_claims(r, jwtcf, jwt);
          ctx->validation_status = extract_var_claims(r, jwtcf, jwt, ctx);
        }

        jwt_free(jwt);

        return ctx;
      }
    }
  }
}

static ngx_int_t handle_request(ngx_http_request_t *r)
{
  auth_jwt_conf_t *jwtcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_jwt_module);

  // Only activate JWT logic if key, keyfile_path, or key_file is set
  if (jwtcf->key.len == 0 && jwtcf->keyfile_path.len == 0 && jwtcf->key_file.len == 0) {
    return NGX_DECLINED;
  }

  auth_jwt_ctx_t *ctx = get_request_jwt_ctx(r);

  ngx_int_t enabled = 1;
  if (jwtcf->enabled != NULL) {
    ngx_str_t cv;
    if (ngx_http_complex_value(r, jwtcf->enabled, &cv) == NGX_OK && cv.len > 0) {
      if (ngx_strncmp(cv.data, "off", 3) == 0) {
        enabled = 0;
      }
    }
  }
  if (!enabled)
  {
    return NGX_DECLINED;
  }
  else if (r->method == NGX_HTTP_OPTIONS) // pass through options requests without token authentication
  {
    return NGX_DECLINED;
  }
  else if (!ctx)
  {
    return NGX_ERROR;
  }
  else if (ctx->validation_status == NGX_ERROR)
  {
    return redirect(r, jwtcf);
  }
  else if (ctx->validation_status >= 301 && ctx->validation_status <= 308 &&
           ctx->validation_status != 304 && ctx->validation_status != 305 && ctx->validation_status != 306)
  {
    // 3xx redirect status code (301, 302, 303, 307, 308)
    ngx_str_t redirect_url;

    // Use custom URL if provided, otherwise use auth_jwt_loginurl
    if (jwtcf->key_file_missing_message.len > 0)
    {
      redirect_url = jwtcf->key_file_missing_message;
    }
    else if (jwtcf->loginurl.len > 0)
    {
      redirect_url = jwtcf->loginurl;
    }
    else
    {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        "auth_jwt_key_file_missing_error: redirect requested but no URL provided");
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.location = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.location == NULL)
    {
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.location->hash = 1;
    ngx_str_set(&r->headers_out.location->key, "Location");
    r->headers_out.location->value = redirect_url;

    return ctx->validation_status;
  }
  else if (ctx->validation_status >= 400 && ctx->validation_status < 600)
  {
    // HTTP error status code - check if we have a custom message to send
    if (jwtcf->key_file_missing_message.len > 0)
    {
      // Send custom error response with message and optional content-type
      ngx_buf_t *b;
      ngx_chain_t out;

      r->headers_out.status = ctx->validation_status;

      // Set content type if specified
      if (jwtcf->key_file_missing_content_type.len > 0)
      {
        r->headers_out.content_type = jwtcf->key_file_missing_content_type;
      }
      else
      {
        ngx_str_set(&r->headers_out.content_type, "text/plain");
      }
      r->headers_out.content_type_lowcase = NULL;
      r->headers_out.content_length_n = jwtcf->key_file_missing_message.len;

      ngx_http_send_header(r);

      b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
      if (b == NULL)
      {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
      }

      b->pos = jwtcf->key_file_missing_message.data;
      b->last = jwtcf->key_file_missing_message.data + jwtcf->key_file_missing_message.len;
      b->memory = 1;
      b->last_buf = 1;

      out.buf = b;
      out.next = NULL;

      return ngx_http_output_filter(r, &out);
    }
    return ctx->validation_status;
  }
  else
  {
    return ctx->validation_status;
  }
}

static int validate_alg(auth_jwt_conf_t *jwtcf, jwt_t *jwt)
{
  const jwt_alg_t alg = jwt_get_alg(jwt);

  if (alg != JWT_ALG_HS256 && alg != JWT_ALG_HS384 && alg != JWT_ALG_HS512 && alg != JWT_ALG_RS256 && alg != JWT_ALG_RS384 && alg != JWT_ALG_RS512 && alg != JWT_ALG_ES256 && alg != JWT_ALG_ES384 && alg != JWT_ALG_ES512)
  {
    return 1;
  }

  return 0;
}

static int validate_exp(auth_jwt_conf_t *jwtcf, jwt_t *jwt)
{
  const time_t exp = (time_t)jwt_get_grant_int(jwt, "exp");
  const time_t now = time(NULL);

  if (exp < now)
  {
    return 1;
  }

  return 0;
}

static int validate_sub(auth_jwt_conf_t *jwtcf, jwt_t *jwt)
{
  if (jwtcf->validate_sub == 1)
  {
    const char *sub = jwt_get_grant(jwt, "sub");

    if (sub == NULL)
    {
      return 1;
    }
  }

  return 0;
}

static ngx_int_t extract_var_claims(ngx_http_request_t *r, auth_jwt_conf_t *jwtcf, jwt_t *jwt, auth_jwt_ctx_t *ctx)
{
  ngx_array_t *claims = jwtcf->extract_var_claims;

  if (claims == NULL || claims->nelts == 0)
  {
    return NGX_OK;
  }
  else
  {
    const ngx_str_t *claimsPtr = claims->elts;

    for (ngx_uint_t i = 0; i < claims->nelts; ++i)
    {
      const ngx_str_t claim = claimsPtr[i];

      // Create null-terminated claim name for jwt_get_grant
      u_char *claim_name = ngx_pnalloc(r->pool, claim.len + 1);
      if (claim_name == NULL)
      {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to allocate memory for claim name");
        return NGX_ERROR;
      }
      ngx_memcpy(claim_name, claim.data, claim.len);
      claim_name[claim.len] = '\0';

      const char *claimValue = jwt_get_grant(jwt, (char *)claim_name);
      ngx_str_t value = ngx_string("");

      if (claimValue != NULL && strlen(claimValue) > 0)
      {
        value = char_ptr_to_ngx_str_t(r->pool, claimValue);
      }

      // Use ngx_array_push to properly track the number of elements
      ngx_str_t *element = ngx_array_push(ctx->claim_values);
      if (element == NULL)
      {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to push claim value to array");
        return NGX_ERROR;
      }
      *element = value;
      ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "set var %V to JWT claim value %s", &claim, value.data);
    }

    return NGX_OK;
  }
}

static void extract_claims(ngx_http_request_t *r, jwt_t *jwt, ngx_array_t *claims, ngx_int_t (*set_header)(ngx_http_request_t *r, ngx_str_t *key, ngx_str_t *value))
{
  if (claims != NULL && claims->nelts > 0)
  {
    const ngx_str_t *claimsPtr = claims->elts;

    for (ngx_uint_t i = 0; i < claims->nelts; ++i)
    {
      const ngx_str_t claim = claimsPtr[i];

      // Create null-terminated claim name for jwt_get_grant
      u_char *claim_name = ngx_pnalloc(r->pool, claim.len + 1);
      if (claim_name == NULL)
      {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to allocate memory for claim name");
        return;
      }
      ngx_memcpy(claim_name, claim.data, claim.len);
      claim_name[claim.len] = '\0';

      const char *value = jwt_get_grant(jwt, (char *)claim_name);

      if (value != NULL && strlen(value) > 0)
      {
        ngx_uint_t claimHeaderLen = strlen(JWT_HEADER_PREFIX) + claim.len;
        ngx_str_t claimHeader = ngx_null_string;
        ngx_str_t claimValue = char_ptr_to_ngx_str_t(r->pool, value);

        claimHeader.data = ngx_palloc(r->pool, claimHeaderLen);
        if (claimHeader.data == NULL)
        {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to allocate memory for claim header");
          return;
        }
        claimHeader.len = claimHeaderLen;
        ngx_snprintf(claimHeader.data, claimHeaderLen, "%s%V", JWT_HEADER_PREFIX, &claim);

        set_header(r, &claimHeader, &claimValue);
      }
    }
  }
}

static void extract_request_claims(ngx_http_request_t *r, auth_jwt_conf_t *jwtcf, jwt_t *jwt)
{
  extract_claims(r, jwt, jwtcf->extract_request_claims, set_request_header);
}

static void extract_response_claims(ngx_http_request_t *r, auth_jwt_conf_t *jwtcf, jwt_t *jwt)
{
  extract_claims(r, jwt, jwtcf->extract_response_claims, set_response_header);
}

static ngx_int_t redirect(ngx_http_request_t *r, auth_jwt_conf_t *jwtcf)
{
  if (jwtcf->redirect)
  {
    r->headers_out.location = ngx_list_push(&r->headers_out.headers);

    if (r->headers_out.location == NULL)
    {
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.location->hash = 1;
    r->headers_out.location->key.len = strlen("Location");
    r->headers_out.location->key.data = (u_char *)"Location";

    if (r->method == NGX_HTTP_GET)
    {
      const int loginlen = jwtcf->loginurl.len;
      const char *scheme = r->connection->ssl ? "https" : "http";
      ngx_str_t port_variable_name = ngx_string("server_port");
      ngx_int_t port_variable_hash = ngx_hash_key(port_variable_name.data, port_variable_name.len);
      ngx_http_variable_value_t *port_var = ngx_http_get_variable(r, &port_variable_name, port_variable_hash);
      char *port_str = "";
      ngx_uint_t port_str_len = 0;
      const ngx_str_t server = r->headers_in.server;
      ngx_str_t uri_variable_name = ngx_string("request_uri");
      ngx_int_t uri_variable_hash = ngx_hash_key(uri_variable_name.data, uri_variable_name.len);
      ngx_http_variable_value_t *uri_var = ngx_http_get_variable(r, &uri_variable_name, uri_variable_hash);
      ngx_str_t uri;
      ngx_str_t uri_escaped;
      uintptr_t escaped_len;
      char *return_url;
      int return_url_idx;

      // get the URI
      if (uri_var && !uri_var->not_found && uri_var->valid)
      {
        // ideally we would like the URI with the querystring parameters
        uri.data = ngx_palloc(r->pool, uri_var->len);
        if (uri.data == NULL)
        {
          return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        uri.len = uri_var->len;
        ngx_memcpy(uri.data, uri_var->data, uri_var->len);
      }
      else
      {
        // fallback to the querystring without params
        uri = r->uri;
      }

      if (port_var && !port_var->not_found && port_var->valid)
      {
        const ngx_uint_t port_num = ngx_atoi(port_var->data, port_var->len);
        const bool is_default_port_80 = !r->connection->ssl && port_num == 80;
        const bool is_default_port_443 = r->connection->ssl && port_num == 443;
        const bool is_non_default_port = !is_default_port_80 && !is_default_port_443;

        if (is_non_default_port)
        {
          port_str = ngx_palloc(r->pool, NGX_INT_T_LEN + 2);
          if (port_str == NULL)
          {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
          }

          u_char *end = ngx_snprintf((u_char *)port_str, NGX_INT_T_LEN + 2, ":%ui", port_num);
          port_str_len = end - (u_char *)port_str;
        }
      }


      // escape the URI
      escaped_len = 2 * ngx_escape_uri(NULL, uri.data, uri.len, NGX_ESCAPE_ARGS) + uri.len;
      uri_escaped.data = ngx_palloc(r->pool, escaped_len);
      if (uri_escaped.data == NULL)
      {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
      }
      uri_escaped.len = escaped_len;
      ngx_escape_uri(uri_escaped.data, uri.data, uri.len, NGX_ESCAPE_ARGS);

      // Add up the lengths of: login URL, "?return_url=", scheme, "://", server, port, uri (path)
      r->headers_out.location->value.len = loginlen + 12 + strlen(scheme) + 3 + server.len + port_str_len + uri_escaped.len;

      return_url = ngx_palloc(r->pool, r->headers_out.location->value.len);
      if (return_url == NULL)
      {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
      }

      ngx_memcpy(return_url, jwtcf->loginurl.data, jwtcf->loginurl.len);
      return_url_idx = jwtcf->loginurl.len;

      ngx_memcpy(return_url + return_url_idx, "?return_url=", 12);
      return_url_idx += 12;

      ngx_memcpy(return_url + return_url_idx, scheme, strlen(scheme));
      return_url_idx += strlen(scheme);

      ngx_memcpy(return_url + return_url_idx, "://", 3);
      return_url_idx += 3;

      ngx_memcpy(return_url + return_url_idx, server.data, server.len);
      return_url_idx += server.len;

      if (port_str_len > 0)
      {
        ngx_memcpy(return_url + return_url_idx, port_str, port_str_len);
        return_url_idx += port_str_len;
      }

      if (uri_escaped.len > 0)
      {
        ngx_memcpy(return_url + return_url_idx, uri_escaped.data, uri_escaped.len);
      }

      r->headers_out.location->value.data = (u_char *)return_url;
    }
    else
    {
      // for non-get requests, redirect to the login page without a return URL
      r->headers_out.location->value.len = jwtcf->loginurl.len;
      r->headers_out.location->value.data = jwtcf->loginurl.data;
    }

    return NGX_HTTP_MOVED_TEMPORARILY;
  }

  // When no redirect is needed, no "Location" header construction is needed, and we can respond with a 401
  return NGX_HTTP_UNAUTHORIZED;
}

// Loads the public key into the location config struct
static ngx_int_t load_public_key(ngx_conf_t *cf, auth_jwt_conf_t *conf)
{
  // Create null-terminated path for fopen
  u_char *path = ngx_pnalloc(cf->pool, conf->keyfile_path.len + 1);
  if (path == NULL)
  {
    return NGX_ERROR;
  }
  ngx_memcpy(path, conf->keyfile_path.data, conf->keyfile_path.len);
  path[conf->keyfile_path.len] = '\0';

  FILE *keyFile = fopen((const char *)path, "rb");

  // Check if file exists or is correctly opened
  if (keyFile == NULL)
  {
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "failed to open public key file: %s", path);
    return NGX_ERROR;
  }

  long keySize;
  size_t keySizeRead;

  // Read file length
  fseek(keyFile, 0, SEEK_END);
  keySize = ftell(keyFile);
  fseek(keyFile, 0, SEEK_SET);

  if (keySize <= 0)
  {
    fclose(keyFile);
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "invalid public key file size of %ld", keySize);
    return NGX_ERROR;
  }

  conf->_keyfile.data = ngx_palloc(cf->pool, keySize);
  if (conf->_keyfile.data == NULL)
  {
    fclose(keyFile);
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "failed to allocate memory for key file");
    return NGX_ERROR;
  }

  keySizeRead = fread(conf->_keyfile.data, 1, keySize, keyFile);
  fclose(keyFile);

  if (keySizeRead == (size_t)keySize)
  {
    conf->_keyfile.len = keySize;
    return NGX_OK;
  }
  else
  {
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "public key size %uz does not match expected size of %ld", keySizeRead, keySize);
    return NGX_ERROR;
  }
}

static char *get_jwt(ngx_http_request_t *r, ngx_str_t jwt_location)
{
  static const char *HEADER_PREFIX = "HEADER=";
  static const char *COOKIE_PREFIX = "COOKIE=";
  char *jwtPtr = NULL;

  ngx_log_debug(NGX_LOG_DEBUG, r->connection->log, 0, "jwt_location.len %d", jwt_location.len);

  if (jwt_location.len > strlen(HEADER_PREFIX) && ngx_strncmp(jwt_location.data, HEADER_PREFIX, strlen(HEADER_PREFIX)) == 0)
  {
    ngx_table_elt_t *jwtHeaderVal;

    jwt_location.data += strlen(HEADER_PREFIX);
    jwt_location.len -= strlen(HEADER_PREFIX);

    jwtHeaderVal = search_headers_in(r, jwt_location.data, jwt_location.len);

    if (jwtHeaderVal != NULL)
    {
      static const char *BEARER_PREFIX = "Bearer ";

      if (ngx_strncasecmp(jwtHeaderVal->value.data, (u_char *)BEARER_PREFIX, strlen(BEARER_PREFIX)) == 0)
      {
        ngx_str_t jwtHeaderValWithoutBearer = jwtHeaderVal->value;

        jwtHeaderValWithoutBearer.data += strlen(BEARER_PREFIX);
        jwtHeaderValWithoutBearer.len -= strlen(BEARER_PREFIX);

        jwtPtr = ngx_str_t_to_char_ptr(r->pool, jwtHeaderValWithoutBearer);
      }
      else
      {
        jwtPtr = ngx_str_t_to_char_ptr(r->pool, jwtHeaderVal->value);
      }
    }
  }
  else if (jwt_location.len > strlen(COOKIE_PREFIX) && ngx_strncmp(jwt_location.data, COOKIE_PREFIX, strlen(COOKIE_PREFIX)) == 0)
  {
    bool has_cookie = false;
    ngx_str_t jwtCookieVal;

    jwt_location.data += strlen(COOKIE_PREFIX);
    jwt_location.len -= strlen(COOKIE_PREFIX);

#ifndef NGX_LINKED_LIST_COOKIES
    if (ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &jwt_location, &jwtCookieVal) != NGX_DECLINED)
    {
      has_cookie = true;
    }
#else
    if (ngx_http_parse_multi_header_lines(r, r->headers_in.cookie, &jwt_location, &jwtCookieVal) != NULL)
    {
      has_cookie = true;
    }
#endif

    if (has_cookie == true)
    {
      jwtPtr = ngx_str_t_to_char_ptr(r->pool, jwtCookieVal);
    }
  }

  return jwtPtr;
}

// Base64URL decode helper (for JWK "k" field)
// Returns NGX_ERROR if input contains invalid characters
static ngx_int_t base64url_decode(ngx_pool_t *pool, ngx_str_t *src, ngx_str_t *dst)
{
  // 77 marks invalid characters, valid values are 0-63
  static const u_char basis64[] = {
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 77,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 77, 77, 77, 77, 77,
    77,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 77, 77, 77, 77, 63,
    77, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 77, 77, 77, 77, 77
  };

  size_t len = src->len;
  u_char *s = src->data;

  // Calculate output length
  size_t decoded_len = (len * 3) / 4;

  dst->data = ngx_palloc(pool, decoded_len);
  if (!dst->data)
  {
    return NGX_ERROR;
  }

  u_char *d = dst->data;
  size_t n = 0;

  while (len > 3)
  {
    // Bounds check: reject bytes >= 128 (outside basis64 table)
    if (s[0] >= 128 || s[1] >= 128 || s[2] >= 128 || s[3] >= 128)
    {
      return NGX_ERROR;
    }
    // Invalid character check (77 marks invalid in basis64)
    if (basis64[s[0]] == 77 || basis64[s[1]] == 77 ||
        basis64[s[2]] == 77 || basis64[s[3]] == 77)
    {
      return NGX_ERROR;
    }
    *d++ = (u_char)(basis64[s[0]] << 2 | basis64[s[1]] >> 4);
    *d++ = (u_char)(basis64[s[1]] << 4 | basis64[s[2]] >> 2);
    *d++ = (u_char)(basis64[s[2]] << 6 | basis64[s[3]]);
    s += 4;
    len -= 4;
    n += 3;
  }

  if (len > 1)
  {
    if (s[0] >= 128 || s[1] >= 128 || basis64[s[0]] == 77 || basis64[s[1]] == 77)
    {
      return NGX_ERROR;
    }
    *d++ = (u_char)(basis64[s[0]] << 2 | basis64[s[1]] >> 4);
    n++;
  }
  if (len > 2)
  {
    if (s[2] >= 128 || basis64[s[2]] == 77)
    {
      return NGX_ERROR;
    }
    *d++ = (u_char)(basis64[s[1]] << 4 | basis64[s[2]] >> 2);
    n++;
  }

  dst->len = n;
  return NGX_OK;
}

// Helper function to copy a JSON string to an ngx_str_t
static ngx_str_t json_string_to_ngx_str(ngx_pool_t *pool, json_t *json_str)
{
  ngx_str_t result = ngx_null_string;

  if (json_str && json_is_string(json_str))
  {
    const char *str = json_string_value(json_str);
    size_t len = strlen(str);

    result.data = ngx_palloc(pool, len);
    if (result.data)
    {
      ngx_memcpy(result.data, str, len);
      result.len = len;
    }
  }

  return result;
}

// Parse a single JWK key from a JSON object
static ngx_int_t parse_jwk_key(ngx_pool_t *pool, json_t *jwk, auth_jwt_key_t *key)
{
  json_t *kty = json_object_get(jwk, "kty");
  json_t *kid = json_object_get(jwk, "kid");
  json_t *alg = json_object_get(jwk, "alg");

  if (!kty || !json_is_string(kty))
  {
    return NGX_ERROR;
  }

  // Initialize key structure
  ngx_memzero(key, sizeof(auth_jwt_key_t));

  key->kty = json_string_to_ngx_str(pool, kty);
  key->kid = json_string_to_ngx_str(pool, kid);
  key->alg = json_string_to_ngx_str(pool, alg);

  const char *kty_str = json_string_value(kty);

  if (ngx_strcmp(kty_str, "oct") == 0)
  {
    // Symmetric key (HMAC)
    json_t *k = json_object_get(jwk, "k");
    if (k && json_is_string(k))
    {
      key->k = json_string_to_ngx_str(pool, k);
    }
    else
    {
      return NGX_ERROR;
    }
  }
  else if (ngx_strcmp(kty_str, "RSA") == 0)
  {
    // RSA key - store n and e for potential later use
    json_t *n = json_object_get(jwk, "n");
    json_t *e = json_object_get(jwk, "e");

    if (n && json_is_string(n) && e && json_is_string(e))
    {
      key->n = json_string_to_ngx_str(pool, n);
      key->e = json_string_to_ngx_str(pool, e);
    }
    else
    {
      return NGX_ERROR;
    }
  }
  else if (ngx_strcmp(kty_str, "EC") == 0)
  {
    // EC key - we'll need the x, y, and crv parameters
    // For now, store basic info
    json_t *crv = json_object_get(jwk, "crv");
    if (!crv)
    {
      return NGX_ERROR;
    }
  }

  return NGX_OK;
}

// Load and parse a JWK/JWKS file
static ngx_int_t load_jwk_file(ngx_conf_t *cf, auth_jwt_conf_t *conf)
{
  FILE *fp;
  json_error_t error;
  json_t *root;

  // Create null-terminated path for fopen
  u_char *path = ngx_pnalloc(cf->pool, conf->key_file.len + 1);
  if (path == NULL)
  {
    return NGX_ERROR;
  }
  ngx_memcpy(path, conf->key_file.data, conf->key_file.len);
  path[conf->key_file.len] = '\0';

  fp = fopen((const char *)path, "r");
  if (!fp)
  {
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "failed to open JWK file: %s", path);
    return NGX_ERROR;
  }

  root = json_loadf(fp, 0, &error);
  fclose(fp);

  if (!root)
  {
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "failed to parse JWK file: %s at line %d", error.text, error.line);
    return NGX_ERROR;
  }

  conf->jwks = ngx_palloc(cf->pool, sizeof(auth_jwt_jwks_t));
  if (!conf->jwks)
  {
    json_decref(root);
    return NGX_ERROR;
  }

  json_t *keys = json_object_get(root, "keys");

  if (keys && json_is_array(keys))
  {
    // JWKS format with multiple keys
    size_t nkeys = json_array_size(keys);

    conf->jwks->keys = ngx_palloc(cf->pool, sizeof(auth_jwt_key_t) * nkeys);
    conf->jwks->nkeys = 0;

    if (!conf->jwks->keys)
    {
      json_decref(root);
      return NGX_ERROR;
    }

    for (size_t i = 0; i < nkeys; i++)
    {
      json_t *jwk = json_array_get(keys, i);

      if (parse_jwk_key(cf->pool, jwk, &conf->jwks->keys[conf->jwks->nkeys]) == NGX_OK)
      {
        conf->jwks->nkeys++;

        ngx_log_error(NGX_LOG_INFO, cf->log, 0, "loaded JWK key: kid=%V, kty=%V",
                      &conf->jwks->keys[conf->jwks->nkeys - 1].kid,
                      &conf->jwks->keys[conf->jwks->nkeys - 1].kty);
      }
    }
  }
  else if (json_is_object(root))
  {
    // Single JWK format
    conf->jwks->keys = ngx_palloc(cf->pool, sizeof(auth_jwt_key_t));
    conf->jwks->nkeys = 0;

    if (!conf->jwks->keys)
    {
      json_decref(root);
      return NGX_ERROR;
    }

    if (parse_jwk_key(cf->pool, root, &conf->jwks->keys[0]) == NGX_OK)
    {
      conf->jwks->nkeys = 1;

      ngx_log_error(NGX_LOG_INFO, cf->log, 0, "loaded JWK key: kid=%V, kty=%V",
                    &conf->jwks->keys[0].kid, &conf->jwks->keys[0].kty);
    }
  }
  else
  {
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "invalid JWK file format");
    json_decref(root);
    return NGX_ERROR;
  }

  json_decref(root);

  if (conf->jwks->nkeys == 0)
  {
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "no valid keys found in JWK file");
    return NGX_ERROR;
  }

  ngx_log_error(NGX_LOG_INFO, cf->log, 0, "loaded %d key(s) from JWK file", conf->jwks->nkeys);

  return NGX_OK;
}

// Find a JWK key by kid (key ID), or return the first key if kid is NULL
static auth_jwt_key_t *find_jwk_key(auth_jwt_conf_t *jwtcf, const char *kid)
{
  if (!jwtcf->jwks || jwtcf->jwks->nkeys == 0)
  {
    return NULL;
  }

  // If kid is provided, search for matching key
  if (kid && strlen(kid) > 0)
  {
    for (ngx_uint_t i = 0; i < jwtcf->jwks->nkeys; i++)
    {
      if (jwtcf->jwks->keys[i].kid.len > 0 &&
          jwtcf->jwks->keys[i].kid.len == strlen(kid) &&
          ngx_strncmp(jwtcf->jwks->keys[i].kid.data, kid, strlen(kid)) == 0)
      {
        return &jwtcf->jwks->keys[i];
      }
    }
  }

  // Return first key if no kid specified or kid not found
  return &jwtcf->jwks->keys[0];
}

// Custom handler for auth_jwt_key_file_missing_error directive
// Accepts: error_code [message] [content_type]
static char *set_key_file_missing_error(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  auth_jwt_conf_t *jwtcf = conf;
  ngx_str_t *values = cf->args->elts;
  ngx_int_t n;

  // First argument: error code (required)
  // Allow 3xx redirects (301, 302, 303, 307, 308) and 4xx-5xx errors
  n = ngx_atoi(values[1].data, values[1].len);
  if (!((n >= 301 && n <= 303) || n == 307 || n == 308 || (n >= 400 && n <= 599)))
  {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
      "invalid error code \"%V\" in auth_jwt_key_file_missing_error (use 301-303, 307, 308, or 400-599)",
      &values[1]);
    return NGX_CONF_ERROR;
  }
  jwtcf->key_file_missing_error = n;

  // Second argument: error message or redirect URL (optional)
  if (cf->args->nelts >= 3)
  {
    jwtcf->key_file_missing_message = values[2];
  }

  // Third argument: content type (optional, only for non-redirect responses)
  if (cf->args->nelts >= 4)
  {
    jwtcf->key_file_missing_content_type = values[3];
  }

  return NGX_CONF_OK;
}
