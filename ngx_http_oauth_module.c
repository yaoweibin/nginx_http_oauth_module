
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_oauth_module.h"
#include "ngx_http_oauth_session.h"
#include <oauth.h>

static char *ngx_http_oauth_session_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_http_oauth_add_variables(ngx_conf_t *cf);

static ngx_int_t ngx_http_oauth_consumer_key_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_oauth_nonce_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_oauth_timestamp_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_oauth_signature_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_oauth_init(ngx_conf_t *cf);
static void *ngx_http_oauth_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_oauth_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);


static ngx_conf_bitmask_t  ngx_http_oauth_signatures[] = {
    { ngx_string("HMAC-SHA1"), SIGNATURE_HMAC_SHA1 },
    { ngx_string("PLAINTEXT"), SIGNATURE_PLAINTEXT },
    { ngx_string("RSA-SHA1"), SIGNATURE_RSA_SHA1 },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_oauth_commands[] = {

    { ngx_string("oauth"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oauth_loc_conf_t, enable),
      NULL },

    { ngx_string("oauth_session_zone"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_oauth_session_zone,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("oauth_consumer_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oauth_loc_conf_t, consumer_key),
      NULL },

    { ngx_string("oauth_consumer_secret"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oauth_loc_conf_t, consumer_secret),
      NULL },

    { ngx_string("oauth_request_token_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oauth_loc_conf_t, request_token_uri),
      NULL },

    { ngx_string("oauth_access_token_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oauth_loc_conf_t, access_token_uri),
      NULL },

    { ngx_string("oauth_authenticated_call_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oauth_loc_conf_t, authenticated_call_uri),
      NULL },

    { ngx_string("oauth_signature_method"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oauth_loc_conf_t, signature_methods),
      &ngx_http_oauth_signatures },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_oauth_module_ctx = {
    ngx_http_oauth_add_variables,          /* preconfiguration */
    ngx_http_oauth_init,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_oauth_create_loc_conf,        /* create location configuration */
    ngx_http_oauth_merge_loc_conf          /* merge location configuration */
};


ngx_module_t  ngx_http_oauth_module = {
    NGX_MODULE_V1,
    &ngx_http_oauth_module_ctx,            /* module context */
    ngx_http_oauth_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_oauth_vars[] = {

    { ngx_string("oauth_consumer_key"), NULL,
      ngx_http_oauth_consumer_key_variable, 0,
      NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("oauth_nonce"), NULL,
      ngx_http_oauth_nonce_variable, 0,
      NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("oauth_timestamp"), NULL,
      ngx_http_oauth_timestamp_variable, 0,
      NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("oauth_signature"), NULL,
      ngx_http_oauth_signature_variable, 0,
      NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_int_t 
ngx_http_oauth_consumer_key_variable(ngx_http_request_t *r, 
        ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_oauth_loc_conf_t  *olcf;

    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oauth_module);

    v->len = olcf->consumer_key.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = olcf->consumer_key.data;

    return NGX_OK;
}


static ngx_int_t 
ngx_http_oauth_nonce_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *req_url;
    ngx_str_t                   url;
    ngx_http_oauth_loc_conf_t  *olcf;

    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oauth_module);

    req_url = (u_char *) oauth_sign_url2((char *)olcf->request_token_uri.data, 
            NULL, OA_HMAC, NULL, 
            (char *)olcf->consumer_key.data, 
            (char *)olcf->consumer_secret.data, NULL, NULL);
    
    url.len = ngx_strlen(req_url);
    url.data = ngx_palloc(r->pool, url.len);
    if (url.data == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    ngx_memcpy(url.data, req_url, url.len);

    if (req_url) {
        free(req_url);
    }

    v->len = url.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = url.data;

    return NGX_OK;
}


static u_char *
oauth_pstrdup(ngx_pool_t *pool, ngx_str_t *src)
{
    u_char  *dst;

    dst = ngx_pcalloc(pool, src->len + 1);
    if (dst == NULL) {
        return NULL;
    }

    ngx_memcpy(dst, src->data, src->len);

    return dst;
}


static ngx_int_t 
ngx_http_oauth_signature_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *req_url, name[1024];
    ngx_int_t                   key;
    ngx_str_t                   url, key_name, secret_name, t_key, t_secret;
    ngx_http_oauth_loc_conf_t  *olcf;
    ngx_http_variable_value_t  *vv;

    key_name = (ngx_str_t) ngx_string("oauth_token");
    secret_name = (ngx_str_t) ngx_string("oauth_token_secret");

    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oauth_module);

    ngx_memcpy(name, key_name.data, key_name.len);
    key = ngx_hash_strlow(name, name, key_name.len);
    vv = ngx_http_get_variable(r, &key_name, key);
    t_key.len = vv->len;
    t_key.data = vv->data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oauth_token: \"%V\"", &t_key);

    ngx_memcpy(name, secret_name.data, secret_name.len);
    key = ngx_hash_strlow(name, name, secret_name.len);
    vv = ngx_http_get_variable(r, &secret_name, key);
    t_secret.len = vv->len;
    t_secret.data = vv->data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oauth_token: \"%V\"", &t_secret);

    req_url = (u_char *) oauth_sign_url2((char *)olcf->access_token_uri.data, 
            NULL, OA_HMAC, NULL, 
            (char *)olcf->consumer_key.data, 
            (char *)olcf->consumer_secret.data, 
           (char *)oauth_pstrdup(r->pool, &t_key), 
           (char *)oauth_pstrdup(r->pool, &t_secret));

    url.len = ngx_strlen(req_url);
    url.data = ngx_palloc(r->pool, url.len);
    if (url.data == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    ngx_memcpy(url.data, req_url, url.len);

    if (req_url) {
        free(req_url);
    }

    v->len = url.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = url.data;

    return NGX_OK;
}


static ngx_int_t 
ngx_http_oauth_timestamp_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *req_url, name[1024];
    ngx_int_t                   key;
    ngx_str_t                   url, key_name, secret_name, t_key, t_secret;
    ngx_http_oauth_loc_conf_t  *olcf;
    ngx_http_variable_value_t  *vv;

    key_name = (ngx_str_t) ngx_string("oauth_token");
    secret_name = (ngx_str_t) ngx_string("oauth_token_secret");

    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oauth_module);

    ngx_memcpy(name, key_name.data, key_name.len);
    key = ngx_hash_strlow(name, name, key_name.len);
    vv = ngx_http_get_variable(r, &key_name, key);
    t_key.len = vv->len;
    t_key.data = vv->data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oauth_token: \"%V\"", &t_key);

    ngx_memcpy(name, secret_name.data, secret_name.len);
    key = ngx_hash_strlow(name, name, secret_name.len);
    vv = ngx_http_get_variable(r, &secret_name, key);
    t_secret.len = vv->len;
    t_secret.data = vv->data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oauth_token: \"%V\"", &t_secret);

    req_url = (u_char *) oauth_sign_url2((char *)olcf->authenticated_call_uri.data, 
            NULL, OA_HMAC, NULL, 
            (char *)olcf->consumer_key.data, 
            (char *)olcf->consumer_secret.data, 
           (char *)oauth_pstrdup(r->pool, &t_key), 
           (char *)oauth_pstrdup(r->pool, &t_secret));

    url.len = ngx_strlen(req_url);
    url.data = ngx_palloc(r->pool, url.len);
    if (url.data == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    ngx_memcpy(url.data, req_url, url.len);

    if (req_url) {
        free(req_url);
    }

    v->len = url.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = url.data;

    return NGX_OK;
}


static char *
ngx_http_oauth_session_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                    *p;
    size_t                     size;
    ngx_str_t                 *value, name, s;
    ngx_uint_t                 i;
    ngx_shm_zone_t            *shm_zone;
    ngx_http_oauth_session_ctx_t  *ctx = NULL;

    value = cf->args->elts;

    size = 0;
    name.len = 0;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p) {
                *p = '\0';

                name.len = p - name.data;

                p++;

                s.len = value[i].data + value[i].len - p;
                s.data = p;

                size = ngx_parse_size(&s);
                if (size > 8191) {
                    continue;
                }
            }

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid zone size \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (name.len == 0 || size == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_oauth_session_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_oauth_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    /*shm_zone->init = ngx_http_oauth_session_init_zone;*/
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_oauth_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_oauth_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_oauth_init(ngx_conf_t *cf)
{
    /*ngx_http_handler_pt        *h;*/
    /*ngx_http_core_main_conf_t  *cmcf;*/

    /*cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);*/

    /*h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);*/
    /*if (h == NULL) {*/
    /*return NGX_ERROR;*/
    /*}*/

    /**h = ngx_http_oauth_handler;*/

    return NGX_OK;
}


static void *
ngx_http_oauth_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_oauth_loc_conf_t  *olcf;

    olcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_oauth_loc_conf_t));
    if (olcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     olcf->consumer_key =  {0, NULL};
     *     olcf->consumer_secret =  {0, NULL};
     *     olcf->request_token_uri =  {0, NULL};
     *     olcf->access_toke_uri =  {0, NULL};
     *     olcf->authenticated_call_uri =  {0, NULL};
     *     olcf->signature_methods =  0;
     */

    olcf->enable = NGX_CONF_UNSET;

    return olcf;
}


static char *
ngx_http_oauth_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_oauth_loc_conf_t *prev = parent;
    ngx_http_oauth_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    ngx_conf_merge_str_value(conf->consumer_key, prev->consumer_key, "");
    ngx_conf_merge_str_value(conf->consumer_secret, prev->consumer_secret, "");

    ngx_conf_merge_str_value(conf->request_token_uri, 
            prev->request_token_uri, "");
    ngx_conf_merge_str_value(conf->access_token_uri, 
            prev->access_token_uri, "");
    ngx_conf_merge_str_value(conf->authenticated_call_uri, 
            prev->authenticated_call_uri, "");

    ngx_conf_merge_bitmask_value(conf->signature_methods, 
            prev->signature_methods, SIGNATURE_HMAC_SHA1);

    return NGX_CONF_OK;
}

