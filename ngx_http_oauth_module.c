
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_oauth_module.h"
#include <oauth.h>

static char * ngx_http_oauth_variables(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);

static ngx_int_t ngx_http_oauth_add_variables(ngx_conf_t *cf);

static ngx_int_t ngx_http_oauth_consumer_key_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_oauth_nonce_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_oauth_signed_request_token_uri_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_oauth_signed_access_token_uri_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_oauth_signed_authenticated_call_uri_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_oauth_signature_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_oauth_timestamp_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static void *ngx_http_oauth_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_oauth_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static ngx_conf_bitmask_t  ngx_http_oauth_signatures[] = {
    { ngx_string("HMAC-SHA1"), OA_HMAC },
    { ngx_string("PLAINTEXT"), OA_PLAINTEXT },
    { ngx_string("RSA-SHA1"), OA_RSA },
    { ngx_null_string, 0 }
};

static ngx_command_t  ngx_http_oauth_commands[] = {

    { ngx_string("oauth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oauth_loc_conf_t, enable),
      NULL },

    { ngx_string("oauth_variables"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_oauth_variables,
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
    NULL,                                  /* postconfiguration */

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

    { ngx_string("oauth_signed_request_token_uri"), NULL,
      ngx_http_oauth_signed_request_token_uri_variable, 0,
      NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("oauth_signed_access_token_uri"), NULL,
      ngx_http_oauth_signed_access_token_uri_variable, 0,
      NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("oauth_signed_authenticated_call_uri"), NULL,
      ngx_http_oauth_signed_authenticated_call_uri_variable, 0,
      NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("oauth_signature"), NULL,
      ngx_http_oauth_signature_variable, 0,
      NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("oauth_timestamp"), NULL,
      ngx_http_oauth_timestamp_variable, 0,
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
    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t 
ngx_http_oauth_signed_request_token_uri_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *req_url, *proxy_uri;
    ngx_str_t                   url;
    ngx_http_oauth_loc_conf_t  *olcf;
    ngx_http_variable_value_t  *vv;

    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oauth_module);

    if (olcf->proxy_uri_index != NGX_CONF_UNSET_UINT) {
        vv = ngx_http_get_indexed_variable(r, olcf->proxy_uri_index);

        if (vv->len == 0) {
            goto not_found;
        }

        proxy_uri = ngx_pcalloc(r->pool, vv->len + 1);
        if (proxy_uri == NULL) {
            goto not_found;
        }

        ngx_memcpy(proxy_uri, vv->data, vv->len);
    }
    else {
        goto not_found;
    }

    req_url = (u_char *) oauth_sign_url2((char *)proxy_uri, 
            NULL, olcf->signature_methods, NULL, 
            (char *)olcf->consumer_key.data, 
            (char *)olcf->consumer_secret.data, NULL, NULL);
    
    url.len = ngx_strlen(req_url);
    url.data = ngx_palloc(r->pool, url.len);
    if (url.data == NULL) {
        if (req_url) {
            free(req_url);
        }

        goto not_found;
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

not_found:

    v->not_found = 1;
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
ngx_http_oauth_signed_access_token_uri_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *req_url, *proxy_uri;
    ngx_str_t                   url, t_key, t_secret;
    ngx_http_oauth_loc_conf_t  *olcf;
    ngx_http_variable_value_t  *vv;

    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oauth_module);

    if (olcf->proxy_uri_index != NGX_CONF_UNSET_UINT) {
        vv = ngx_http_get_indexed_variable(r, olcf->proxy_uri_index);

        if (vv->len == 0) {
            goto not_found;
        }

        proxy_uri = ngx_pcalloc(r->pool, vv->len + 1);
        if (proxy_uri == NULL) {
            goto not_found;
        }

        ngx_memcpy(proxy_uri, vv->data, vv->len);
    }
    else {
        goto not_found;
    }

    if (olcf->token_index == NGX_CONF_UNSET_UINT) {
        goto not_found;
    }

    vv = ngx_http_get_indexed_variable(r, olcf->token_index);

    t_key.len = vv->len;
    t_key.data = vv->data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oauth_token: \"%V\"", &t_key);

    if (olcf->token_index == NGX_CONF_UNSET_UINT) {
        goto not_found;
    }

    vv = ngx_http_get_indexed_variable(r, olcf->token_secret_index);

    t_secret.len = vv->len;
    t_secret.data = vv->data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oauth_secret: \"%V\"", &t_secret);

    req_url = (u_char *) oauth_sign_url2((char *)proxy_uri, 
            NULL, olcf->signature_methods, NULL, 
            (char *)olcf->consumer_key.data, 
            (char *)olcf->consumer_secret.data, 
           (char *)oauth_pstrdup(r->pool, &t_key), 
           (char *)oauth_pstrdup(r->pool, &t_secret));

    url.len = ngx_strlen(req_url);
    url.data = ngx_palloc(r->pool, url.len);
    if (url.data == NULL) {
        if (req_url) {
            free(req_url);
        }

        goto not_found;
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

not_found:

    v->not_found = 1;
    return NGX_OK;
}


static ngx_int_t 
ngx_http_oauth_signed_authenticated_call_uri_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *req_url, *proxy_uri;
    ngx_str_t                   url, t_key, t_secret;
    ngx_http_oauth_ctx_t       *oauth_ctx;
    ngx_http_oauth_loc_conf_t  *olcf;
    ngx_http_variable_value_t  *vv;

    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oauth_module);

    if (olcf->proxy_uri_index != NGX_CONF_UNSET_UINT) {
        vv = ngx_http_get_indexed_variable(r, olcf->proxy_uri_index);

        if (vv->len == 0) {
            goto not_found;
        }

        proxy_uri = ngx_pcalloc(r->pool, vv->len + 1);
        if (proxy_uri == NULL) {
            goto not_found;
        }

        ngx_memcpy(proxy_uri, vv->data, vv->len);
    }
    else {
        goto not_found;
    }

    oauth_ctx = ngx_http_get_module_ctx(r, ngx_http_oauth_module);

    if(oauth_ctx && oauth_ctx->token.len > 0) {
        t_key = oauth_ctx->token;
        t_secret = oauth_ctx->token_secret;
    }
    else {
        if (olcf->token_index == NGX_CONF_UNSET_UINT) {
            goto not_found;
        }

        vv = ngx_http_get_indexed_variable(r, olcf->token_index);
        t_key.len = vv->len;
        t_key.data = vv->data;

        if (olcf->token_index == NGX_CONF_UNSET_UINT) {
            goto not_found;
        }

        vv = ngx_http_get_indexed_variable(r, olcf->token_secret_index);

        t_secret.len = vv->len;
        t_secret.data = vv->data;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oauth_token: \"%V\", oauth_secret: \"%V\"", 
                   &t_key, &t_secret);

    req_url = (u_char *) oauth_sign_url2((char *)proxy_uri, 
            NULL, olcf->signature_methods, NULL, 
            (char *)olcf->consumer_key.data, 
            (char *)olcf->consumer_secret.data, 
           (char *)oauth_pstrdup(r->pool, &t_key), 
           (char *)oauth_pstrdup(r->pool, &t_secret));

    url.len = ngx_strlen(req_url);
    url.data = ngx_palloc(r->pool, url.len);
    if (url.data == NULL) {
        if (req_url) {
            free(req_url);
        }

        goto not_found;
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

not_found:

    v->not_found = 1;
    return NGX_OK;
}


static ngx_int_t 
ngx_http_oauth_dummy_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t 
ngx_http_oauth_signature_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t 
ngx_http_oauth_timestamp_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;

    return NGX_OK;
}


static char *
ngx_http_oauth_variables(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                 *value;
    ngx_int_t                  index;
    ngx_http_variable_t       *v;

    ngx_http_oauth_loc_conf_t *olcf = conf;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    index = ngx_http_get_variable_index(cf, &value[1]);
    if (index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    olcf->token_index = (ngx_uint_t) index;

    if (value[2].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid variable name \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    value[2].len--;
    value[2].data++;

    v = ngx_http_add_variable(cf, &value[2], NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    index = ngx_http_get_variable_index(cf, &value[2]);
    if (index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    olcf->token_secret_index = (ngx_uint_t) index;

    if (cf->args->nelts < 4) {
        return NGX_CONF_OK;
    }

    if (value[3].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid variable name \"%V\"", &value[3]);
        return NGX_CONF_ERROR;
    }

    value[3].len--;
    value[3].data++;

    v = ngx_http_add_variable(cf, &value[3], NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }
    v->get_handler = ngx_http_oauth_dummy_variable;

    index = ngx_http_get_variable_index(cf, &value[3]);
    if (index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    olcf->proxy_uri_index = (ngx_uint_t) index;

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
     *     olcf->call_back_uri =  {0, NULL};
     *     olcf->request_auth_uri =  {0, NULL};
     *     olcf->access_toke_uri =  {0, NULL};
     *     olcf->authenticated_call_uri =  {0, NULL};
     *     olcf->signature_methods =  0;
     */

    olcf->enable = NGX_CONF_UNSET;
    olcf->token_index = NGX_CONF_UNSET_UINT;
    olcf->token_secret_index = NGX_CONF_UNSET_UINT;
    olcf->verifier_index = NGX_CONF_UNSET_UINT;
    olcf->proxy_uri_index = NGX_CONF_UNSET_UINT;

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
    ngx_conf_merge_str_value(conf->call_back_uri, 
            prev->call_back_uri, "");
    ngx_conf_merge_str_value(conf->request_auth_uri, 
            prev->request_auth_uri, "");
    ngx_conf_merge_str_value(conf->access_token_uri, 
            prev->access_token_uri, "");
    ngx_conf_merge_str_value(conf->authenticated_call_uri, 
            prev->authenticated_call_uri, "");

    ngx_conf_merge_bitmask_value(conf->signature_methods, 
            prev->signature_methods, OA_HMAC);

    ngx_conf_merge_uint_value(conf->token_index, prev->token_index,
            NGX_CONF_UNSET_UINT);
    ngx_conf_merge_uint_value(conf->token_secret_index, 
            prev->token_secret_index, NGX_CONF_UNSET_UINT);
    ngx_conf_merge_uint_value(conf->verifier_index, 
            prev->verifier_index, NGX_CONF_UNSET_UINT);
    ngx_conf_merge_uint_value(conf->proxy_uri_index, 
            prev->proxy_uri_index, NGX_CONF_UNSET_UINT);

    return NGX_CONF_OK;
}

