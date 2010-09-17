
#ifndef _NGX_HTTP_OAUTH_MODULE_H_
#define _NGX_HTTP_OAUTH_MODULE_H_

#define SIGNATURE_HMAC_SHA1 0x01
#define SIGNATURE_PLAINTEXT 0x02
#define SIGNATURE_RSA_SHA1  0x04

typedef struct {
    ngx_flag_t enable;
    ngx_str_t consumer_key;
    ngx_str_t consumer_secret;

    ngx_str_t request_token_uri;
    ngx_str_t access_token_uri;
    ngx_str_t authenticated_call_uri;

    ngx_uint_t signature_methods;
    ngx_uint_t eval_token_index;
    ngx_uint_t eval_token_secret_index;
    ngx_shm_zone_t *session_shm_zone;
} ngx_http_oauth_loc_conf_t;

typedef struct {
    ngx_str_t oauth_token;
    ngx_str_t oauth_token_secret;
} ngx_http_oauth_ctx_t;

extern ngx_module_t  ngx_http_oauth_module;

#endif /* _NGX_HTTP_OAUTH_MODULE_H_ */
