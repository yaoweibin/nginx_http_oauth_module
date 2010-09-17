
#ifndef _NGX_HTTP_OAUTH_SESSION_H_
#define _NGX_HTTP_OAUTH_SESSION_H_


#define OAUTH_INIT                   0
#define OAUTH_FETCHING_REQUEST_TOKEN 1
#define OAUTH_GET_REQUEST_TOKEN      2
#define OAUTH_USER_AUTHORIZATION     3
#define OAUTH_GET_VERIFIER           4
#define OAUTH_FETCHING_ACCESS_TOKEN  5
#define OAUTH_GET_ACCESS_TOKEN       6


typedef struct {
    ngx_rbtree_node_t              node;
    ngx_queue_t                    queue;
    u_short                        len;
    ngx_uint_t                     state;
    time_t                         expire;
    u_char                         data[1];
} ngx_http_oauth_session_node_t;

typedef struct {
    ngx_rbtree_t                  rbtree;
    ngx_rbtree_node_t             sentinel;
    ngx_queue_t                   queue;
} ngx_http_oauth_session_shctx_t;

typedef struct {
    ngx_http_oauth_session_shctx_t  *sh;
    ngx_slab_pool_t                 *shpool;
    ngx_int_t                        index;
    ngx_str_t                        var;
} ngx_http_oauth_session_ctx_t;


ngx_int_t ngx_http_oauth_session_handler(ngx_http_request_t *r);

ngx_int_t ngx_http_oauth_session_init_zone(ngx_shm_zone_t *shm_zone, 
        void *data);

#endif /* _NGX_HTTP_OAUTH_SESSION_H_ */
