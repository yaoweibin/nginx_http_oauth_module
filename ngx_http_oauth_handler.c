
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_oauth_module.h"
#include "ngx_http_oauth_session.h"
#include "ngx_http_oauth_handler.h"


static ngx_int_t ngx_http_oauth_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_oauth_reinit_request(ngx_http_request_t *r);
static void ngx_http_oauth_abort_request(ngx_http_request_t *r);
static void ngx_http_oauth_finalize_request(ngx_http_request_t *r,
        ngx_int_t rc);

static ngx_int_t ngx_http_oauth_process_header(ngx_http_request_t *r);

static ngx_int_t ngx_http_oauth_input_filter_init(void *data);

static ngx_int_t ngx_http_oauth_input_filter(void *data, ssize_t bytes);


ngx_int_t
ngx_http_oauth_handler(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_http_upstream_t            *u;
    ngx_http_oauth_loc_conf_t    *mlcf;

    if (r->subrequest_in_memory) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "ngx_http_oauth_module does not support "
                      "subrequest in memory");

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_PUT|NGX_HTTP_POST))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

#if defined(nginx_version) && \
    ((nginx_version >= 7063 && nginx_version < 8000) \
     || nginx_version >= 8007)

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u = r->upstream;

#else /* 0.7.x < 0.7.63, 0.8.x < 0.8.7 */

    u = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t));
    if (u == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->peer.log = r->connection->log;
    u->peer.log_error = NGX_ERROR_ERR;
#  if (NGX_THREADS)
    u->peer.lock = &r->connection->lock;
#  endif

    r->upstream = u;

#endif

    u->schema.len = sizeof("http://") - 1;
    u->schema.data = (u_char *) "http://";

    u->output.tag = (ngx_buf_tag_t) &ngx_http_oauth_module;

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_oauth_module);

    u->conf = &mlcf->upstream;

    u->create_request = ngx_http_oauth_create_request;
    u->reinit_request = ngx_http_oauth_reinit_request;
    u->process_header = ngx_http_oauth_process_header;
    u->abort_request = ngx_http_oauth_abort_request;
    u->finalize_request = ngx_http_oauth_finalize_request;

    /* we bypass the upstream input filter mechanism in
     * ngx_http_upstream_process_headers */

    u->input_filter_init = ngx_http_oauth_input_filter_init;
    u->input_filter = ngx_http_oauth_input_filter;
    u->input_filter_ctx = NULL;

#if defined(nginx_version) && nginx_version >= 8011
    r->main->count++;
#endif

    /*ngx_http_upstream_dbd_init(r);*/

    u->write_event_handler = ngx_http_oauth_wev_handler;
    u->read_event_handler  = ngx_http_oauth_rev_handler;

    return NGX_DONE;
}


void
ngx_http_oauth_wev_handler(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_connection_t            *c;

    /*dd("oauth wev handler");*/

    /* just to ensure u->reinit_request always gets called for
     * upstream_next */
    u->request_sent = 1;

    c = u->peer.connection;

    if (c->write->timedout) {
        /*dd("oauth connection write timeout");*/

        ngx_http_upstream_oauth_next(r, u,
                NGX_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

    if (ngx_http_upstream_oauth_test_connect(c) != NGX_OK) {
        /*dd("oauth connection is broken");*/

        ngx_http_upstream_oauth_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    (void) ngx_http_oauth_process_events(r);
}


void
ngx_http_oauth_rev_handler(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_connection_t            *c;

    /*dd("oauth rev handler");*/

    /* just to ensure u->reinit_request always gets called for
     * upstream_next */
    u->request_sent = 1;

    c = u->peer.connection;

    if (c->read->timedout) {
        /*dd("oauth connection read timeout");*/

        ngx_http_upstream_oauth_next(r, u,
                NGX_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

    if (ngx_http_upstream_oauth_test_connect(c) != NGX_OK) {
        /*dd("oauth connection is broken");*/

        ngx_http_upstream_oauth_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    (void) ngx_http_oauth_process_events(r);
}


static ngx_int_t
ngx_http_oauth_create_request(ngx_http_request_t *r)
{
    r->upstream->request_bufs = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_oauth_reinit_request(ngx_http_request_t *r)
{
    ngx_http_upstream_t         *u;

    u = r->upstream;

    u->write_event_handler = ngx_http_oauth_wev_handler;
    u->read_event_handler  = ngx_http_oauth_rev_handler;

    return NGX_OK;
}


static void
ngx_http_oauth_abort_request(ngx_http_request_t *r)
{
}


static void
ngx_http_oauth_finalize_request(ngx_http_request_t *r,
        ngx_int_t rc)
{
}


static ngx_int_t
ngx_http_oauth_process_header(ngx_http_request_t *r)
{
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
           "ngx_http_oauth_process_header should not be called"
           " by the upstream");

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_oauth_input_filter_init(void *data)
{
    ngx_http_request_t          *r = data;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
           "ngx_http_oauth_input_filter_init should not be called"
           " by the upstream");

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_oauth_input_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t          *r = data;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
           "ngx_http_oauth_input_filter should not be called"
           " by the upstream");

    return NGX_ERROR;
}

