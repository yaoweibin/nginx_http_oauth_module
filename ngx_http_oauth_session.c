
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_oauth_module.h"
#include "ngx_http_oauth_session.h"

static void ngx_http_oauth_session_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_int_t ngx_http_oauth_session_lookup(ngx_http_oauth_loc_conf_t *olcf, 
        ngx_uint_t hash, u_char *data, size_t len, 
        ngx_http_oauth_session_node_t **osnp);
static void ngx_http_oauth_session_delete(ngx_http_oauth_session_ctx_t *ctx, 
        ngx_http_oauth_session_node_t  *osn);
static void ngx_http_oauth_session_expire(ngx_http_oauth_session_ctx_t *ctx,
        ngx_uint_t n);


ngx_int_t 
ngx_http_oauth_store_session_by_name(ngx_http_request_t *r, ngx_str_t *token,
        ngx_str_t *secret)
{
    size_t                          n, len;
    uint32_t                        hash;
    ngx_int_t                       rc;
    ngx_rbtree_node_t              *node;
    ngx_http_variable_value_t      *vv;
    ngx_http_oauth_loc_conf_t      *olcf;
    ngx_http_oauth_session_ctx_t   *ctx;
    ngx_http_oauth_session_node_t  *osn;

    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oauth_module);

    if (olcf->session_shm_zone == NULL) {
        return NGX_ERROR;
    }

    ctx = olcf->session_shm_zone->data;

    vv = ngx_http_get_indexed_variable(r, ctx->index);

    if (vv == NULL || vv->not_found) {
        return NGX_ERROR;
    }

    len = vv->len;

    if (len == 0) {
        return NGX_DECLINED;
    }

    if (len > 65535) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "the value of the \"%V\" variable "
                      "is more than 65535 bytes: \"%v\"",
                      &ctx->var, vv);
        return NGX_ERROR;
    }

    hash = ngx_crc32_short(vv->data, len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

    ngx_http_oauth_session_expire(ctx, 1);

    rc = ngx_http_oauth_session_lookup(olcf, hash, vv->data, len, &osn);

    /* Find, delete the old one */
    if (osn) {
        ngx_http_oauth_session_delete(ctx, osn);
    };

    /* Not find */

    n = offsetof(ngx_rbtree_node_t, color)
        + offsetof(ngx_http_oauth_session_node_t, data)
        + len + token->len + secret->len;

    node = ngx_slab_alloc_locked(ctx->shpool, n);
    if (node == NULL) {

        ngx_http_oauth_session_expire(ctx, 0);

        node = ngx_slab_alloc_locked(ctx->shpool, n);
        if (node == NULL) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                    "not enough share memory for zone \"%V\"", 
                    &olcf->session_shm_zone->shm.name);
            return NGX_ERROR;
        }
    }

    osn = (ngx_http_oauth_session_node_t *) &node->color;

    node->key = hash;
    osn->name_len = (u_char) len;
    osn->expire = olcf->session_timeout;

    ngx_memcpy(osn->data, vv->data, len);

    osn->token_start = len;
    osn->token_len = token->len;
    ngx_memcpy(osn->data + osn->token_start, token->data, token->len);

    osn->token_secret_start = osn->token_start + osn->token_len;
    osn->token_secret_len = secret->len;
    ngx_memcpy(osn->data + osn->token_secret_start, secret->data, 
            secret->len);

    ngx_rbtree_insert(&ctx->sh->rbtree, node);

    ngx_queue_insert_head(&ctx->sh->queue, &osn->queue);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;
}


ngx_int_t
ngx_http_oauth_find_session_by_name(ngx_http_request_t *r)
{
    size_t                          len;
    uint32_t                        hash;
    ngx_int_t                       rc;
    ngx_str_t                       str;
    ngx_http_oauth_ctx_t           *oauth_ctx;
    ngx_http_variable_value_t      *vv;
    ngx_http_oauth_loc_conf_t      *olcf;
    ngx_http_oauth_session_ctx_t   *ctx;
    ngx_http_oauth_session_node_t  *osn;

    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oauth_module);

    if (olcf->session_shm_zone == NULL) {
        return NGX_DECLINED;
    }

    ctx = olcf->session_shm_zone->data;

    vv = ngx_http_get_indexed_variable(r, ctx->index);

    if (vv == NULL || vv->not_found) {
        return NGX_DECLINED;
    }

    len = vv->len;

    if (len == 0) {
        return NGX_DECLINED;
    }

    if (len > 65535) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "the value of the \"%V\" variable "
                      "is more than 65535 bytes: \"%v\"",
                      &ctx->var, vv);
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "find session: %*s", len, vv->data);

    hash = ngx_crc32_short(vv->data, len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

    ngx_http_oauth_session_expire(ctx, 1);

    rc = ngx_http_oauth_session_lookup(olcf, hash, vv->data, len, &osn);

    if (osn) {
        ngx_queue_remove(&osn->queue);
        ngx_queue_insert_head(&ctx->sh->queue, &osn->queue);

        oauth_ctx = ngx_http_get_module_ctx(r, ngx_http_oauth_module);

        if(oauth_ctx == NULL) {
            oauth_ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_oauth_ctx_t));
            if (oauth_ctx == NULL) {
                return NGX_ERROR;
            }

            ngx_http_set_ctx(r, oauth_ctx, ngx_http_oauth_module);
        }

        str.data = &osn->data[osn->token_start];
        str.len = osn->token_len;
        oauth_ctx->token.data = ngx_pstrdup(r->pool, &str);
        if (oauth_ctx->token.data == NULL) {
            return NGX_ERROR;
        }
        oauth_ctx->token.len = str.len;

        str.data = &osn->data[osn->token_secret_start];
        str.len = osn->token_secret_len;
        oauth_ctx->token_secret.data = ngx_pstrdup(r->pool, &str);
        if (oauth_ctx->token_secret.data == NULL) {
            return NGX_ERROR;
        }

        oauth_ctx->token_secret.len = str.len;
    }
    else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "not find session");
    };

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;
}


static void
ngx_http_oauth_session_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t               **p;
    ngx_http_oauth_session_node_t   *osn, *osnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            osn = (ngx_http_oauth_session_node_t *) &node->color;
            osnt = (ngx_http_oauth_session_node_t *) &temp->color;

            p = (ngx_memn2cmp(osn->data, osnt->data, osn->name_len, osnt->name_len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_int_t
ngx_http_oauth_session_lookup(ngx_http_oauth_loc_conf_t *olcf, ngx_uint_t hash,
    u_char *data, size_t len, ngx_http_oauth_session_node_t **osnp)
{
    time_t                          now;
    ngx_int_t                       rc;
    ngx_rbtree_node_t              *node, *sentinel;
    ngx_http_oauth_session_ctx_t   *ctx;
    ngx_http_oauth_session_node_t  *osn;

    ctx = olcf->session_shm_zone->data;

    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        do {
            osn = (ngx_http_oauth_session_node_t *) &node->color;

            rc = ngx_memn2cmp(data, osn->data, len, (size_t) osn->name_len);

            if (rc == 0) {

                now = ngx_time();

                /*TODO*/

                /*if (now > osn->expire) {*/
                /**osnp = NULL;*/
                /*return NGX_OK;*/
                /*}*/

                *osnp = osn;

                return NGX_OK;
            }

            node = (rc < 0) ? node->left : node->right;

        } while (node != sentinel && hash == node->key);

        break;
    }

    *osnp = NULL;

    return NGX_OK;
}


static void
ngx_http_oauth_session_delete(ngx_http_oauth_session_ctx_t *ctx, 
        ngx_http_oauth_session_node_t  *osn)
{
    ngx_rbtree_node_t              *node;

    ngx_queue_remove(&osn->queue);

    node = (ngx_rbtree_node_t *)
        ((u_char *) osn - offsetof(ngx_rbtree_node_t, color));

    ngx_rbtree_delete(&ctx->sh->rbtree, node);

    ngx_slab_free_locked(ctx->shpool, node);
}


static void
ngx_http_oauth_session_expire(ngx_http_oauth_session_ctx_t *ctx, ngx_uint_t n)
{
    time_t                          now;
    ngx_queue_t                    *q;
    ngx_rbtree_node_t              *node;
    ngx_http_oauth_session_node_t  *osn;

    now = ngx_time();

    /*
     * n == 1 deletes one or two entries
     * n == 0 deletes oldest entry by force
     *        and one or two entries
     */

    while (n < 3) {

        if (ngx_queue_empty(&ctx->sh->queue)) {
            return;
        }

        q = ngx_queue_last(&ctx->sh->queue);

        osn = ngx_queue_data(q, ngx_http_oauth_session_node_t, queue);

        if (n++ != 0) {
            /*if (osn->expire > now) {*/
                return;
                /*}*/
        }

        ngx_queue_remove(q);

        node = (ngx_rbtree_node_t *)
                   ((u_char *) osn - offsetof(ngx_rbtree_node_t, color));

        ngx_rbtree_delete(&ctx->sh->rbtree, node);

        ngx_slab_free_locked(ctx->shpool, node);
    }
}


ngx_int_t
ngx_http_oauth_session_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                         len;
    ngx_http_oauth_session_ctx_t  *ctx;
    ngx_http_oauth_session_ctx_t  *octx = data;

    ctx = shm_zone->data;

    if (octx) {
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_oauth_session_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_http_oauth_session_rbtree_insert_value);

    ngx_queue_init(&ctx->sh->queue);

    len = sizeof(" in oauth session zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx, " in oauth session zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}

