
#if 0
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_oauth_session.h"


static ngx_int_t
ngx_http_oauth_session_handler(ngx_http_request_t *r)
{
    size_t                      len, n;
    uint32_t                    hash;
    ngx_int_t                   rc;
    ngx_uint_t                  excess;
    ngx_time_t                 *tp;
    ngx_rbtree_node_t          *node;
    ngx_http_variable_value_t  *vv;
    ngx_http_oauth_session_ctx_t   *ctx;
    ngx_http_oauth_session_node_t  *lr;
    ngx_http_oauth_session_conf_t  *lrcf;

    if (r->main->oauth_session_set) {
        return NGX_DECLINED;
    }

    lrcf = ngx_http_get_module_loc_conf(r, ngx_http_oauth_module);

    if (lrcf->shm_zone == NULL) {
        return NGX_DECLINED;
    }

    ctx = lrcf->shm_zone->data;

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

    hash = ngx_crc32_short(vv->data, len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

    ngx_http_oauth_session_expire(ctx, 1);

    rc = ngx_http_oauth_session_lookup(lrcf, hash, vv->data, len, &lr);

    if (lr) {
        ngx_queue_remove(&lr->queue);
        ngx_queue_insert_head(&ctx->sh->queue, &lr->queue);

        goto done;
    };

    /* Not find or expire */

    n = offsetof(ngx_rbtree_node_t, color)
        + offsetof(ngx_http_oauth_session_node_t, data)
        + len;

    node = ngx_slab_alloc_locked(ctx->shpool, n);
    if (node == NULL) {

        ngx_http_oauth_session_expire(ctx, 0);

        node = ngx_slab_alloc_locked(ctx->shpool, n);
        if (node == NULL) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_HTTP_SERVICE_UNAVAILABLE;
        }
    }

    lr = (ngx_http_oauth_session_node_t *) &node->color;

    node->key = hash;
    lr->len = (u_char) len;

    tp = ngx_timeofday();

    ngx_memcpy(lr->data, vv->data, len);

    ngx_rbtree_insert(&ctx->sh->rbtree, node);

    ngx_queue_insert_head(&ctx->sh->queue, &lr->queue);

done:

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_DONE;
}


static void
ngx_http_oauth_session_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t               **p;
    ngx_http_oauth_session_node_t   *lrn, *lrnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lrn = (ngx_http_oauth_session_node_t *) &node->color;
            lrnt = (ngx_http_oauth_session_node_t *) &temp->color;

            p = (ngx_memn2cmp(lrn->data, lrnt->data, lrn->len, lrnt->len) < 0)
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
ngx_http_oauth_session_lookup(ngx_http_oauth_conf_t *lrcf, ngx_uint_t hash,
    u_char *data, size_t len, ngx_http_oauth_session_node_t **lrp)
{
    ngx_int_t                   rc, excess;
    ngx_time_t                 *tp;
    ngx_msec_t                  now;
    ngx_msec_int_t              ms;
    ngx_rbtree_node_t          *node, *sentinel;
    ngx_http_oauth_session_ctx_t   *ctx;
    ngx_http_oauth_session_node_t  *lr;

    ctx = lrcf->shm_zone->data;

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
            lr = (ngx_http_oauth_session_node_t *) &node->color;

            rc = ngx_memn2cmp(data, lr->data, len, (size_t) lr->len);

            if (rc == 0) {

                tp = ngx_timeofday();

                now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);

                if (now > lr->expire) {
                    *lrp = NULL;
                    return NGX_OK;
                }

                /*TODO*/

                *lrp = lr;

                return NGX_OK;
            }

            node = (rc < 0) ? node->left : node->right;

        } while (node != sentinel && hash == node->key);

        break;
    }

    *lrp = NULL;

    return NGX_OK;
}


static void
ngx_http_oauth_session_expire(ngx_http_oauth_session_ctx_t *ctx, ngx_uint_t n)
{
    time_t                      now;
    ngx_queue_t                *q;
    ngx_rbtree_node_t          *node;
    ngx_http_oauth_session_node_t  *lr;

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

        lr = ngx_queue_data(q, ngx_http_oauth_session_node_t, queue);

        if (n++ != 0) {
            if (lr->expire > now) {
                return;
            }
        }

        ngx_queue_remove(q);

        node = (ngx_rbtree_node_t *)
                   ((u_char *) lr - offsetof(ngx_rbtree_node_t, color));

        ngx_rbtree_delete(&ctx->sh->rbtree, node);

        ngx_slab_free_locked(ctx->shpool, node);
    }
}


ngx_int_t
ngx_http_oauth_session_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_oauth_session_ctx_t  *octx = data;

    size_t                     len;
    ngx_http_oauth_session_ctx_t  *ctx;

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

#endif
