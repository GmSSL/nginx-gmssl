
/*
 * Copyright (C) GmSSL Project.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


static void *ngx_gmssl_create_conf(ngx_cycle_t *cycle);
static void ngx_gmssl_exit(ngx_cycle_t *cycle);
static void ngx_gmssl_handshake_handler(ngx_event_t *ev);
static ngx_int_t ngx_gmssl_again(ngx_connection_t *c, int rc);
static int ngx_gmssl_protocol(ngx_uint_t protocols, ngx_uint_t *protocol);
static ngx_int_t ngx_gmssl_configure_ctx(ngx_ssl_t *ssl);
static ngx_int_t ngx_gmssl_set_str(ngx_pool_t *pool, ngx_str_t *dst,
    ngx_str_t *src);


static ngx_command_t  ngx_gmssl_commands[] = {
      ngx_null_command
};


static ngx_core_module_t  ngx_gmssl_module_ctx = {
    ngx_string("gmssl"),
    ngx_gmssl_create_conf,
    NULL
};


ngx_module_t  ngx_gmssl_module = {
    NGX_MODULE_V1,
    &ngx_gmssl_module_ctx,
    ngx_gmssl_commands,
    NGX_CORE_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_gmssl_exit,
    NGX_MODULE_V1_PADDING
};


ngx_int_t
ngx_ssl_init(ngx_log_t *log)
{
    const char  *runtime_version;

    runtime_version = gmssl_version_str();
    if (runtime_version == NULL
        || ngx_strcmp(runtime_version, GMSSL_VERSION_STR) != 0)
    {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "GmSSL version mismatch: built with \"%s\", "
                      "running with \"%s\"",
                      GMSSL_VERSION_STR,
                      runtime_version ? runtime_version : "(null)");
        return NGX_ERROR;
    }

    if (tls_socket_lib_init() != 1) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "tls_socket_lib_init() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_create(ngx_ssl_t *ssl, ngx_uint_t protocols, void *data)
{
    ngx_uint_t  protocol;

    if (ngx_gmssl_protocol(protocols, &protocol) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, ssl->log, 0,
                      "GmSSL requires exactly one of TLCP, TLSv1.2, TLSv1.3 "
                      "in ssl_protocols");
        return NGX_ERROR;
    }

    ssl->ctx = ngx_pcalloc(ngx_cycle->pool, sizeof(TLS_CTX));
    if (ssl->ctx == NULL) {
        return NGX_ERROR;
    }

    ssl->protocols = protocols;
    ssl->protocol = protocol;
    ssl->buffer_size = NGX_SSL_BUFSIZE;

    ngx_rbtree_init(&ssl->staple_rbtree, &ssl->staple_sentinel,
                    ngx_rbtree_insert_value);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_certificates(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_array_t *certs,
    ngx_array_t *keys, ngx_array_t *passwords)
{
    ngx_str_t   *cert, *key;

    cert = certs->elts;
    key = keys->elts;

    return ngx_ssl_certificate(cf, ssl, &cert[0], &key[0], passwords);
}


ngx_int_t
ngx_ssl_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
    ngx_str_t *key, ngx_array_t *passwords)
{
    ngx_str_t  *pwd;

    if (ngx_conf_full_name(cf->cycle, cert, 1) != NGX_OK
        || ngx_conf_full_name(cf->cycle, key, 1) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_gmssl_set_str(cf->pool, &ssl->certificate, cert) != NGX_OK
        || ngx_gmssl_set_str(cf->pool, &ssl->certificate_key, key) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (passwords && passwords->nelts) {
        pwd = passwords->elts;
        if (ngx_gmssl_set_str(cf->pool, &ssl->certificate_pass, &pwd[0])
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_connection_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *cert, ngx_str_t *key, ngx_ssl_cache_t *cache,
    ngx_array_t *passwords)
{
    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                  "variables in SSL certificate paths are not supported by "
                  "the GmSSL backend");
    return NGX_ERROR;
}


ngx_int_t
ngx_ssl_certificate_compression(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_uint_t enable)
{
    if (enable) {
        ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
                      "\"ssl_certificate_compression\" is not supported by "
                      "the GmSSL backend, ignored");
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_ciphers(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *ciphers,
    ngx_uint_t prefer_server_ciphers)
{
    return NGX_OK;
}


ngx_int_t
ngx_ssl_client_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
    ngx_int_t depth)
{
    return NGX_OK;
}


ngx_int_t
ngx_ssl_trusted_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
    ngx_int_t depth)
{
    if (cert->len == 0) {
        return NGX_OK;
    }

    if (ngx_conf_full_name(cf->cycle, cert, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_gmssl_set_str(cf->pool, &ssl->ca_certificate, cert) != NGX_OK) {
        return NGX_ERROR;
    }

    ssl->verify_depth = depth;

    return NGX_OK;
}


ngx_int_t ngx_ssl_crl(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *crl)
{
    return NGX_OK;
}


ngx_int_t ngx_ssl_stapling(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file,
    ngx_str_t *responder, ngx_uint_t verify)
{
    return NGX_OK;
}


ngx_int_t ngx_ssl_stapling_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout)
{
    return NGX_OK;
}


ngx_int_t ngx_ssl_ocsp(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *responder,
    ngx_uint_t depth, ngx_shm_zone_t *shm_zone)
{
    return NGX_OK;
}


ngx_int_t ngx_ssl_ocsp_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout)
{
    return NGX_OK;
}


ngx_int_t ngx_ssl_ocsp_validate(ngx_connection_t *c) { return NGX_OK; }
ngx_int_t ngx_ssl_ocsp_get_status(ngx_connection_t *c, const char **s)
{
    *s = "disabled";
    return NGX_OK;
}
void ngx_ssl_ocsp_cleanup(ngx_connection_t *c) { }
ngx_int_t ngx_ssl_ocsp_cache_init(ngx_shm_zone_t *shm_zone, void *data)
{
    return NGX_OK;
}


ngx_ssl_cache_t *
ngx_ssl_cache_init(ngx_pool_t *pool, ngx_uint_t max, time_t valid,
    time_t inactive)
{
    return (ngx_ssl_cache_t *) 1;
}


void *ngx_ssl_cache_fetch(ngx_conf_t *cf, ngx_uint_t index, char **err,
    ngx_str_t *id, void *data)
{
    *err = "GmSSL backend does not expose OpenSSL cache objects";
    return NULL;
}


void *ngx_ssl_cache_connection_fetch(ngx_ssl_cache_t *cache, ngx_pool_t *pool,
    ngx_uint_t index, char **err, ngx_str_t *id, void *data)
{
    *err = "GmSSL backend does not expose OpenSSL cache objects";
    return NULL;
}


ngx_array_t *
ngx_ssl_read_password_file(ngx_conf_t *cf, ngx_str_t *file)
{
    ngx_array_t  *passwords;
    ngx_str_t    *pwd;
    ngx_file_t    f;
    ssize_t       n;
    u_char        buf[4096];

    if (ngx_conf_full_name(cf->cycle, file, 1) != NGX_OK) {
        return NULL;
    }

    ngx_memzero(&f, sizeof(ngx_file_t));
    f.name = *file;
    f.log = cf->log;

    f.fd = ngx_open_file(file->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (f.fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%s\" failed", file->data);
        return NULL;
    }

    n = ngx_read_file(&f, buf, sizeof(buf) - 1, 0);
    ngx_close_file(f.fd);

    if (n <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "cannot read password file \"%s\"", file->data);
        return NULL;
    }

    while (n > 0 && (buf[n - 1] == LF || buf[n - 1] == CR)) {
        n--;
    }

    passwords = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
    if (passwords == NULL) {
        return NULL;
    }

    pwd = ngx_array_push(passwords);
    if (pwd == NULL) {
        return NULL;
    }

    pwd->len = n;
    pwd->data = ngx_pnalloc(cf->pool, pwd->len + 1);
    if (pwd->data == NULL) {
        return NULL;
    }

    ngx_memcpy(pwd->data, buf, pwd->len);
    pwd->data[pwd->len] = '\0';

    return passwords;
}


ngx_array_t *
ngx_ssl_preserve_passwords(ngx_conf_t *cf, ngx_array_t *passwords)
{
    return passwords;
}


ngx_int_t ngx_ssl_dhparam(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file)
{
    return NGX_OK;
}


ngx_int_t ngx_ssl_ech_files(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_array_t *filenames)
{
    return NGX_OK;
}


ngx_int_t ngx_ssl_ecdh_curve(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *name)
{
    return NGX_OK;
}


ngx_int_t ngx_ssl_early_data(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_uint_t enable)
{
    return NGX_OK;
}


ngx_int_t ngx_ssl_conf_commands(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_array_t *commands)
{
    if (commands != NULL) {
        ngx_log_error(NGX_LOG_EMERG, ssl->log, 0,
                      "\"ssl_conf_command\" is not supported by the GmSSL "
                      "backend");
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t ngx_ssl_client_session_cache(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_uint_t enable)
{
    return NGX_OK;
}


ngx_int_t ngx_ssl_session_cache(ngx_ssl_t *ssl, ngx_str_t *sess_ctx,
    ngx_array_t *certificates, ssize_t builtin_session_cache,
    ngx_shm_zone_t *shm_zone, time_t timeout)
{
    return NGX_OK;
}


ngx_int_t ngx_ssl_session_ticket_keys(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_array_t *paths)
{
    return NGX_OK;
}


ngx_int_t ngx_ssl_session_cache_init(ngx_shm_zone_t *shm_zone, void *data)
{
    return NGX_OK;
}


ngx_int_t ngx_ssl_set_client_hello_callback(ngx_ssl_t *ssl,
    ngx_ssl_client_hello_arg *cb)
{
    return NGX_OK;
}


ngx_int_t
ngx_ssl_create_connection(ngx_ssl_t *ssl, ngx_connection_t *c, ngx_uint_t flags)
{
    ngx_ssl_connection_t  *sc;

    if (flags & NGX_SSL_CLIENT) {
        ssl->client = 1;
    }

    if (ngx_gmssl_configure_ctx(ssl) != NGX_OK) {
        return NGX_ERROR;
    }

    sc = ngx_pcalloc(c->pool, sizeof(ngx_ssl_connection_t));
    if (sc == NULL) {
        return NGX_ERROR;
    }

    sc->connection = ngx_pcalloc(c->pool, sizeof(TLS_CONNECT));
    if (sc->connection == NULL) {
        return NGX_ERROR;
    }

    if (tls_init(sc->connection, ssl->ctx) != 1
        || tls_set_socket(sc->connection, c->fd) != 1)
    {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "GmSSL connection init failed");
        return NGX_ERROR;
    }

    sc->session_ctx = ssl->ctx;
    sc->buffer = ((flags & NGX_SSL_BUFFER) != 0);
    sc->buffer_size = ssl->buffer_size;
    c->ssl = sc;

    return NGX_OK;
}


void ngx_ssl_remove_cached_session(TLS_CTX *ssl, ngx_ssl_session_t *sess) { }
ngx_int_t ngx_ssl_set_session(ngx_connection_t *c, ngx_ssl_session_t *session)
{
    return NGX_OK;
}
ngx_ssl_session_t *ngx_ssl_get_session(ngx_connection_t *c) { return NULL; }
ngx_ssl_session_t *ngx_ssl_get0_session(ngx_connection_t *c) { return NULL; }


ngx_int_t
ngx_ssl_handshake(ngx_connection_t *c)
{
    int  rc;

    rc = tls_do_handshake(c->ssl->connection);

    if (rc == 1) {
        c->ssl->handshaked = 1;
        c->recv = ngx_ssl_recv;
        c->send = ngx_ssl_write;
        c->recv_chain = ngx_ssl_recv_chain;
        c->send_chain = ngx_ssl_send_chain;
        c->read->ready = 1;
        c->write->ready = 1;

        if (c->ssl->handler) {
            c->ssl->handler(c);
        }

        return NGX_OK;
    }

    if (ngx_gmssl_again(c, rc) == NGX_AGAIN) {
        c->read->handler = ngx_gmssl_handshake_handler;
        c->write->handler = ngx_gmssl_handshake_handler;
        return NGX_AGAIN;
    }

    ngx_log_error(NGX_LOG_ERR, c->log, 0, "GmSSL handshake failed: %d", rc);
    return NGX_ERROR;
}


void ngx_ssl_handshake_log(ngx_connection_t *c) { }


static void
ngx_gmssl_handshake_handler(ngx_event_t *ev)
{
    ngx_connection_t  *c;

    c = ev->data;

    if (ngx_ssl_handshake(c) == NGX_AGAIN) {
        return;
    }
}


ssize_t
ngx_ssl_recv_chain(ngx_connection_t *c, ngx_chain_t *cl, off_t limit)
{
    u_char   *last;
    size_t    size;
    ssize_t   n, bytes;

    bytes = 0;

    while (cl) {
        if (ngx_buf_special(cl->buf)) {
            cl = cl->next;
            continue;
        }

        size = cl->buf->end - cl->buf->last;

        if (limit && bytes + (off_t) size > limit) {
            size = (size_t) (limit - bytes);
        }

        if (size == 0) {
            break;
        }

        last = cl->buf->last;
        n = ngx_ssl_recv(c, last, size);

        if (n > 0) {
            cl->buf->last += n;
            bytes += n;

            if (limit && bytes == limit) {
                return bytes;
            }

            cl = cl->next;
            continue;
        }

        return bytes ? bytes : n;
    }

    return bytes;
}


ssize_t
ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    int     rc;
    size_t  n;

    if (c->ssl == NULL || c->ssl->connection == NULL) {
        c->read->eof = 1;
        return 0;
    }

    rc = tls_recv(c->ssl->connection, buf, size, &n);

    if (rc == 1) {
        c->read->ready = 1;
        return (ssize_t) n;
    }

    if (rc == 0 || rc == TLS_ERROR_TCP_CLOSED) {
        c->read->eof = 1;
        return 0;
    }

    if (rc == TLS_ERROR_RECV_AGAIN || rc == TLS_ERROR_SEND_AGAIN) {
        return NGX_AGAIN;
    }

    c->read->error = 1;
    ngx_log_error(NGX_LOG_ERR, c->log, 0, "GmSSL recv failed: %d", rc);
    return NGX_ERROR;
}


ngx_chain_t *
ngx_ssl_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    u_char       buf[NGX_SSL_BUFSIZE];
    size_t       size;
    ssize_t      n;
    ngx_chain_t *cl;

    for (cl = in; cl; cl = cl->next) {
        if (ngx_buf_special(cl->buf)) {
            continue;
        }

        while (cl->buf->in_file && cl->buf->file_pos < cl->buf->file_last) {
            size = (size_t) ngx_min(cl->buf->file_last - cl->buf->file_pos,
                                    (off_t) sizeof(buf));

            if (limit && (off_t) size > limit) {
                size = (size_t) limit;
            }

            if (size == 0) {
                return cl;
            }

            n = ngx_read_file(cl->buf->file, buf, size, cl->buf->file_pos);
            if (n == NGX_ERROR) {
                return NGX_CHAIN_ERROR;
            }

            size = (size_t) n;
            n = ngx_ssl_write(c, buf, size);

            if (n == NGX_AGAIN) {
                return cl;
            }

            if (n == NGX_ERROR) {
                return NGX_CHAIN_ERROR;
            }

            cl->buf->file_pos += n;

            if (limit) {
                limit -= n;
                if (limit == 0) {
                    return cl;
                }
            }
        }

        while (cl->buf->pos < cl->buf->last) {
            size = cl->buf->last - cl->buf->pos;

            if (limit && (off_t) size > limit) {
                size = (size_t) limit;
            }

            if (size == 0) {
                return cl;
            }

            n = ngx_ssl_write(c, cl->buf->pos, size);

            if (n == NGX_AGAIN) {
                return cl;
            }

            if (n == NGX_ERROR) {
                return NGX_CHAIN_ERROR;
            }

            cl->buf->pos += n;

            if (limit) {
                limit -= n;
                if (limit == 0) {
                    return cl;
                }
            }
        }
    }

    return NULL;
}


ssize_t
ngx_ssl_write(ngx_connection_t *c, u_char *data, size_t size)
{
    int     rc;
    size_t  n;

    if (c->ssl == NULL || c->ssl->connection == NULL) {
        c->write->error = 1;
        return NGX_ERROR;
    }

    rc = tls_send(c->ssl->connection, data, size, &n);

    if (rc == 1) {
        c->sent += n;
        return (ssize_t) n;
    }

    if (rc == TLS_ERROR_RECV_AGAIN || rc == TLS_ERROR_SEND_AGAIN) {
        return NGX_AGAIN;
    }

    c->write->error = 1;
    ngx_log_error(NGX_LOG_ERR, c->log, 0, "GmSSL send failed: %d", rc);
    return NGX_ERROR;
}


void
ngx_ssl_free_buffer(ngx_connection_t *c)
{
    if (c->ssl && c->ssl->buf && c->ssl->buf->start) {
        if (ngx_pfree(c->pool, c->ssl->buf->start) == NGX_OK) {
            c->ssl->buf->start = NULL;
        }
    }
}


ngx_int_t
ngx_ssl_shutdown(ngx_connection_t *c)
{
    int  rc;

    if (c->ssl == NULL) {
        return NGX_OK;
    }

    if (c->ssl->handshaked && c->ssl->connection) {
        rc = tls_shutdown(c->ssl->connection);
        if (rc != 1 && rc != TLS_ERROR_RECV_AGAIN
            && rc != TLS_ERROR_SEND_AGAIN && rc != TLS_ERROR_TCP_CLOSED)
        {
            ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
                          "GmSSL shutdown returned %d", rc);
        }
    }

    if (c->ssl->connection) {
        tls_cleanup(c->ssl->connection);
        c->ssl->connection = NULL;
    }
    c->ssl = NULL;
    return NGX_OK;
}


void
ngx_ssl_cleanup_ctx(void *data)
{
    ngx_ssl_t  *ssl = data;

    if (ssl->ctx) {
        tls_ctx_cleanup(ssl->ctx);
        ssl->ctx = NULL;
    }
}


void ngx_ssl_cleanup_connection(ngx_connection_t *c)
{
    if (c->ssl && c->ssl->connection) {
        tls_cleanup(c->ssl->connection);
        c->ssl->connection = NULL;
    }
}


ngx_int_t ngx_ssl_check_host(ngx_connection_t *c, ngx_str_t *name)
{
    return NGX_OK;
}


ngx_int_t ngx_ssl_get_protocol(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s)
{
    const char  *p;

    p = tls_protocol_name(c->ssl->connection->protocol);
    s->len = ngx_strlen(p);
    s->data = (u_char *) p;
    return NGX_OK;
}


ngx_int_t ngx_ssl_get_cipher_name(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s)
{
    const char  *p;

    p = tls_cipher_suite_name(c->ssl->connection->cipher_suite);
    s->len = ngx_strlen(p);
    s->data = (u_char *) p;
    return NGX_OK;
}


static ngx_int_t ngx_gmssl_empty(ngx_pool_t *pool, ngx_str_t *s)
{
    s->len = 0;
    s->data = (u_char *) "";
    return NGX_OK;
}

ngx_int_t ngx_ssl_get_ciphers(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { return ngx_ssl_get_cipher_name(c, pool, s); }
ngx_int_t ngx_ssl_get_curve(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { return ngx_gmssl_empty(pool, s); }
ngx_int_t ngx_ssl_get_curves(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { return ngx_gmssl_empty(pool, s); }
ngx_int_t ngx_ssl_get_sigalg(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { return ngx_gmssl_empty(pool, s); }
ngx_int_t ngx_ssl_get_session_id(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { return ngx_gmssl_empty(pool, s); }
ngx_int_t ngx_ssl_get_session_reused(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { ngx_str_set(s, "."); return NGX_OK; }
ngx_int_t ngx_ssl_get_early_data(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { ngx_str_set(s, ""); return NGX_OK; }
ngx_int_t ngx_ssl_get_server_name(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { return ngx_gmssl_empty(pool, s); }
ngx_int_t ngx_ssl_get_ech_status(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { return ngx_gmssl_empty(pool, s); }
ngx_int_t ngx_ssl_get_ech_outer_server_name(ngx_connection_t *c,
    ngx_pool_t *pool, ngx_str_t *s) { return ngx_gmssl_empty(pool, s); }
ngx_int_t ngx_ssl_get_alpn_protocol(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { return ngx_gmssl_empty(pool, s); }
ngx_int_t ngx_ssl_get_raw_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { return ngx_gmssl_empty(pool, s); }
ngx_int_t ngx_ssl_get_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { return ngx_gmssl_empty(pool, s); }
ngx_int_t ngx_ssl_get_escaped_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { return ngx_gmssl_empty(pool, s); }
ngx_int_t ngx_ssl_get_subject_dn(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { return ngx_gmssl_empty(pool, s); }
ngx_int_t ngx_ssl_get_issuer_dn(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { return ngx_gmssl_empty(pool, s); }
ngx_int_t ngx_ssl_get_subject_dn_legacy(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { return ngx_gmssl_empty(pool, s); }
ngx_int_t ngx_ssl_get_issuer_dn_legacy(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { return ngx_gmssl_empty(pool, s); }
ngx_int_t ngx_ssl_get_serial_number(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { return ngx_gmssl_empty(pool, s); }
ngx_int_t ngx_ssl_get_fingerprint(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { return ngx_gmssl_empty(pool, s); }
ngx_int_t ngx_ssl_get_client_verify(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { ngx_str_set(s, "NONE"); return NGX_OK; }
ngx_int_t ngx_ssl_get_client_v_start(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { return ngx_gmssl_empty(pool, s); }
ngx_int_t ngx_ssl_get_client_v_end(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { return ngx_gmssl_empty(pool, s); }
ngx_int_t ngx_ssl_get_client_v_remain(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { return ngx_gmssl_empty(pool, s); }
ngx_int_t ngx_ssl_get_client_sigalg(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s) { return ngx_gmssl_empty(pool, s); }


void ngx_cdecl
ngx_ssl_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err, char *fmt, ...)
{
    va_list  args;
    u_char   errstr[NGX_MAX_CONF_ERRSTR], *p, *last;

    last = errstr + NGX_MAX_CONF_ERRSTR;

    va_start(args, fmt);
    p = ngx_vslprintf(errstr, last, fmt, args);
    va_end(args);

    ngx_log_error(level, log, err, "%*s", p - errstr, errstr);
}


void ngx_ssl_clear_error(ngx_log_t *log) { }


static void *
ngx_gmssl_create_conf(ngx_cycle_t *cycle)
{
    return NGX_CONF_UNSET_PTR;
}


static void
ngx_gmssl_exit(ngx_cycle_t *cycle)
{
    (void) tls_socket_lib_cleanup();
}


static ngx_int_t
ngx_gmssl_again(ngx_connection_t *c, int rc)
{
    if (rc == TLS_ERROR_RECV_AGAIN) {
        c->read->ready = 0;
        return NGX_AGAIN;
    }

    if (rc == TLS_ERROR_SEND_AGAIN) {
        c->write->ready = 0;
        return NGX_AGAIN;
    }

    return NGX_ERROR;
}


static int
ngx_gmssl_protocol(ngx_uint_t protocols, ngx_uint_t *protocol)
{
    ngx_uint_t  n;

    n = 0;

    if (protocols & NGX_SSL_TLCP) {
        *protocol = TLS_protocol_tlcp;
        n++;
    }

    if (protocols & NGX_SSL_TLSv1_2) {
        *protocol = TLS_protocol_tls12;
        n++;
    }

    if (protocols & NGX_SSL_TLSv1_3) {
        *protocol = TLS_protocol_tls13;
        n++;
    }

    return n == 1 ? NGX_OK : NGX_ERROR;
}


static ngx_int_t
ngx_gmssl_configure_ctx(ngx_ssl_t *ssl)
{
    int  protocol, mode;
    int  ciphers[4];
    int  groups[2];
    int  sigalgs[2];
    size_t ciphers_n;
    const char *pass;

    if (ssl->ctx->protocol) {
        return NGX_OK;
    }

    protocol = ssl->protocol;
    mode = ssl->client ? TLS_client_mode : TLS_server_mode;

    if (tls_ctx_init(ssl->ctx, protocol, mode) != 1) {
        return NGX_ERROR;
    }

    ciphers_n = 0;
    switch (protocol) {
    case TLS_protocol_tlcp:
        ciphers[ciphers_n++] = TLS_cipher_ecdhe_sm4_cbc_sm3;
        ciphers[ciphers_n++] = TLS_cipher_ecc_sm4_cbc_sm3;
        break;

    case TLS_protocol_tls12:
        ciphers[ciphers_n++] = TLS_cipher_ecdhe_sm4_cbc_sm3;
        break;

    case TLS_protocol_tls13:
        ciphers[ciphers_n++] = TLS_cipher_sm4_gcm_sm3;
        break;
    }

    if (ciphers_n
        && tls_ctx_set_cipher_suites(ssl->ctx, ciphers, ciphers_n) != 1)
    {
        return NGX_ERROR;
    }

    groups[0] = TLS_curve_sm2p256v1;
    if (tls_ctx_set_supported_groups(ssl->ctx, groups, 1) != 1) {
        return NGX_ERROR;
    }

    sigalgs[0] = TLS_sig_sm2sig_sm3;
    if (tls_ctx_set_signature_algorithms(ssl->ctx, sigalgs, 1) != 1) {
        return NGX_ERROR;
    }

    if (ssl->ca_certificate.len
        && tls_ctx_set_ca_certificates(ssl->ctx, (char *) ssl->ca_certificate.data,
                                       ssl->verify_depth
                                          ? ssl->verify_depth
                                          : TLS_DEFAULT_VERIFY_DEPTH) != 1)
    {
        return NGX_ERROR;
    }

    if (ssl->certificate.len == 0) {
        return NGX_OK;
    }

    pass = ssl->certificate_pass.len ? (char *) ssl->certificate_pass.data
                                     : NULL;

    if (protocol == TLS_protocol_tlcp) {
        if (tlcp_ctx_add_server_certificate_and_keys(ssl->ctx,
                (char *) ssl->certificate.data,
                (char *) ssl->certificate_key.data, pass) != 1)
        {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    if (tls_ctx_add_certificate_chain_and_key(ssl->ctx,
            (char *) ssl->certificate.data,
            (char *) ssl->certificate_key.data, pass) != 1)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_gmssl_set_str(ngx_pool_t *pool, ngx_str_t *dst, ngx_str_t *src)
{
    dst->len = src->len;
    dst->data = ngx_pnalloc(pool, src->len + 1);

    if (dst->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(dst->data, src->data, src->len);
    dst->data[src->len] = '\0';

    return NGX_OK;
}
