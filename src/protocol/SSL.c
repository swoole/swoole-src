/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.0 of the Apache license,    |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.apache.org/licenses/LICENSE-2.0.html                      |
 | If you did not receive a copy of the Apache2.0 license and are unable|
 | to obtain it through the world-wide-web, please send a note to       |
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#include "swoole.h"
#include "Connection.h"

#ifdef SW_USE_OPENSSL

static int openssl_init = 0;

static const SSL_METHOD *swSSL_get_method(int method);
static int swSSL_verify_callback(int ok, X509_STORE_CTX *x509_store);
static RSA* swSSL_rsa512_key_callback(SSL *ssl, int is_export, int key_length);
static int swSSL_set_dhparam(SSL_CTX* ssl_context);
static int swSSL_set_ecdh_curve(SSL_CTX* ssl_context);

#ifdef TLSEXT_TYPE_next_proto_neg
static int swSSL_npn_advertised(SSL *ssl, const uchar **out, uint32_t *outlen, void *arg);
#endif

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
static int swSSL_alpn_advertised(SSL *ssl, const uchar **out, uchar *outlen, const uchar *in, uint32_t inlen, void *arg);
#endif

static const SSL_METHOD *swSSL_get_method(int method)
{
    switch (method)
    {
#ifndef OPENSSL_NO_SSL3_METHOD
    case SW_SSLv3_METHOD:
        return SSLv3_method();
    case SW_SSLv3_SERVER_METHOD:
        return SSLv3_server_method();
    case SW_SSLv3_CLIENT_METHOD:
        return SSLv3_client_method();
#endif
    case SW_SSLv23_SERVER_METHOD:
        return SSLv23_server_method();
    case SW_SSLv23_CLIENT_METHOD:
        return SSLv23_client_method();
    case SW_TLSv1_METHOD:
        return TLSv1_method();
    case SW_TLSv1_SERVER_METHOD:
        return TLSv1_server_method();
    case SW_TLSv1_CLIENT_METHOD:
        return TLSv1_client_method();
#ifdef TLS1_1_VERSION
    case SW_TLSv1_1_METHOD:
        return TLSv1_1_method();
    case SW_TLSv1_1_SERVER_METHOD:
        return TLSv1_1_server_method();
    case SW_TLSv1_1_CLIENT_METHOD:
        return TLSv1_1_client_method();
#endif
#ifdef TLS1_2_VERSION
    case SW_TLSv1_2_METHOD:
        return TLSv1_2_method();
    case SW_TLSv1_2_SERVER_METHOD:
        return TLSv1_2_server_method();
    case SW_TLSv1_2_CLIENT_METHOD:
        return TLSv1_2_client_method();
#endif
    case SW_DTLSv1_METHOD:
        return DTLSv1_method();
    case SW_DTLSv1_SERVER_METHOD:
        return DTLSv1_server_method();
    case SW_DTLSv1_CLIENT_METHOD:
        return DTLSv1_client_method();
    case SW_SSLv23_METHOD:
    default:
        return SSLv23_method();
    }
    return SSLv23_method();
}

void swSSL_init(void)
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    openssl_init = 1;
}

void swSSL_server_http_advise(SSL_CTX* ssl_context, swSSL_config *cfg)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
    SSL_CTX_set_alpn_select_cb(ssl_context, swSSL_alpn_advertised, cfg);
#endif

#ifdef TLSEXT_TYPE_next_proto_neg
    SSL_CTX_set_next_protos_advertised_cb(ssl_context, swSSL_npn_advertised, cfg);
#endif

    if (cfg->http)
    {
        SSL_CTX_set_session_id_context(ssl_context, (const unsigned char *) "HTTP", strlen("HTTP"));
        SSL_CTX_set_session_cache_mode(ssl_context, SSL_SESS_CACHE_SERVER);
        SSL_CTX_sess_set_cache_size(ssl_context, 1);
    }
}

int swSSL_server_set_cipher(SSL_CTX* ssl_context, swSSL_config *cfg)
{
#ifndef TLS1_2_VERSION
    return SW_OK;
#endif
    SSL_CTX_set_read_ahead(ssl_context, 1);

    if (strlen(cfg->ciphers) > 0)
    {
        if (SSL_CTX_set_cipher_list(ssl_context, cfg->ciphers) == 0)
        {
            swWarn("SSL_CTX_set_cipher_list(\"%s\") failed", cfg->ciphers);
            return SW_ERR;
        }
        if (cfg->prefer_server_ciphers)
        {
            SSL_CTX_set_options(ssl_context, SSL_OP_CIPHER_SERVER_PREFERENCE);
        }
    }

#ifndef LIBRESSL_VERSION_NUMBER
    SSL_CTX_set_tmp_rsa_callback(ssl_context, swSSL_rsa512_key_callback);
#endif

    if (strlen(cfg->ecdh_curve) > 0)
    {
        swSSL_set_dhparam(ssl_context);
        swSSL_set_ecdh_curve(ssl_context);
    }
    return SW_OK;
}

SSL_CTX* swSSL_get_context(int method, char *cert_file, char *key_file)
{
    if (!openssl_init)
    {
        swSSL_init();
    }

    SSL_CTX *ssl_context = SSL_CTX_new(swSSL_get_method(method));
    if (ssl_context == NULL)
    {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    SSL_CTX_set_options(ssl_context, SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG);
    SSL_CTX_set_options(ssl_context, SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER);
    SSL_CTX_set_options(ssl_context, SSL_OP_MSIE_SSLV2_RSA_PADDING);
    SSL_CTX_set_options(ssl_context, SSL_OP_SSLEAY_080_CLIENT_DH_BUG);
    SSL_CTX_set_options(ssl_context, SSL_OP_TLS_D5_BUG);
    SSL_CTX_set_options(ssl_context, SSL_OP_TLS_BLOCK_PADDING_BUG);
    SSL_CTX_set_options(ssl_context, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
    SSL_CTX_set_options(ssl_context, SSL_OP_SINGLE_DH_USE);

    if (cert_file)
    {
        /*
         * set the local certificate from CertFile
         */
        if (SSL_CTX_use_certificate_file(ssl_context, cert_file, SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            return NULL;
        }
        /*
         * if the crt file have many certificate entry ,means certificate chain
         * we need call this function
         */
        if (SSL_CTX_use_certificate_chain_file(ssl_context, cert_file) <= 0)
        {
            ERR_print_errors_fp(stderr);
            return NULL;
        }
        /*
         * set the private key from KeyFile (may be the same as CertFile)
         */
        if (SSL_CTX_use_PrivateKey_file(ssl_context, key_file, SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            return NULL;
        }
        /*
         * verify private key
         */
        if (!SSL_CTX_check_private_key(ssl_context))
        {
            swWarn("Private key does not match the public certificate");
            return NULL;
        }
    }

    return ssl_context;
}

static int swSSL_verify_callback(int ok, X509_STORE_CTX *x509_store)
{
#if 0
    char *subject, *issuer;
    int err, depth;
    X509 *cert;
    X509_NAME *sname, *iname;
    X509_STORE_CTX_get_ex_data(x509_store, SSL_get_ex_data_X509_STORE_CTX_idx());
    cert = X509_STORE_CTX_get_current_cert(x509_store);
    err = X509_STORE_CTX_get_error(x509_store);
    depth = X509_STORE_CTX_get_error_depth(x509_store);

    sname = X509_get_subject_name(cert);
    subject = sname ? X509_NAME_oneline(sname, NULL, 0) : "(none)";

    iname = X509_get_issuer_name(cert);
    issuer = iname ? X509_NAME_oneline(iname, NULL, 0) : "(none)";
    swWarn("verify:%d, error:%d, depth:%d, subject:\"%s\", issuer:\"%s\"", ok, err, depth, subject, issuer);

    if (sname)
    {
        OPENSSL_free(subject);
    }
    if (iname)
    {
        OPENSSL_free(issuer);
    }
#endif

    return 1;
}

int swSSL_set_client_certificate(SSL_CTX *ctx, char *cert_file, int depth)
{
    STACK_OF(X509_NAME) *list;

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, swSSL_verify_callback);
    SSL_CTX_set_verify_depth(ctx, depth);

    if (SSL_CTX_load_verify_locations(ctx, cert_file, NULL) == 0)
    {
        swWarn("SSL_CTX_load_verify_locations(\"%s\") failed.", cert_file);
        return SW_ERR;
    }

    ERR_clear_error();
    list = SSL_load_client_CA_file(cert_file);
    if (list == NULL)
    {
        swWarn("SSL_load_client_CA_file(\"%s\") failed.", cert_file);
        return SW_ERR;
    }

    ERR_clear_error();
    SSL_CTX_set_client_CA_list(ctx, list);

    return SW_OK;
}

int swSSL_verify(swConnection *conn, int allow_self_signed)
{
    int err = SSL_get_verify_result(conn->ssl);
    switch (err)
    {
    case X509_V_OK:
        return SW_OK;
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        if (allow_self_signed)
        {
            return SW_OK;
        }
        else
        {
            return SW_ERR;
        }
    default:
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SSL_VEFIRY_FAILED, "Could not verify peer: code:%d %s", err, X509_verify_cert_error_string(err));
        return SW_ERR;
    }

    return SW_ERR;
}

int swSSL_get_client_certificate(SSL *ssl, char *buffer, size_t length)
{
    long len;
    BIO *bio;
    X509 *cert;

    cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL)
    {
        return SW_ERR;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
    {
        swWarn("BIO_new() failed.");
        X509_free(cert);
        return SW_ERR;
    }

    if (PEM_write_bio_X509(bio, cert) == 0)
    {
        swWarn("PEM_write_bio_X509() failed.");
        goto failed;
    }

    len = BIO_pending(bio);
    if (len < 0 && len > length)
    {
        swWarn("certificate length[%ld] is too big.", len);
        goto failed;
    }

    int n = BIO_read(bio, buffer, len);

    BIO_free(bio);
    X509_free(cert);

    return n;

    failed:

    BIO_free(bio);
    X509_free(cert);

    return SW_ERR;
}

int swSSL_accept(swConnection *conn)
{
    int n = SSL_do_handshake(conn->ssl);
    if (n == 1)
    {
        conn->ssl_state = SW_SSL_STATE_READY;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifdef SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS
        if (conn->ssl->s3)
        {
            conn->ssl->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
        }
#endif
#endif
        return SW_READY;
    }
    long err = SSL_get_error(conn->ssl, n);
    if (err == SSL_ERROR_WANT_READ)
    {
        return SW_WAIT;
    }
    else if (err == SSL_ERROR_WANT_WRITE)
    {
        return SW_WAIT;
    }
    else if (err == SSL_ERROR_SSL)
    {
        swWarn("bad SSL client[%s:%d].", swConnection_get_ip(conn), swConnection_get_port(conn));
        return SW_ERROR;
    }
    //EOF was observed
    else if (err == SSL_ERROR_SYSCALL && n == 0)
    {
        return SW_ERROR;
    }
    err = ERR_GET_REASON(ERR_peek_error());
    swWarn("SSL_do_handshake() failed. Error: %s[%ld]", ERR_reason_error_string(err), err);
    return SW_ERROR;
}

int swSSL_connect(swConnection *conn)
{
    int n = SSL_connect(conn->ssl);
    if (n == 1)
    {
        conn->ssl_state = SW_SSL_STATE_READY;
        conn->ssl_want_read = 0;
        conn->ssl_want_write = 0;
        return SW_OK;
    }

    long err = SSL_get_error(conn->ssl, n);
    if (err == SSL_ERROR_WANT_READ)
    {
        conn->ssl_want_read = 1;
        conn->ssl_want_write = 0;
        conn->ssl_state = SW_SSL_STATE_WAIT_STREAM;
        return SW_OK;
    }
    else if (err == SSL_ERROR_WANT_WRITE)
    {
        conn->ssl_want_read = 0;
        conn->ssl_want_write = 1;
        conn->ssl_state = SW_SSL_STATE_WAIT_STREAM;
        return SW_OK;
    }
    swWarn("SSL_connect() failed. Error: %s[%ld]", ERR_reason_error_string(err), err);
    return SW_ERR;
}

void swSSL_close(swConnection *conn)
{
    SSL_set_quiet_shutdown(conn->ssl, 1);
    SSL_set_shutdown(conn->ssl, SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);

    SSL_shutdown(conn->ssl);
    SSL_free(conn->ssl);
    conn->ssl = NULL;
}

ssize_t swSSL_recv(swConnection *conn, void *__buf, size_t __n)
{
    int n = SSL_read(conn->ssl, __buf, __n);
    if (n < 0)
    {
        int _errno = SSL_get_error(conn->ssl, n);
        switch (_errno)
        {
        case SSL_ERROR_WANT_READ:
            conn->ssl_want_read = 1;
            errno = EAGAIN;
            return SW_ERR;
            break;

        case SSL_ERROR_WANT_WRITE:
            conn->ssl_want_write = 1;
            errno = EAGAIN;
            return SW_ERR;

        case SSL_ERROR_SSL:
            n = ERR_GET_REASON(ERR_peek_error());
            swWarn("SSL_read(%d, %ld) failed, Reason: %s[%d].", conn->fd, __n, ERR_reason_error_string((ulong_t )n), n);
            errno = SW_ERROR_SSL_BAD_CLIENT;
            return SW_ERR;

        case SSL_ERROR_SYSCALL:
            return SW_ERR;

        default:
            swWarn("SSL_read(%d, %ld) failed, errno=%d.", conn->fd, __n, _errno);
            return SW_ERR;
        }
    }
    return n;
}

ssize_t swSSL_send(swConnection *conn, void *__buf, size_t __n)
{
    int n = SSL_write(conn->ssl, __buf, __n);
    if (n < 0)
    {
        switch (SSL_get_error(conn->ssl, n))
        {
        case SSL_ERROR_WANT_READ:
            conn->ssl_want_read = 1;
            errno = EAGAIN;
            return SW_ERR;
            break;

        case SSL_ERROR_WANT_WRITE:
            conn->ssl_want_write = 1;
            errno = EAGAIN;
            return SW_ERR;

        case SSL_ERROR_SSL:
            n = ERR_GET_REASON(ERR_peek_error());
            swWarn("SSL_write(%d, %ld) failed, Reason: %s[%d].", conn->fd, __n, ERR_reason_error_string((ulong_t )n), n);
            errno = SW_ERROR_SSL_BAD_CLIENT;
            return SW_ERR;

        default:
            return SW_ERR;
        }
    }
    return n;
}

int swSSL_create(swConnection *conn, SSL_CTX* ssl_context, int flags)
{
    SSL *ssl = SSL_new(ssl_context);
    if (ssl == NULL)
    {
        swWarn("SSL_new() failed.");
        return SW_ERR;
    }
    if (!SSL_set_fd(ssl, conn->fd))
    {
        long err = ERR_get_error();
        swWarn("SSL_set_fd() failed. Error: %s[%ld]", ERR_reason_error_string(err), err);
        return SW_ERR;
    }
    if (flags & SW_SSL_CLIENT)
    {
        SSL_set_connect_state(ssl);
    }
    else
    {
        SSL_set_accept_state(ssl);
    }
    conn->ssl = ssl;
    conn->ssl_state = 0;
    return SW_OK;
}

void swSSL_free_context(SSL_CTX* ssl_context)
{
    if (ssl_context)
    {
        SSL_CTX_free(ssl_context);
    }
}

static RSA* swSSL_rsa512_key_callback(SSL *ssl, int is_export, int key_length)
{
    static RSA *key;
    if (key_length == 512)
    {
        if (key == NULL)
        {
            key = RSA_generate_key(512, RSA_F4, NULL, NULL);
        }
    }
    return key;
}

static int swSSL_set_dhparam(SSL_CTX* ssl_context)
{
    DH *dh;
    static unsigned char dh1024_p[] =
    { 0xBB, 0xBC, 0x2D, 0xCA, 0xD8, 0x46, 0x74, 0x90, 0x7C, 0x43, 0xFC, 0xF5, 0x80, 0xE9, 0xCF, 0xDB, 0xD9, 0x58, 0xA3,
            0xF5, 0x68, 0xB4, 0x2D, 0x4B, 0x08, 0xEE, 0xD4, 0xEB, 0x0F, 0xB3, 0x50, 0x4C, 0x6C, 0x03, 0x02, 0x76, 0xE7,
            0x10, 0x80, 0x0C, 0x5C, 0xCB, 0xBA, 0xA8, 0x92, 0x26, 0x14, 0xC5, 0xBE, 0xEC, 0xA5, 0x65, 0xA5, 0xFD, 0xF1,
            0xD2, 0x87, 0xA2, 0xBC, 0x04, 0x9B, 0xE6, 0x77, 0x80, 0x60, 0xE9, 0x1A, 0x92, 0xA7, 0x57, 0xE3, 0x04, 0x8F,
            0x68, 0xB0, 0x76, 0xF7, 0xD3, 0x6C, 0xC8, 0xF2, 0x9B, 0xA5, 0xDF, 0x81, 0xDC, 0x2C, 0xA7, 0x25, 0xEC, 0xE6,
            0x62, 0x70, 0xCC, 0x9A, 0x50, 0x35, 0xD8, 0xCE, 0xCE, 0xEF, 0x9E, 0xA0, 0x27, 0x4A, 0x63, 0xAB, 0x1E, 0x58,
            0xFA, 0xFD, 0x49, 0x88, 0xD0, 0xF6, 0x5D, 0x14, 0x67, 0x57, 0xDA, 0x07, 0x1D, 0xF0, 0x45, 0xCF, 0xE1, 0x6B,
            0x9B };

    static unsigned char dh1024_g[] =
    { 0x02 };
    dh = DH_new();
    if (dh == NULL)
    {
        swWarn("DH_new() failed");
        return SW_ERR;
    }

    dh->p = BN_bin2bn(dh1024_p, sizeof(dh1024_p), NULL);
    dh->g = BN_bin2bn(dh1024_g, sizeof(dh1024_g), NULL);

    if (dh->p == NULL || dh->g == NULL)
    {
        DH_free(dh);
    }
    SSL_CTX_set_tmp_dh(ssl_context, dh);
    DH_free(dh);
    return SW_OK;
}

static int swSSL_set_ecdh_curve(SSL_CTX* ssl_context)
{
#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH

    EC_KEY *ecdh;
    /*
     * Elliptic-Curve Diffie-Hellman parameters are either "named curves"
     * from RFC 4492 section 5.1.1, or explicitly described curves over
     * binary fields. OpenSSL only supports the "named curves", which provide
     * maximum interoperability.
     */
    int nid = OBJ_sn2nid(SW_SSL_ECDH_CURVE);
    if (nid == 0)
    {
        swWarn("Unknown curve name \"%s\"", SW_SSL_ECDH_CURVE);
        return SW_ERR;
    }

    ecdh = EC_KEY_new_by_curve_name(nid);
    if (ecdh == NULL)
    {
        swWarn("Unable to create curve \"%s\"", SW_SSL_ECDH_CURVE);
        return SW_ERR;
    }

    SSL_CTX_set_options(ssl_context, SSL_OP_SINGLE_ECDH_USE);
    SSL_CTX_set_tmp_ecdh(ssl_context, ecdh);

    EC_KEY_free(ecdh);
#endif
#endif

    return SW_OK;
}

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

static int swSSL_alpn_advertised(SSL *ssl, const uchar **out, uchar *outlen, const uchar *in, uint32_t inlen, void *arg)
{
    unsigned int srvlen;
    unsigned char *srv;

#ifdef SW_USE_HTTP2
    swSSL_config *cfg = arg;
    if (cfg->http_v2)
    {
        srv = (unsigned char *) SW_SSL_HTTP2_NPN_ADVERTISE SW_SSL_NPN_ADVERTISE;
        srvlen = sizeof (SW_SSL_HTTP2_NPN_ADVERTISE SW_SSL_NPN_ADVERTISE) - 1;
    }
    else
#endif
    {
        srv = (unsigned char *) SW_SSL_NPN_ADVERTISE;
        srvlen = sizeof (SW_SSL_NPN_ADVERTISE) - 1;
    }
    if (SSL_select_next_proto((unsigned char **) out, outlen, srv, srvlen, in, inlen) != OPENSSL_NPN_NEGOTIATED)
    {
        return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}
#endif

#ifdef TLSEXT_TYPE_next_proto_neg

static int swSSL_npn_advertised(SSL *ssl, const uchar **out, uint32_t *outlen, void *arg)
{
#ifdef SW_USE_HTTP2
    swSSL_config *cfg = arg;
    if (cfg->http_v2)
    {
        *out = (uchar *) SW_SSL_HTTP2_NPN_ADVERTISE SW_SSL_NPN_ADVERTISE;
        *outlen = sizeof (SW_SSL_HTTP2_NPN_ADVERTISE SW_SSL_NPN_ADVERTISE) - 1;
    }
    else
#endif
    {
        *out = (uchar *) SW_SSL_NPN_ADVERTISE;
        *outlen = sizeof(SW_SSL_NPN_ADVERTISE) - 1;
    }
    return SSL_TLSEXT_ERR_OK;
}
#endif

#endif
