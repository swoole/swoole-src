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

static const SSL_METHOD *swSSL_get_method(int method)
{
    switch (method)
    {
    case SW_SSLv3_METHOD:
        return SSLv3_method();
    case SW_SSLv3_SERVER_METHOD:
        return SSLv3_server_method();
    case SW_SSLv3_CLIENT_METHOD:
        return SSLv3_client_method();
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
    case SW_TLSv1_1_METHOD:
        return TLSv1_1_method();
    case SW_TLSv1_1_SERVER_METHOD:
        return TLSv1_1_server_method();
    case SW_TLSv1_1_CLIENT_METHOD:
        return TLSv1_1_client_method();
    case SW_TLSv1_2_METHOD:
        return TLSv1_2_method();
    case SW_TLSv1_2_SERVER_METHOD:
        return TLSv1_2_server_method();
    case SW_TLSv1_2_CLIENT_METHOD:
        return TLSv1_2_client_method();
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

int swSSL_get_client_certificate(SSL *ssl, char *buffer, size_t length)
{
    size_t len;
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
        if (conn->ssl->s3)
        {
            conn->ssl->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
        }
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
        swWarn("bad SSL client[%s:%d] .", swConnection_get_ip(conn), swConnection_get_port(conn));
        return SW_ERROR;
    }
    else if (err == SSL_ERROR_SYSCALL)
    {
        swSysError("SSL error syscall.");
        return SW_ERROR;
    }
    swWarn("swSSL_accept() failed. Error: %s[%ld]", ERR_reason_error_string(err), err);
    return SW_ERROR;
}

int swSSL_connect(swConnection *conn)
{
    int n = SSL_connect(conn->ssl);
    if (n == 1)
    {
        conn->ssl_state = 1;
        return SW_OK;
    }
    long err = SSL_get_error(conn->ssl, n);
    if (err == SSL_ERROR_WANT_READ)
    {
        return SW_OK;
    }
    else if (err == SSL_ERROR_WANT_WRITE)
    {
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

#endif
