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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#ifndef SW_CONNECTION_H_
#define SW_CONNECTION_H_

#include "swoole.h"

SW_EXTERN_C_BEGIN

#ifdef SW_USE_OPENSSL

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/ossl_typ.h>

enum swSSL_create_flag {
    SW_SSL_SERVER = 1,
    SW_SSL_CLIENT = 2,
};

typedef struct _swSSL_option {
    char *cert_file;
    char *key_file;
    char *passphrase;
    char *client_cert_file;
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    uchar disable_tls_host_name : 1;
    char *tls_host_name;
#endif
    char *cafile;
    char *capath;
    uint8_t verify_depth;
    uint8_t method;
#ifdef SW_SUPPORT_DTLS
    uint8_t dtls;
#endif
    uchar disable_compress : 1;
    uchar verify_peer : 1;
    uchar allow_self_signed : 1;
    uint32_t disable_protocols;
} swSSL_option;

enum swSSL_state {
    SW_SSL_STATE_HANDSHAKE = 0,
    SW_SSL_STATE_READY = 1,
    SW_SSL_STATE_WAIT_STREAM = 2,
};

enum swSSL_version {
    SW_SSL_SSLv2 = 0x0002,
    SW_SSL_SSLv3 = 0x0004,
    SW_SSL_TLSv1 = 0x0008,
    SW_SSL_TLSv1_1 = 0x0010,
    SW_SSL_TLSv1_2 = 0x0020,
};

enum swSSL_method {
    SW_SSLv23_METHOD = 0,
    SW_SSLv3_METHOD,
    SW_SSLv3_SERVER_METHOD,
    SW_SSLv3_CLIENT_METHOD,
    SW_SSLv23_SERVER_METHOD,
    SW_SSLv23_CLIENT_METHOD,
    SW_TLSv1_METHOD,
    SW_TLSv1_SERVER_METHOD,
    SW_TLSv1_CLIENT_METHOD,
#ifdef TLS1_1_VERSION
    SW_TLSv1_1_METHOD,
    SW_TLSv1_1_SERVER_METHOD,
    SW_TLSv1_1_CLIENT_METHOD,
#endif
#ifdef TLS1_2_VERSION
    SW_TLSv1_2_METHOD,
    SW_TLSv1_2_SERVER_METHOD,
    SW_TLSv1_2_CLIENT_METHOD,
#endif
#ifdef SW_SUPPORT_DTLS
    SW_DTLS_CLIENT_METHOD,
    SW_DTLS_SERVER_METHOD,
#endif
};

typedef struct {
    uchar http : 1;
    uchar http_v2 : 1;
    uchar prefer_server_ciphers : 1;
    uchar session_tickets : 1;
    uchar stapling : 1;
    uchar stapling_verify : 1;
    char *ciphers;
    char *ecdh_curve;
    char *session_cache;
    char *dhparam;
} swSSL_config;

void swSSL_init(void);
void swSSL_init_thread_safety();
int swSSL_server_set_cipher(SSL_CTX *ssl_context, swSSL_config *cfg);
void swSSL_server_http_advise(SSL_CTX *ssl_context, swSSL_config *cfg);
SSL_CTX *swSSL_get_context(swSSL_option *option);
void swSSL_free_context(SSL_CTX *ssl_context);
int swSSL_create(swSocket *conn, SSL_CTX *ssl_context, int flags);
int swSSL_set_client_certificate(SSL_CTX *ctx, char *cert_file, int depth);
int swSSL_set_capath(swSSL_option *cfg, SSL_CTX *ctx);
int swSSL_check_host(swSocket *conn, char *tls_host_name);
int swSSL_get_peer_cert(SSL *ssl, char *buffer, size_t length);
const char *swSSL_get_error();
int swSSL_verify(swSocket *conn, int allow_self_signed);
enum swReturn_code swSSL_accept(swSocket *conn);
int swSSL_connect(swSocket *conn);
void swSSL_close(swSocket *conn);
ssize_t swSSL_recv(swSocket *conn, void *__buf, size_t __n);
ssize_t swSSL_send(swSocket *conn, const void *__buf, size_t __n);
int swSSL_sendfile(swSocket *conn, int fd, off_t *offset, size_t size);
#endif

SW_EXTERN_C_END

#endif /* SW_CONNECTION_H_ */
