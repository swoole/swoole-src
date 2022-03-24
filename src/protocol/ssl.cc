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
 | Author: Tianfeng Han  <rango@swoole.com>                             |
 +----------------------------------------------------------------------+
 */

#include "swoole.h"
#include "swoole_string.h"
#include "swoole_socket.h"
#include "swoole_ssl.h"
#include "swoole_util.h"

#ifdef SW_USE_OPENSSL

using swoole::SSLContext;
using swoole::network::Address;
using swoole::network::Socket;

#if OPENSSL_VERSION_NUMBER < 0x10000000L
#error "require openssl version 1.0 or later"
#endif

static bool openssl_init = false;
static bool openssl_thread_safety_init = false;
static int ssl_connection_index = 0;
static int ssl_port_index = 0;
static pthread_mutex_t *lock_array;

static int swoole_ssl_verify_callback(int ok, X509_STORE_CTX *x509_store);
#ifndef OPENSSL_NO_RSA
static RSA *swoole_ssl_rsa_key_callback(SSL *ssl, int is_export, int key_length);
#endif
#if OPENSSL_VERSION_NUMBER < 0x10100000L
static int swoole_ssl_set_default_dhparam(SSL_CTX *ssl_context);
#endif

#ifdef SW_SUPPORT_DTLS
static int swoole_ssl_generate_cookie(SSL *ssl, uchar *cookie, uint *cookie_len);
static int swoole_ssl_verify_cookie(SSL *ssl, const uchar *cookie, uint cookie_len);
#endif

#ifdef __GNUC__
#define MAYBE_UNUSED __attribute__((used))
#else
#define MAYBE_UNUSED
#endif

std::string swoole_ssl_get_version_message() {
    return swoole::std_string::format("OPENSSL_VERSION: %s\n", OPENSSL_VERSION_TEXT);
}

static void MAYBE_UNUSED swoole_ssl_lock_callback(int mode, int type, const char *file, int line);

void swoole_ssl_init(void) {
    if (openssl_init) {
        return;
    }
#if OPENSSL_VERSION_NUMBER >= 0x10100003L && !defined(LIBRESSL_VERSION_NUMBER)
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
                     nullptr);
#else
    OPENSSL_config(nullptr);
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#endif

    ssl_connection_index = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    if (ssl_connection_index < 0) {
        swoole_error("SSL_get_ex_new_index() failed");
        return;
    }

    ssl_port_index = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    if (ssl_port_index < 0) {
        swoole_error("SSL_get_ex_new_index() failed");
        return;
    }

    openssl_init = true;
}

int swoole_ssl_get_ex_connection_index() {
    return ssl_connection_index;
}

int swoole_ssl_get_ex_port_index() {
    return ssl_port_index;
}

void swoole_ssl_destroy() {
    if (!openssl_init) {
        return;
    }

    SW_LOOP_N(CRYPTO_num_locks()) {
        pthread_mutex_destroy(&(lock_array[i]));
    }

    OPENSSL_free(lock_array);

#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_0_0
    (void) CRYPTO_THREADID_set_callback(nullptr);
#else
    CRYPTO_set_id_callback(nullptr);
#endif
    CRYPTO_set_locking_callback(nullptr);
    openssl_init = false;
    openssl_thread_safety_init = false;
}

static void MAYBE_UNUSED swoole_ssl_lock_callback(int mode, int type, const char *file, int line) {
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&(lock_array[type]));
    } else {
        pthread_mutex_unlock(&(lock_array[type]));
    }
}

static int ssl_error_cb(const char *str, size_t len, void *buf) {
    memcpy(buf, str, len);

    return 0;
}

const char *swoole_ssl_get_error() {
    ERR_print_errors_cb(ssl_error_cb, sw_tg_buffer()->str);

    return sw_tg_buffer()->str;
}

#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_0_0
static void MAYBE_UNUSED swoole_ssl_id_callback(CRYPTO_THREADID *id) {
    CRYPTO_THREADID_set_numeric(id, (ulong_t) pthread_self());
}
#else
static ulong_t swoole_ssl_id_callback(void) {
    return (ulong_t) pthread_self();
}
#endif

void swoole_ssl_init_thread_safety() {
    if (!openssl_init) {
        return;
    }

    if (openssl_thread_safety_init) {
        return;
    }

    lock_array = (pthread_mutex_t *) OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    SW_LOOP_N(CRYPTO_num_locks()) {
        pthread_mutex_init(&(lock_array[i]), nullptr);
    }

#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_0_0
    (void) CRYPTO_THREADID_set_callback(swoole_ssl_id_callback);
#else
    CRYPTO_set_id_callback(swoole_ssl_id_callback);
#endif

    CRYPTO_set_locking_callback(swoole_ssl_lock_callback);
    openssl_thread_safety_init = true;
}

bool swoole_ssl_is_thread_safety() {
    return openssl_thread_safety_init;
}

static void swoole_ssl_info_callback(const SSL *ssl, int where, int ret) {
    BIO *rbio, *wbio;
    swSocket *sock;

    if (where & SSL_CB_HANDSHAKE_START) {
        sock = (swSocket *) SSL_get_ex_data(ssl, ssl_connection_index);

        if (sock->ssl_state == SW_SSL_STATE_READY) {
            sock->ssl_renegotiation = 1;
            swoole_debug("SSL renegotiation");
        }
    }

    if ((where & SSL_CB_ACCEPT_LOOP) == SSL_CB_ACCEPT_LOOP) {
        sock = (swSocket *) SSL_get_ex_data(ssl, ssl_connection_index);

        if (!sock->ssl_handshake_buffer_set) {
            /*
             * By default OpenSSL uses 4k buffer during a handshake,
             * which is too low for long certificate chains and might
             * result in extra round-trips.
             *
             * To adjust a buffer size we detect that buffering was added
             * to write side of the connection by comparing rbio and wbio.
             * If they are different, we assume that it's due to buffering
             * added to wbio, and set buffer size.
             */

            rbio = SSL_get_rbio(ssl);
            wbio = SSL_get_wbio(ssl);

            if (rbio != wbio) {
                (void) BIO_set_write_buffer_size(wbio, SW_SSL_BUFFER_SIZE);
                sock->ssl_handshake_buffer_set = 1;
            }
        }
    }
}

namespace swoole {

#ifndef OPENSSL_NO_NEXTPROTONEG

#define HTTP2_H2_ALPN "\x02h2"
#define HTTP2_H2_16_ALPN "\x05h2-16"
#define HTTP2_H2_14_ALPN "\x05h2-14"
#define HTTP1_NPN "\x08http/1.1"

static bool ssl_select_proto(const uchar **out, uchar *outlen, const uchar *in, uint inlen, const std::string &key) {
    for (auto p = in, end = in + inlen; p + key.size() <= end; p += *p + 1) {
        if (std::equal(std::begin(key), std::end(key), p)) {
            *out = p + 1;
            *outlen = *p;
            return true;
        }
    }
    return false;
}

static bool ssl_select_h2(const uchar **out, uchar *outlen, const uchar *in, uint inlen) {
    return ssl_select_proto(out, outlen, in, inlen, HTTP2_H2_ALPN) ||
           ssl_select_proto(out, outlen, in, inlen, HTTP2_H2_16_ALPN) ||
           ssl_select_proto(out, outlen, in, inlen, HTTP2_H2_14_ALPN);
}

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
static int ssl_alpn_advertised(SSL *ssl, const uchar **out, uchar *outlen, const uchar *in, uint32_t inlen, void *arg) {
    unsigned int protos_len;
    const char *protos;

    SSLContext *cfg = (SSLContext *) arg;
    if (cfg->http_v2) {
        protos = HTTP2_H2_ALPN HTTP1_NPN;
        protos_len = sizeof(HTTP2_H2_ALPN HTTP1_NPN) - 1;
    } else {
        protos = HTTP1_NPN;
        protos_len = sizeof(HTTP1_NPN) - 1;
    }

    if (SSL_select_next_proto((unsigned char **) out, outlen, (const uchar *) protos, protos_len, in, inlen) !=
        OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}
#endif

static int ssl_select_next_proto_cb(SSL *ssl, uchar **out, uchar *outlen, const uchar *in, uint inlen, void *arg) {
#ifdef SW_LOG_TRACE_OPEN
    std::string info("[NPN] server offers:\n");
    for (unsigned int i = 0; i < inlen; i += in[i] + 1) {
        info += "        * " + std::string(reinterpret_cast<const char *>(&in[i + 1]), in[i]);
    }
    swoole_trace_log(SW_TRACE_HTTP2, "[NPN] server offers: %s", info.c_str());
#endif
    SSLContext *ctx = (SSLContext *) arg;
    if (ctx->http_v2 && !ssl_select_h2(const_cast<const unsigned char **>(out), outlen, in, inlen)) {
        swoole_warning("HTTP/2 protocol was not selected, expects [h2]");
        return SSL_TLSEXT_ERR_NOACK;
    } else if (ctx->http) {
        *out = (uchar *) HTTP1_NPN;
        *outlen = sizeof(HTTP1_NPN) - 1;
    }
    return SSL_TLSEXT_ERR_OK;
}
#endif

static int ssl_passwd_callback(char *buf, int num, int verify, void *data) {
    SSLContext *ctx = (SSLContext *) data;
    if (!ctx->passphrase.empty()) {
        int len = ctx->passphrase.length();
        if (len < num - 1) {
            memcpy(buf, ctx->passphrase.c_str(), len);
            buf[len] = '\0';
            return (int) len;
        }
    }
    return 0;
}

bool SSLContext::create() {
    if (!openssl_init) {
        swoole_ssl_init();
    }

    const SSL_METHOD *method;
#ifdef SW_SUPPORT_DTLS
    if (protocols & SW_SSL_DTLS) {
        method = DTLS_method();
    } else
#endif
    {
        method = SSLv23_method();
    }
    if (protocols == 0) {
        protocols = SW_SSL_ALL;
    }
    context = SSL_CTX_new(method);
    if (context == nullptr) {
        int error = ERR_get_error();
        swoole_warning("SSL_CTX_new() failed, Error: %s[%d]", ERR_reason_error_string(error), error);
        return false;
    }

#ifdef SSL_OP_MICROSOFT_SESS_ID_BUG
    SSL_CTX_set_options(context, SSL_OP_MICROSOFT_SESS_ID_BUG);
#endif

#ifdef SSL_OP_NETSCAPE_CHALLENGE_BUG
    SSL_CTX_set_options(context, SSL_OP_NETSCAPE_CHALLENGE_BUG);
#endif

    /* server side options */
#ifdef SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
    SSL_CTX_set_options(context, SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG);
#endif

#ifdef SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
    SSL_CTX_set_options(context, SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER);
#endif

#ifdef SSL_OP_MSIE_SSLV2_RSA_PADDING
    /* this option allow a potential SSL 2.0 rollback (CAN-2005-2969) */
    SSL_CTX_set_options(context, SSL_OP_MSIE_SSLV2_RSA_PADDING);
#endif

#ifdef SSL_OP_SSLEAY_080_CLIENT_DH_BUG
    SSL_CTX_set_options(context, SSL_OP_SSLEAY_080_CLIENT_DH_BUG);
#endif

#ifdef SSL_OP_TLS_D5_BUG
    SSL_CTX_set_options(context, SSL_OP_TLS_D5_BUG);
#endif

#ifdef SSL_OP_TLS_BLOCK_PADDING_BUG
    SSL_CTX_set_options(context, SSL_OP_TLS_BLOCK_PADDING_BUG);
#endif

#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    SSL_CTX_set_options(context, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x009080dfL
    /* only in 0.9.8m+ */
    SSL_CTX_clear_options(context, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
#endif

#ifdef SSL_OP_NO_SSLv2
    if (!(protocols & SW_SSL_SSLv2)) {
        SSL_CTX_set_options(context, SSL_OP_NO_SSLv2);
    }
#endif
#ifdef SSL_OP_NO_SSLv3
    if (!(protocols & SW_SSL_SSLv3)) {
        SSL_CTX_set_options(context, SSL_OP_NO_SSLv3);
    }
#endif
#ifdef SSL_OP_NO_TLSv1
    if (!(protocols & SW_SSL_TLSv1)) {
        SSL_CTX_set_options(context, SSL_OP_NO_TLSv1);
    }
#endif
#ifdef SSL_OP_NO_TLSv1_1
    SSL_CTX_clear_options(context, SSL_OP_NO_TLSv1_1);
    if (!(protocols & SW_SSL_TLSv1_1)) {
        SSL_CTX_set_options(context, SSL_OP_NO_TLSv1_1);
    }
#endif
#ifdef SSL_OP_NO_TLSv1_2
    SSL_CTX_clear_options(context, SSL_OP_NO_TLSv1_2);
    if (!(protocols & SW_SSL_TLSv1_2) && !(protocols & SW_SSL_DTLS)) {
        SSL_CTX_set_options(context, SSL_OP_NO_TLSv1_2);
    }
#endif
#ifdef SSL_OP_NO_TLSv1_3
    SSL_CTX_clear_options(context, SSL_OP_NO_TLSv1_3);
    if (!(protocols & SW_SSL_TLSv1_3)) {
        SSL_CTX_set_options(context, SSL_OP_NO_TLSv1_3);
    }
#endif

#ifdef SSL_OP_NO_COMPRESSION
    if (disable_compress) {
        SSL_CTX_set_options(context, SSL_OP_NO_COMPRESSION);
    }
#endif

#ifdef SSL_MODE_RELEASE_BUFFERS
    SSL_CTX_set_mode(context, SSL_MODE_RELEASE_BUFFERS);
#endif

#ifdef SSL_MODE_NO_AUTO_CHAIN
    SSL_CTX_set_mode(context, SSL_MODE_NO_AUTO_CHAIN);
#endif

    SSL_CTX_set_read_ahead(context, 1);
    SSL_CTX_set_info_callback(context, swoole_ssl_info_callback);

    if (!passphrase.empty()) {
        SSL_CTX_set_default_passwd_cb_userdata(context, this);
        SSL_CTX_set_default_passwd_cb(context, ssl_passwd_callback);
    }

    if (!cert_file.empty()) {
        /*
         * set the local certificate from CertFile
         */
        if (SSL_CTX_use_certificate_file(context, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
            int error = ERR_get_error();
            swoole_warning("SSL_CTX_use_certificate_file(%s) failed, Error: %s[%d]",
                           cert_file.c_str(),
                           ERR_reason_error_string(error),
                           error);
            return true;
        }
        /*
         * if the crt file have many certificate entry ,means certificate chain
         * we need call this function
         */
        if (SSL_CTX_use_certificate_chain_file(context, cert_file.c_str()) <= 0) {
            int error = ERR_get_error();
            swoole_warning("SSL_CTX_use_certificate_chain_file(%s) failed, Error: %s[%d]",
                           cert_file.c_str(),
                           ERR_reason_error_string(error),
                           error);
            return false;
        }
    }
    if (!key_file.empty()) {
        /*
         * set the private key from KeyFile (may be the same as CertFile)
         */
        if (SSL_CTX_use_PrivateKey_file(context, key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
            int error = ERR_get_error();
            swoole_warning("SSL_CTX_use_PrivateKey_file(%s) failed, Error: %s[%d]",
                           key_file.c_str(),
                           ERR_reason_error_string(error),
                           error);
            return false;
        }
        /*
         * verify private key
         */
        if (!SSL_CTX_check_private_key(context)) {
            swoole_warning("Private key does not match the public certificate");
            return false;
        }
    }

#ifdef SW_SUPPORT_DTLS
    if (protocols & SW_SSL_DTLS) {
#ifndef OPENSSL_IS_BORINGSSL
        SSL_CTX_set_cookie_generate_cb(context, swoole_ssl_generate_cookie);
        SSL_CTX_set_cookie_verify_cb(context, swoole_ssl_verify_cookie);
#endif
    }
#endif

    if (verify_peer && !set_capath()) {
        return false;
    } else {
        SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nullptr);
    }

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    if (http || http_v2) {
        unsigned int protos_len;
        const char *protos;
        if (http_v2) {
            protos = HTTP2_H2_ALPN HTTP1_NPN;
            protos_len = sizeof(HTTP2_H2_ALPN HTTP1_NPN) - 1;
        } else {
            protos = HTTP1_NPN;
            protos_len = sizeof(HTTP2_H2_ALPN HTTP1_NPN) - 1;
        }
#ifndef OPENSSL_NO_NEXTPROTONEG
        SSL_CTX_set_next_proto_select_cb(context, ssl_select_next_proto_cb, nullptr);
#endif
        if (SSL_CTX_set_alpn_protos(context, (const uchar *) protos, protos_len) < 0) {
            return false;
        }

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
        SSL_CTX_set_alpn_select_cb(context, ssl_alpn_advertised, (void *) this);
#endif

        SSL_CTX_set_session_id_context(context, (const unsigned char *) "HTTP", sizeof("HTTP") - 1);
        SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_SERVER);
        SSL_CTX_sess_set_cache_size(context, 1);
    }
#endif

#ifdef OPENSSL_IS_BORINGSSL
    SSL_CTX_set_grease_enabled(context, grease);
#endif

    if (!client_cert_file.empty() && !set_client_certificate()) {
        swoole_warning("set_client_certificate() error");
        return false;
    }

    if (!set_ciphers()) {
        swoole_warning("set_cipher() error");
        return false;
    }

    return true;
}

bool SSLContext::set_capath() {
    if (!cafile.empty() || !capath.empty()) {
        const char *_cafile = cafile.empty() ? nullptr : cafile.c_str();
        const char *_capath = capath.empty() ? nullptr : capath.c_str();
        if (!SSL_CTX_load_verify_locations(context, _cafile, _capath)) {
            return false;
        }
    } else {
        if (!SSL_CTX_set_default_verify_paths(context)) {
            swoole_warning("Unable to set default verify locations and no CA settings specified");
            return false;
        }
    }

    if (verify_depth > 0) {
        SSL_CTX_set_verify_depth(context, verify_depth);
    }

    return true;
}

bool SSLContext::set_ciphers() {
#ifndef TLS1_2_VERSION
    return true;
#endif

    if (!ciphers.empty()) {
        if (SSL_CTX_set_cipher_list(context, ciphers.c_str()) == 0) {
            swoole_warning("SSL_CTX_set_cipher_list(\"%s\") failed", ciphers.c_str());
            return false;
        }
        if (prefer_server_ciphers) {
            SSL_CTX_set_options(context, SSL_OP_CIPHER_SERVER_PREFERENCE);
        }
    }

#ifndef OPENSSL_NO_RSA
    SSL_CTX_set_tmp_rsa_callback(context, swoole_ssl_rsa_key_callback);
#endif

    if (!dhparam.empty() && !set_dhparam()) {
        return false;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    else {
        swoole_ssl_set_default_dhparam(context);
    }
#endif
    if (!ecdh_curve.empty() && !set_ecdh_curve()) {
        return false;
    }
    return true;
}

bool SSLContext::set_client_certificate() {
    STACK_OF(X509_NAME) * list;

    const char *cert_file = client_cert_file.c_str();
    int depth = verify_depth;

    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, swoole_ssl_verify_callback);
    SSL_CTX_set_verify_depth(context, depth);

    if (SSL_CTX_load_verify_locations(context, cert_file, nullptr) == 0) {
        swoole_warning("SSL_CTX_load_verify_locations(\"%s\") failed", cert_file);
        return false;
    }

    ERR_clear_error();
    list = SSL_load_client_CA_file(cert_file);
    if (list == nullptr) {
        swoole_warning("SSL_load_client_CA_file(\"%s\") failed", cert_file);
        return false;
    }

    ERR_clear_error();
    SSL_CTX_set_client_CA_list(context, list);

    return true;
}

bool SSLContext::set_ecdh_curve() {
#ifndef OPENSSL_NO_ECDH
    /*
     * Elliptic-Curve Diffie-Hellman parameters are either "named curves"
     * from RFC 4492 section 5.1.1, or explicitly described curves over
     * binary fields.  OpenSSL only supports the "named curves", which provide
     * maximum interoperability.
     */
#if (defined SSL_CTX_set1_curves_list || defined SSL_CTRL_SET_CURVES_LIST)
    /*
     * OpenSSL 1.0.2+ allows configuring a curve list instead of a single
     * curve previously supported.  By default an internal list is used,
     * with prime256v1 being preferred by server in OpenSSL 1.0.2b+
     * and X25519 in OpenSSL 1.1.0+.
     *
     * By default a curve preferred by the client will be used for
     * key exchange.  The SSL_OP_CIPHER_SERVER_PREFERENCE option can
     * be used to prefer server curves instead, similar to what it
     * does for ciphers.
     */
    SSL_CTX_set_options(context, SSL_OP_SINGLE_ECDH_USE);
#if SSL_CTRL_SET_ECDH_AUTO
    /* not needed in OpenSSL 1.1.0+ */
    SSL_CTX_set_ecdh_auto(context, 1);
#endif
    if (strcmp(ecdh_curve.c_str(), "auto") == 0) {
        return true;
    }
    if (SSL_CTX_set1_curves_list(context, ecdh_curve.c_str()) == 0) {
        swoole_warning("SSL_CTX_set1_curves_list(\"%s\") failed", ecdh_curve.c_str());
        return false;
    }
#else
    EC_KEY *ecdh;
    /*
     * Elliptic-Curve Diffie-Hellman parameters are either "named curves"
     * from RFC 4492 section 5.1.1, or explicitly described curves over
     * binary fields. OpenSSL only supports the "named curves", which provide
     * maximum interoperability.
     */
    int nid = OBJ_sn2nid(ecdh_curve.c_str());
    if (nid == 0) {
        swoole_warning("Unknown curve name \"%s\"", ecdh_curve.c_str());
        return false;
    }

    ecdh = EC_KEY_new_by_curve_name(nid);
    if (ecdh == nullptr) {
        swoole_warning("Unable to create curve \"%s\"", ecdh_curve.c_str());
        return false;
    }

    SSL_CTX_set_options(context, SSL_OP_SINGLE_ECDH_USE);
    SSL_CTX_set_tmp_ecdh(context, ecdh);

    EC_KEY_free(ecdh);
#endif
#endif

    return true;
}

bool SSLContext::set_dhparam() {
    DH *dh;
    BIO *bio;

    const char *file = dhparam.c_str();

    bio = BIO_new_file(file, "r");
    if (bio == nullptr) {
        swoole_warning("BIO_new_file(%s) failed", file);
        return false;
    }

    dh = PEM_read_bio_DHparams(bio, nullptr, nullptr, nullptr);
    if (dh == nullptr) {
        swoole_warning("PEM_read_bio_DHparams(%s) failed", file);
        BIO_free(bio);
        return false;
    }

    SSL_CTX_set_tmp_dh(context, dh);

    DH_free(dh);
    BIO_free(bio);

    return true;
}

SSLContext::~SSLContext() {
    SSL_CTX_free(context);
}

}  // namespace swoole

static int swoole_ssl_verify_callback(int ok, X509_STORE_CTX *x509_store) {
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
    subject = sname ? X509_NAME_oneline(sname, nullptr, 0) : "(none)";

    iname = X509_get_issuer_name(cert);
    issuer = iname ? X509_NAME_oneline(iname, nullptr, 0) : "(none)";
    swoole_warning("verify:%d, error:%d, depth:%d, subject:\"%s\", issuer:\"%s\"", ok, err, depth, subject, issuer);

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

#ifdef SW_SUPPORT_DTLS

#define COOKIE_SECRET_LENGTH (32)

static void calculate_cookie(SSL *ssl, uchar *cookie_secret, uint cookie_length) {
    long rv = (long) ssl;
    long inum = (cookie_length - (((long) cookie_secret) % sizeof(long))) / sizeof(long);
    long i = 0;
    long *ip = (long *) cookie_secret;
    for (i = 0; i < inum; ++i, ++ip) {
        *ip = rv;
    }
}

static int swoole_ssl_generate_cookie(SSL *ssl, uchar *cookie, uint *cookie_len) {
    uchar *buffer, result[EVP_MAX_MD_SIZE];
    uint length = 0, result_len;
    Address sa{};

    uchar cookie_secret[COOKIE_SECRET_LENGTH];
    calculate_cookie(ssl, cookie_secret, sizeof(cookie_secret));

    /* Read peer information */
    (void) BIO_dgram_get_peer(SSL_get_wbio(ssl), &sa);

    length = 0;
    switch (sa.addr.ss.sa_family) {
    case AF_INET:
        length += sizeof(struct in_addr);
        break;
    case AF_INET6:
        length += sizeof(struct in6_addr);
        break;
    default:
        OPENSSL_assert(0);
        break;
    }

    length += sizeof(in_port_t);
    buffer = (uchar *) OPENSSL_malloc(length);

    if (buffer == nullptr) {
        swoole_sys_warning("out of memory");
        return 0;
    }

    switch (sa.addr.ss.sa_family) {
    case AF_INET:
        memcpy(buffer, &sa.addr.inet_v4.sin_port, sizeof(in_port_t));
        memcpy(buffer + sizeof(sa.addr.inet_v4.sin_port), &sa.addr.inet_v4.sin_addr, sizeof(struct in_addr));
        break;
    case AF_INET6:
        memcpy(buffer, &sa.addr.inet_v6.sin6_port, sizeof(in_port_t));
        memcpy(buffer + sizeof(in_port_t), &sa.addr.inet_v6.sin6_addr, sizeof(struct in6_addr));
        break;
    default:
        OPENSSL_assert(0);
        break;
    }

    HMAC(EVP_sha1(), (const void *) cookie_secret, COOKIE_SECRET_LENGTH, buffer, length, result, &result_len);
    OPENSSL_free(buffer);

    memcpy(cookie, result, result_len);
    *cookie_len = result_len;

    return 1;
}

static int swoole_ssl_verify_cookie(SSL *ssl, const uchar *cookie, uint cookie_len) {
    uint result_len = 0;
    uchar result[COOKIE_SECRET_LENGTH];

    swoole_ssl_generate_cookie(ssl, result, &result_len);

    return cookie_len == result_len && memcmp(result, cookie, result_len) == 0;
}
#endif

#ifndef OPENSSL_NO_RSA
static RSA *swoole_ssl_rsa_key_callback(SSL *ssl, int is_export, int key_length) {
    static RSA *rsa_tmp = nullptr;
    if (rsa_tmp) {
        return rsa_tmp;
    }

    BIGNUM *bn = BN_new();
    if (bn == nullptr) {
        swoole_warning("allocation error generating RSA key");
        return nullptr;
    }

    if (!BN_set_word(bn, RSA_F4) || ((rsa_tmp = RSA_new()) == nullptr) ||
        !RSA_generate_key_ex(rsa_tmp, key_length, bn, nullptr)) {
        if (rsa_tmp) {
            RSA_free(rsa_tmp);
        }
        rsa_tmp = nullptr;
    }
    BN_free(bn);
    return rsa_tmp;
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static int swoole_ssl_set_default_dhparam(SSL_CTX *ssl_context) {
    DH *dh;
    static unsigned char dh1024_p[] = {
        0xBB, 0xBC, 0x2D, 0xCA, 0xD8, 0x46, 0x74, 0x90, 0x7C, 0x43, 0xFC, 0xF5, 0x80, 0xE9, 0xCF, 0xDB,
        0xD9, 0x58, 0xA3, 0xF5, 0x68, 0xB4, 0x2D, 0x4B, 0x08, 0xEE, 0xD4, 0xEB, 0x0F, 0xB3, 0x50, 0x4C,
        0x6C, 0x03, 0x02, 0x76, 0xE7, 0x10, 0x80, 0x0C, 0x5C, 0xCB, 0xBA, 0xA8, 0x92, 0x26, 0x14, 0xC5,
        0xBE, 0xEC, 0xA5, 0x65, 0xA5, 0xFD, 0xF1, 0xD2, 0x87, 0xA2, 0xBC, 0x04, 0x9B, 0xE6, 0x77, 0x80,
        0x60, 0xE9, 0x1A, 0x92, 0xA7, 0x57, 0xE3, 0x04, 0x8F, 0x68, 0xB0, 0x76, 0xF7, 0xD3, 0x6C, 0xC8,
        0xF2, 0x9B, 0xA5, 0xDF, 0x81, 0xDC, 0x2C, 0xA7, 0x25, 0xEC, 0xE6, 0x62, 0x70, 0xCC, 0x9A, 0x50,
        0x35, 0xD8, 0xCE, 0xCE, 0xEF, 0x9E, 0xA0, 0x27, 0x4A, 0x63, 0xAB, 0x1E, 0x58, 0xFA, 0xFD, 0x49,
        0x88, 0xD0, 0xF6, 0x5D, 0x14, 0x67, 0x57, 0xDA, 0x07, 0x1D, 0xF0, 0x45, 0xCF, 0xE1, 0x6B, 0x9B};

    static unsigned char dh1024_g[] = {0x02};
    dh = DH_new();
    if (dh == nullptr) {
        swoole_warning("DH_new() failed");
        return SW_ERR;
    }

    dh->p = BN_bin2bn(dh1024_p, sizeof(dh1024_p), nullptr);
    dh->g = BN_bin2bn(dh1024_g, sizeof(dh1024_g), nullptr);

    if (dh->p == nullptr || dh->g == nullptr) {
        DH_free(dh);
    }
    SSL_CTX_set_tmp_dh(ssl_context, dh);
    DH_free(dh);
    return SW_OK;
}
#endif

#endif
