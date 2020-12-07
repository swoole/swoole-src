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

#pragma once

#include "swoole.h"

#ifdef SW_USE_OPENSSL

#include <unordered_map>
#include <string>
#include <array>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/ossl_typ.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#define SW_SUPPORT_DTLS
#endif

enum swSSL_create_flag {
    SW_SSL_SERVER = 1,
    SW_SSL_CLIENT = 2,
};

enum swSSL_state {
    SW_SSL_STATE_HANDSHAKE = 0,
    SW_SSL_STATE_READY = 1,
    SW_SSL_STATE_WAIT_STREAM = 2,
};

enum swSSL_version {
    SW_SSL_SSLv2 = 1u << 1,
    SW_SSL_SSLv3 = 1u << 2,
    SW_SSL_TLSv1 = 1u << 3,
    SW_SSL_TLSv1_1 = 1u << 4,
    SW_SSL_TLSv1_2 = 1u << 5,
    SW_SSL_TLSv1_3 = 1u << 6,
    SW_SSL_DTLS = 1u << 7,
};

#define SW_SSL_ALL (SW_SSL_SSLv2 | SW_SSL_SSLv3 | SW_SSL_TLSv1 | SW_SSL_TLSv1_1 | SW_SSL_TLSv1_2 | SW_SSL_TLSv1_3)

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

namespace swoole {

struct SSLContext {
    uchar http : 1;
    uchar http_v2 : 1;
    uchar prefer_server_ciphers : 1;
    uchar session_tickets : 1;
    uchar stapling : 1;
    uchar stapling_verify : 1;
    std::string ciphers;
    std::string ecdh_curve;
    std::string session_cache;
    std::string dhparam;
    std::string cert_file;
    std::string key_file;
    std::string passphrase;
    std::string client_cert_file;
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    uchar disable_tls_host_name : 1;
    std::string tls_host_name;
#endif
    std::string cafile;
    std::string capath;
    uint8_t verify_depth;
    uchar disable_compress : 1;
    uchar verify_peer : 1;
    uchar allow_self_signed : 1;
    uint32_t protocols;
    uint8_t create_flag;
    SSL_CTX *context;

    SSL_CTX *get_context() {
        return context;
    }

    void set_protocols(uint32_t _protocols) {
        protocols = _protocols;
    }

    bool set_cert_file(const std::string &_cert_file) {
        if (access(_cert_file.c_str(), R_OK) < 0) {
            swWarn("ssl cert file[%s] not found", _cert_file.c_str());
            return false;
        }
        cert_file = _cert_file;
        return true;
    }

    bool set_key_file(const std::string &_key_file) {
        if (access(_key_file.c_str(), R_OK) < 0) {
            swWarn("ssl key file[%s] not found", _key_file.c_str());
            return false;
        }
        key_file = _key_file;
        return true;
    }

    bool create();
    bool set_capath();
    bool set_ciphers();
    bool set_client_certificate();
    bool set_ecdh_curve();
    bool set_dhparam();
    ~SSLContext();
};
}

void swSSL_init(void);
void swSSL_init_thread_safety();
void swSSL_server_http_advise(swoole::SSLContext &);
const char *swSSL_get_error();
int swSSL_get_ex_connection_index();
int swSSL_get_ex_port_index();
#endif
