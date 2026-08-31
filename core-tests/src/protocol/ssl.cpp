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
  | @link     https://www.swoole.com/                                    |
  | @contact  team@swoole.com                                            |
  | @license  https://github.com/swoole/swoole-src/blob/master/LICENSE   |
  | @Author   Tianfeng Han  <rango@swoole.com>                           |
  +----------------------------------------------------------------------+
*/

#include "test_core.h"
#include "swoole_util.h"

#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/pem.h>

using swoole::SSLContext;
using swoole::String;

static std::pair<int, int> verify_certificate(SSL_CTX *context, const std::string &file) {
    BIO *bio = BIO_new_file(file.c_str(), "r");
    if (bio == nullptr) {
        ADD_FAILURE() << "BIO_new_file() failed for " << file;
        return {-2, -2};
    }
    ON_SCOPE_EXIT {
        BIO_free(bio);
    };
    X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (cert == nullptr) {
        ADD_FAILURE() << "PEM_read_bio_X509() failed for " << file;
        return {-2, -2};
    }
    ON_SCOPE_EXIT {
        X509_free(cert);
    };
    X509_STORE_CTX *store_ctx = X509_STORE_CTX_new();
    if (store_ctx == nullptr) {
        ADD_FAILURE() << "X509_STORE_CTX_new() failed";
        return {-2, -2};
    }
    ON_SCOPE_EXIT {
        X509_STORE_CTX_free(store_ctx);
    };
    if (!X509_STORE_CTX_init(store_ctx, SSL_CTX_get_cert_store(context), cert, nullptr)) {
        ADD_FAILURE() << "X509_STORE_CTX_init() failed for " << file;
        return {-2, -2};
    }
    int result = X509_verify_cert(store_ctx);
    int error = X509_STORE_CTX_get_error(store_ctx);
    return {result, error};
}

TEST(ssl, destroy) {
    swoole_ssl_init();
    swoole_ssl_destroy();
    ASSERT_EQ(ERR_peek_error(), 0);
}

TEST(ssl, get_error) {
    swoole_ssl_init();
    {
        ERR_clear_error();
        ERR_put_error(ERR_LIB_SSL, SSL_F_SSL_SET_SESSION, SSL_R_CERTIFICATE_VERIFY_FAILED, __FILE__, __LINE__);
        const char *error_str = swoole_ssl_get_error();
        EXPECT_NE(error_str, nullptr);
        String str(error_str);
        DEBUG() << str.to_std_string() << std::endl;
        ASSERT_TRUE(str.contains("certificate verify failed"));
    }
    {
        ERR_clear_error();

        ERR_put_error(ERR_LIB_SSL, SSL_F_SSL_SET_SESSION, SSL_R_CERTIFICATE_VERIFY_FAILED, __FILE__, __LINE__);
        ERR_put_error(ERR_LIB_SSL, SSL_F_SSL_SHUTDOWN, SSL_R_PROTOCOL_IS_SHUTDOWN, __FILE__, __LINE__);

        const char *error_str = swoole_ssl_get_error();
        EXPECT_NE(error_str, nullptr);

        const char *error_str2 = swoole_ssl_get_error();
        EXPECT_NE(error_str2, nullptr);

        String str(error_str2);
        DEBUG() << str.to_std_string() << std::endl;
        ASSERT_TRUE(str.contains("protocol is shutdown"));

        const char *error_st3 = swoole_ssl_get_error();
        ASSERT_STREQ(error_st3, "");
    }
}

TEST(ssl, password) {
    SSLContext ctx{};
    ctx.key_file = swoole::test::get_ssl_dir() + "/passwd_key.pem";
    ctx.passphrase = "swoole";
    ctx.cert_file = swoole::test::get_ssl_dir() + "/passwd.crt";
    ASSERT_TRUE(ctx.create(SW_SSL_CLIENT));
}

TEST(ssl, server_client_certificate) {
    const char *cert_file = getenv("SSL_CERT_FILE");
    bool cert_file_was_set = cert_file != nullptr;
    std::string previous_cert_file = cert_file_was_set ? cert_file : "";
    ON_SCOPE_EXIT {
        if (cert_file_was_set) {
            setenv("SSL_CERT_FILE", previous_cert_file.c_str(), 1);
        } else {
            unsetenv("SSL_CERT_FILE");
        }
    };

    std::string ssl_dir = swoole::test::get_ssl_dir();
    ASSERT_EQ(setenv("SSL_CERT_FILE", (ssl_dir + "/mosquitto.org.crt").c_str(), 1), 0);

    SSLContext ctx{};
    ctx.client_cert_file = ssl_dir + "/ca-cert.pem";
    ASSERT_TRUE(ctx.create(SW_SSL_SERVER));
    EXPECT_TRUE(SSL_CTX_get_verify_mode(ctx.get_context()) & SSL_VERIFY_PEER);
    EXPECT_NE(SSL_CTX_get_verify_depth(ctx.get_context()), 0);

    auto configured_ca = verify_certificate(ctx.get_context(), ssl_dir + "/client-cert.pem");
    ASSERT_EQ(configured_ca.first, 1);
    ASSERT_EQ(configured_ca.second, X509_V_OK);

    auto default_ca = verify_certificate(ctx.get_context(), ssl_dir + "/mosquitto.org.crt");
    EXPECT_EQ(default_ca.first, 0);
    EXPECT_EQ(default_ca.second, X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT);
}
