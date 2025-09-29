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

#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

using swoole::SSLContext;
using swoole::String;

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
    SSLContext ctx;
    ctx.key_file = swoole::test::get_ssl_dir() + "/passwd_key.pem";
    ctx.passphrase = "swoole";
    ctx.cert_file = swoole::test::get_ssl_dir() + "/passwd.crt";
    ASSERT_TRUE(ctx.create());
}
