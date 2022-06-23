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
#include "swoole_mime_type.h"

using namespace swoole;

TEST(mime_type, get) {
    auto result = mime_type::get("test.html.json");
    ASSERT_EQ(result, "application/json");
}

TEST(mime_type, exists) {
    ASSERT_TRUE(mime_type::exists("test.html.json"));
}

TEST(mime_type, set) {
    std::string test_mime_type("application/swoole-core-test");
    mime_type::set("swoole_test", test_mime_type);

    auto result = mime_type::get("test.swoole_test");
    ASSERT_EQ(result, test_mime_type);
}

TEST(mime_type, add) {
    std::string test_mime_type("application/swoole-core-test2");
    ASSERT_TRUE(mime_type::add("swoole_test2", test_mime_type));
    ASSERT_FALSE(mime_type::add("swoole_test2", test_mime_type));

    auto result = mime_type::get("test.swoole_test2");
    ASSERT_EQ(result, test_mime_type);
}

TEST(mime_type, del) {
    ASSERT_TRUE(mime_type::del("json"));
    ASSERT_FALSE(mime_type::exists("test.html.json"));
}
