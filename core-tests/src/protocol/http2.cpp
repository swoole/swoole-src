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
#include "test_coroutine.h"
#include "redis_client.h"
#include "swoole_http2.h"

using namespace swoole;
using namespace std;

const std::string REDIS_TEST_KEY = "key-swoole";
const std::string REDIS_TEST_VALUE = "value-swoole";

TEST(http2, default_settings) {
    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTING_HEADER_TABLE_SIZE), SW_HTTP2_DEFAULT_HEADER_TABLE_SIZE);
    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTINGS_ENABLE_PUSH), SW_HTTP2_DEFAULT_ENABLE_PUSH);
    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS),
              SW_HTTP2_DEFAULT_MAX_CONCURRENT_STREAMS);
    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE), SW_HTTP2_DEFAULT_INIT_WINDOW_SIZE);
    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTINGS_MAX_FRAME_SIZE), SW_HTTP2_DEFAULT_MAX_FRAME_SIZE);
    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE),
              SW_HTTP2_DEFAULT_MAX_HEADER_LIST_SIZE);

    http2::Settings _settings = {
        (uint32_t) swoole_rand(1, 100000),
        (uint32_t) swoole_rand(1, 100000),
        (uint32_t) swoole_rand(1, 100000),
        (uint32_t) swoole_rand(1, 100000),
        (uint32_t) swoole_rand(1, 100000),
        (uint32_t) swoole_rand(1, 100000),
    };

    http2::put_default_setting(SW_HTTP2_SETTING_HEADER_TABLE_SIZE, _settings.header_table_size);
    http2::put_default_setting(SW_HTTP2_SETTINGS_ENABLE_PUSH, _settings.enable_push);
    http2::put_default_setting(SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, _settings.max_concurrent_streams);
    http2::put_default_setting(SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE, _settings.init_window_size);
    http2::put_default_setting(SW_HTTP2_SETTINGS_MAX_FRAME_SIZE, _settings.max_frame_size);
    http2::put_default_setting(SW_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, _settings.max_header_list_size);

    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTING_HEADER_TABLE_SIZE), _settings.header_table_size);
    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTINGS_ENABLE_PUSH), _settings.enable_push);
    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS), _settings.max_concurrent_streams);
    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE), _settings.init_window_size);
    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTINGS_MAX_FRAME_SIZE), _settings.max_frame_size);
    ASSERT_EQ(http2::get_default_setting(SW_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE), _settings.max_header_list_size);
}
