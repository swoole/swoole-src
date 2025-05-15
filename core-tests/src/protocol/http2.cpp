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

TEST(http2, pack_setting_frame) {
    char frame[SW_HTTP2_SETTING_FRAME_SIZE];
    http2::Settings settings_1{};
    http2::init_settings(&settings_1);
    size_t n = http2::pack_setting_frame(frame, settings_1, false);

    ASSERT_GT(n, 16);

    http2::Settings settings_2{};
    http2::unpack_setting_data(
        frame + SW_HTTP2_FRAME_HEADER_SIZE, n, [&settings_2](uint16_t id, uint32_t value) -> ReturnCode {
            switch (id) {
            case SW_HTTP2_SETTING_HEADER_TABLE_SIZE:
                settings_2.header_table_size = value;
                break;
            case SW_HTTP2_SETTINGS_ENABLE_PUSH:
                settings_2.enable_push = value;
                break;
            case SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
                settings_2.max_concurrent_streams = value;
                break;
            case SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE:
                settings_2.init_window_size = value;
                break;
            case SW_HTTP2_SETTINGS_MAX_FRAME_SIZE:
                settings_2.max_frame_size = value;
                break;
            case SW_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
                settings_2.max_header_list_size = value;
                break;
            default:
                return SW_ERROR;
            }
            return SW_SUCCESS;
        });

    ASSERT_MEMEQ(&settings_1, &settings_2, sizeof(settings_2));
}

#define HTTP2_GET_TYPE_TEST(t) ASSERT_STREQ(http2::get_type(SW_HTTP2_TYPE_##t), #t)

TEST(http2, get_type) {
    HTTP2_GET_TYPE_TEST(DATA);
    HTTP2_GET_TYPE_TEST(HEADERS);
    HTTP2_GET_TYPE_TEST(PRIORITY);
    HTTP2_GET_TYPE_TEST(RST_STREAM);
    HTTP2_GET_TYPE_TEST(SETTINGS);
    HTTP2_GET_TYPE_TEST(PUSH_PROMISE);
    HTTP2_GET_TYPE_TEST(PING);
    HTTP2_GET_TYPE_TEST(GOAWAY);
    HTTP2_GET_TYPE_TEST(WINDOW_UPDATE);
    HTTP2_GET_TYPE_TEST(CONTINUATION);
}

TEST(http2, get_type_color) {
    SW_LOOP_N(SW_HTTP2_TYPE_GOAWAY + 2) {
        ASSERT_GE(http2::get_type_color(i), 0);
    }
}
