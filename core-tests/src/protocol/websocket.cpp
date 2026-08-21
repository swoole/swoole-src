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
#include "swoole_websocket.h"

using namespace swoole;

TEST(websocket, encode_uses_fresh_mask_key) {
    std::set<std::string> payload_keys;
    std::set<std::string> empty_keys;

    for (int i = 0; i < 8; i++) {
        String buffer(64);
        ASSERT_TRUE(
            websocket::encode(&buffer, "hello", 5, websocket::OPCODE_TEXT, websocket::FLAG_FIN | websocket::FLAG_MASK));
        payload_keys.emplace(buffer.str + SW_WEBSOCKET_HEADER_LEN, SW_WEBSOCKET_MASK_LEN);

        websocket::Frame frame{};
        ASSERT_TRUE(websocket::decode(&frame, buffer.str, buffer.length));
        ASSERT_EQ(frame.payload_length, 5);
        ASSERT_MEMEQ(frame.payload, "hello", frame.payload_length);
    }
    // Eight equal 32-bit keys have a 2^-224 probability with a correct random source.
    ASSERT_GT(payload_keys.size(), 1);

    for (int i = 0; i < 8; i++) {
        String buffer(64);
        ASSERT_TRUE(
            websocket::encode(&buffer, nullptr, 0, websocket::OPCODE_TEXT, websocket::FLAG_FIN | websocket::FLAG_MASK));
        ASSERT_EQ(buffer.length, SW_WEBSOCKET_HEADER_LEN + SW_WEBSOCKET_MASK_LEN);
        empty_keys.emplace(buffer.str + SW_WEBSOCKET_HEADER_LEN, SW_WEBSOCKET_MASK_LEN);
    }
    ASSERT_GT(empty_keys.size(), 1);
}
