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

TEST(websocket, encode_mask_with_header_only) {
    String buffer(64);
    uint8_t flags = websocket::FLAG_FIN | websocket::FLAG_MASK | websocket::FLAG_ENCODE_HEADER_ONLY;

    // With MASK + HEADER_ONLY, should return true (consistent with non-MASK behavior)
    // BUG: currently returns false when MASK is set with HEADER_ONLY
    ASSERT_TRUE(websocket::encode(&buffer, "hello", 5, websocket::OPCODE_TEXT, flags));

    // Should have appended header (2 bytes) + mask key (4 bytes) only, no body
    ASSERT_EQ(buffer.length, 2 + SW_WEBSOCKET_MASK_LEN);
}

TEST(websocket, decode_unaligned_buffer) {
    String buffer(64);
    ASSERT_TRUE(websocket::encode(&buffer, "hello", 5, websocket::OPCODE_TEXT, websocket::FLAG_FIN));

    std::unique_ptr<char[]> raw(new char[buffer.length + 1]);
    memcpy(raw.get() + 1, buffer.str, buffer.length);

    websocket::Frame frame{};
    ASSERT_TRUE(websocket::decode(&frame, raw.get() + 1, buffer.length));
    ASSERT_EQ(frame.payload_length, 5);
    ASSERT_MEMEQ(frame.payload, "hello", frame.payload_length);
}
