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

#include <limits>

using namespace swoole;

TEST(websocket, encode_mask_with_header_only) {
    String buffer(64);
    uint8_t flags = websocket::FLAG_FIN | websocket::FLAG_MASK | websocket::FLAG_ENCODE_HEADER_ONLY;

    ASSERT_TRUE(websocket::encode(&buffer, "hello", 5, websocket::OPCODE_TEXT, flags));

    // Should have appended header (2 bytes) + mask key (4 bytes) only, no body
    ASSERT_EQ(buffer.length, 2 + SW_WEBSOCKET_MASK_LEN);
}

namespace {
// Build wire bytes independently of encode(), so matching encoder/decoder bugs cannot hide each other.
std::string websocket_header(uint64_t length, bool masked) {
    std::string header(1, static_cast<char>(0x82));
    const uint8_t mask = masked ? 0x80 : 0;
    if (length < 126) {
        header.push_back(static_cast<char>(mask | length));
    } else {
        const int bytes = length <= UINT16_MAX ? 2 : 8;
        header.push_back(static_cast<char>(mask | (bytes == 2 ? 126 : 127)));
        for (int shift = (bytes - 1) * 8; shift >= 0; shift -= 8) {
            header.push_back(static_cast<char>(length >> shift));
        }
    }
    if (masked) {
        header.append(SW_WEBSOCKET_MASK_DATA, SW_WEBSOCKET_MASK_LEN);
    }
    return header;
}
}  // namespace

TEST(websocket, length_requires_every_header_byte) {
    for (const uint64_t length : {0u, 125u, 126u, 65535u, 65536u}) {
        for (const bool masked : {false, true}) {
            const auto header = websocket_header(length, masked);
            SCOPED_TRACE(testing::Message() << "length=" << length << ", mask=" << masked);
            for (size_t prefix = 0; prefix < header.size(); ++prefix) {
                PacketLength pl{header.data(), static_cast<uint32_t>(prefix), 0};
                EXPECT_EQ(websocket::get_package_length(nullptr, nullptr, &pl), 0) << prefix;
            }
            PacketLength pl{header.data(), static_cast<uint32_t>(header.size()), 0};
            EXPECT_EQ(websocket::get_package_length(nullptr, nullptr, &pl),
                      static_cast<ssize_t>(header.size() + length));
            EXPECT_EQ(pl.header_len, header.size());
        }
    }
}

TEST(websocket, length_rejects_total_size_overflow) {
    const auto max_length = static_cast<uint64_t>(std::numeric_limits<ssize_t>::max());
    for (const bool masked : {false, true}) {
        const size_t header_length = masked ? 14 : 10;
        for (const uint64_t length :
             {max_length - header_length, max_length - header_length + 1, max_length, UINT64_MAX}) {
            const auto header = websocket_header(length, masked);
            PacketLength pl{header.data(), static_cast<uint32_t>(header.size()), 0};
            const auto actual = websocket::get_package_length(nullptr, nullptr, &pl);
            if (length == max_length - header_length) {
                EXPECT_EQ(actual, std::numeric_limits<ssize_t>::max());
            } else {
                EXPECT_EQ(actual, SW_ERR) << length;
            }
        }
    }
}

TEST(websocket, parse_rejects_short_base_header) {
    const int saved_error = swoole_get_last_error();
    websocket::Frame frame{};
    EXPECT_FALSE(websocket::parse_frame(&frame, nullptr, 0));
    // Allocate exactly one byte: reading the second header byte must be caught by ASan.
    std::unique_ptr<char[]> data(new char[1]);
    data[0] = static_cast<char>(0x82);
    EXPECT_FALSE(websocket::parse_frame(&frame, data.get(), 1));
    EXPECT_FALSE(websocket::decode(&frame, data.get(), 1));
    swoole_set_last_error(saved_error);
}

TEST(websocket, decode_rejects_incomplete_extended_header_mask_and_payload) {
    const int saved_error = swoole_get_last_error();
    for (const uint64_t length : {1u, 126u, 65536u}) {
        for (const bool masked : {false, true}) {
            auto packet = websocket_header(length, masked);
            for (size_t prefix = 2; prefix <= packet.size(); ++prefix) {
                websocket::Frame frame{};
                EXPECT_FALSE(websocket::decode(&frame, &packet[0], prefix)) << prefix;
                EXPECT_EQ(swoole_get_last_error(), SW_ERROR_WEBSOCKET_INCOMPLETE_PACKET);
            }
        }
    }
    swoole_set_last_error(saved_error);
}

TEST(websocket, encode_matches_wire_at_payload_length_boundaries) {
    for (const size_t length : {0u, 125u, 126u, 65535u, 65536u}) {
        for (const bool masked : {false, true}) {
            std::string payload(length, '\0');
            for (size_t i = 0; i < length; ++i) {
                payload[i] = static_cast<char>(i);
            }
            auto expected = websocket_header(length, masked);
            for (size_t i = 0; i < length; ++i) {
                expected.push_back(masked ? payload[i] ^ SW_WEBSOCKET_MASK_DATA[i % 4] : payload[i]);
            }
            String buffer("prefix");
            ASSERT_TRUE(websocket::encode(&buffer,
                                          payload.data(),
                                          payload.size(),
                                          websocket::OPCODE_BINARY,
                                          websocket::FLAG_FIN | (masked ? websocket::FLAG_MASK : 0)));
            EXPECT_EQ(buffer.to_std_string(), "prefix" + expected);
        }
    }
}

TEST(websocket, mask_handles_unaligned_blocks_and_tails) {
    const char key[] = {0x12, 0x34, 0x56, 0x78};
    for (size_t offset = 0; offset < 8; ++offset) {
        for (size_t length = 0; length <= 33; ++length) {
            std::string data(offset + length + 8, 'g');
            const auto original = data;
            auto expected = data;
            for (size_t i = 0; i < length; ++i) {
                expected[offset + i] ^= key[i % 4];
            }
            websocket::mask(&data[0] + offset, length, key);
            EXPECT_EQ(data, expected);
            websocket::mask(&data[0] + offset, length, key);
            EXPECT_EQ(data, original);
        }
    }
}

TEST(websocket, parse_preserves_masked_payload_until_decode) {
    const std::string payload("a\0b\xff", 4);
    auto wire = websocket_header(payload.size(), true);
    wire[0] = static_cast<char>(0xf2);  // FIN, RSV1, RSV2, RSV3, BINARY
    for (size_t i = 0; i < payload.size(); ++i) {
        wire.push_back(payload[i] ^ SW_WEBSOCKET_MASK_DATA[i % 4]);
    }
    const auto original = wire;
    websocket::Frame frame{};
    ASSERT_TRUE(websocket::parse_frame(&frame, wire.data(), wire.size()));
    EXPECT_EQ(wire, original);
    EXPECT_EQ(frame.header_length, 6);
    EXPECT_EQ(frame.payload_length, payload.size());
    EXPECT_TRUE(frame.compressed());
    EXPECT_EQ(frame.get_flags(),
              websocket::FLAG_FIN | websocket::FLAG_MASK | websocket::FLAG_RSV1 | websocket::FLAG_RSV2 |
                  websocket::FLAG_RSV3);
    EXPECT_EQ(std::string(frame.mask_key, 4), std::string(SW_WEBSOCKET_MASK_DATA, 4));
    ASSERT_TRUE(websocket::decode(&frame, &wire[0], wire.size()));
    EXPECT_EQ(std::string(frame.payload, frame.payload_length), payload);
}

TEST(websocket, empty_frame_has_no_payload) {
    for (const bool masked : {false, true}) {
        auto wire = websocket_header(0, masked);
        websocket::Frame frame{};
        ASSERT_TRUE(websocket::decode(&frame, &wire[0], wire.size()));
        EXPECT_EQ(frame.payload, nullptr);
        EXPECT_EQ(frame.payload_length, 0u);
        EXPECT_EQ(frame.header_length, wire.size());
    }
}

TEST(websocket, encode_rejects_fragmented_and_oversized_control_frames_without_appending) {
    for (const auto opcode : {websocket::OPCODE_CLOSE, websocket::OPCODE_PING, websocket::OPCODE_PONG}) {
        String buffer("prefix");
        const std::string payload(126, 'x');
        EXPECT_FALSE(websocket::encode(&buffer, payload.data(), 0, opcode, 0));
        EXPECT_FALSE(websocket::encode(&buffer, payload.data(), 126, opcode, websocket::FLAG_FIN));
        EXPECT_EQ(buffer.to_std_string(), "prefix");
        EXPECT_TRUE(websocket::encode(&buffer, payload.data(), 125, opcode, websocket::FLAG_FIN));
    }
}

TEST(websocket, parse_rejects_compressed_fragmented_and_oversized_control_frames) {
    for (const uint8_t opcode : {websocket::OPCODE_CLOSE, websocket::OPCODE_PING, websocket::OPCODE_PONG}) {
        for (const uint8_t flags : {0u, 0x80u, 0xc0u}) {
            const size_t length = flags == 0x80 ? 126 : 0;
            auto wire = websocket_header(length, false) + std::string(length, 'x');
            wire[0] = static_cast<char>(flags | opcode);
            websocket::Frame frame{};
            EXPECT_FALSE(websocket::parse_frame(&frame, wire.data(), wire.size()));
        }
    }
}

TEST(websocket, close_frame_encodes_binary_reason_and_limits_length) {
    for (const bool masked : {false, true}) {
        String buffer;
        const std::string reason = std::string("a\0", 2) + std::string(121, 'x');
        ASSERT_TRUE(websocket::pack_close_frame(
            &buffer, websocket::CLOSE_GOING_AWAY, reason.data(), reason.size(), masked ? websocket::FLAG_MASK : 0));
        websocket::Frame frame{};
        ASSERT_TRUE(websocket::decode(&frame, buffer.str, buffer.length));
        EXPECT_EQ(frame.header.OPCODE, websocket::OPCODE_CLOSE);
        EXPECT_TRUE(frame.header.FIN);
        ASSERT_EQ(frame.payload_length, 125u);
        EXPECT_EQ(static_cast<uint8_t>(frame.payload[0]), 0x03);
        EXPECT_EQ(static_cast<uint8_t>(frame.payload[1]), 0xe9);
        EXPECT_EQ(std::string(frame.payload + 2, frame.payload_length - 2), reason);
        const auto original = buffer.to_std_string();
        EXPECT_FALSE(websocket::pack_close_frame(&buffer, websocket::CLOSE_NORMAL, reason.data(), 124, 0));
        EXPECT_EQ(buffer.to_std_string(), original);
    }
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
