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

#include "test_core.h"
#include "swoole_http.h"
#include "swoole_proxy.h"

#include <array>
#include <limits>

using swoole::HttpProxy;
using swoole::http_server::url_decode;
using swoole::http_server::url_encode;

namespace {
using EncodedUrl = std::unique_ptr<char, decltype(&sw_free)>;
}

TEST(http_url, empty_input_has_a_terminator) {
    EncodedUrl encoded(url_encode("", 0), sw_free);
    ASSERT_NE(encoded, nullptr);
    EXPECT_STREQ(encoded.get(), "");

    char decoded[] = "x";
    EXPECT_EQ(url_decode(decoded, 0), 0u);
    EXPECT_EQ(decoded[0], '\0');
}

TEST(http_url, unreserved_characters_remain_literal) {
    const std::string input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    EncodedUrl encoded(url_encode(input.data(), input.size()), sw_free);
    ASSERT_NE(encoded, nullptr);
    EXPECT_EQ(input, encoded.get());
}

TEST(http_url, reserved_characters_and_binary_bytes_are_percent_encoded) {
    const char input[] = " :/?#[]@!$&'()*+,;=\"\\\0\xff";
    EncodedUrl encoded(url_encode(input, sizeof(input) - 1), sw_free);
    ASSERT_NE(encoded, nullptr);
    EXPECT_STREQ(encoded.get(), "%20%3A%2F%3F%23%5B%5D%40%21%24%26%27%28%29%2A%2B%2C%3B%3D%22%5C%00%FF");
}

TEST(http_url, encode_respects_the_explicit_input_length) {
    EncodedUrl encoded(url_encode("a b?ignored", 3), sw_free);
    ASSERT_NE(encoded, nullptr);
    EXPECT_STREQ(encoded.get(), "a%20b");
}

TEST(http_url, every_byte_round_trips_including_embedded_nuls) {
    std::string input;
    for (unsigned int c = 0; c < 256; c++) {
        input.push_back(static_cast<char>(c));
    }
    EncodedUrl encoded(url_encode(input.data(), input.size()), sw_free);
    ASSERT_NE(encoded, nullptr);
    EXPECT_EQ(strlen(encoded.get()), 636u);
    EXPECT_EQ(url_decode(encoded.get(), strlen(encoded.get())), input.size());
    EXPECT_MEMEQ(encoded.get(), input.data(), input.size());
    EXPECT_EQ(encoded.get()[input.size()], '\0');
}

TEST(http_url, decode_accepts_both_hex_cases_and_preserves_malformed_escapes) {
    const std::vector<std::pair<std::string, std::string>> cases = {
        {"a+b%2Bc%20d", "a b+c d"},
        {"%41%4a%4A%7e%7E", "AJJ~~"},
        {"%00%Ff%ff", std::string("\0\xff\xff", 3)},
        {"%", "%"},
        {"%A", "%A"},
        {"%GG%4G%G4", "%GG%4G%G4"},
        {"%%41", "%A"},
        {"%\200A%F\377", "%\200A%F\377"},
    };
    for (const auto &entry : cases) {
        auto decoded = entry.first;
        SCOPED_TRACE(entry.first);
        EXPECT_EQ(url_decode(&decoded[0], decoded.size()), entry.second.size());
        EXPECT_MEMEQ(decoded.data(), entry.second.data(), entry.second.size());
        EXPECT_EQ(decoded[entry.second.size()], '\0');
    }
}

TEST(http_url, decode_respects_the_input_boundary) {
    std::array<char, 7> decoded{{'%', '4', '1', '+', 'B', '?', '!'}};
    EXPECT_EQ(url_decode(decoded.data(), 5), 3u);
    EXPECT_STREQ(decoded.data(), "A B");
    EXPECT_EQ(decoded[5], '?');
    EXPECT_EQ(decoded[6], '!');
}

TEST(http_url, impossible_lengths_fail_before_reading_input) {
    const size_t maximum = std::numeric_limits<size_t>::max();
    for (const size_t length : {(maximum - 1) / 3 + 1, maximum}) {
        EXPECT_EXIT(
            {
                errno = 0;
                auto *encoded = url_encode("x", length);
                _exit(encoded == nullptr && errno == EOVERFLOW ? 0 : 1);
            },
            testing::ExitedWithCode(0),
            "");
    }
}

TEST(http_url, allocation_failure_returns_null) {
    EXPECT_EXIT(
        {
            SwooleG.std_allocator.malloc = [](size_t) -> void * {
                errno = ENOMEM;
                return nullptr;
            };
            auto *encoded = url_encode("a b", 3);
            _exit(encoded == nullptr && errno == ENOMEM ? 0 : 1);
        },
        testing::ExitedWithCode(0),
        "");
}

TEST(http_proxy, parse_response) {
    size_t response_length = 0;

    ASSERT_EQ(HttpProxy::parse_response(SW_STRL("HTTP/1."), &response_length), SW_HTTP_PROXY_RESPONSE_WAIT);
    ASSERT_EQ(HttpProxy::parse_response(SW_STRL("not-http"), &response_length), SW_HTTP_PROXY_RESPONSE_ERROR);
    ASSERT_EQ(HttpProxy::parse_response(SW_STRL("HTTP/1.1 200 Connection established\r\n"), &response_length),
              SW_HTTP_PROXY_RESPONSE_WAIT);
    ASSERT_EQ(HttpProxy::parse_response(SW_STRL("HTTP/1.1 407 Proxy Authentication Required\r\n"), &response_length),
              SW_HTTP_PROXY_RESPONSE_ERROR);
    ASSERT_EQ(HttpProxy::parse_response(SW_STRL("HTTP/1.1 2000 OK\r\n\r\n"), &response_length),
              SW_HTTP_PROXY_RESPONSE_ERROR);
    ASSERT_EQ(HttpProxy::parse_response(SW_STRL("HTTP/2 200 OK\r\n\r\n"), &response_length),
              SW_HTTP_PROXY_RESPONSE_ERROR);

    const char response_1_0[] = "HTTP/1.0 200\r\n\r\n";
    ASSERT_EQ(HttpProxy::parse_response(SW_STRL(response_1_0), &response_length), SW_HTTP_PROXY_RESPONSE_READY);
    ASSERT_EQ(response_length, sizeof(response_1_0) - 1);

    const char response[] = "HTTP/1.1 200 OK\r\nProxy-Agent: test\r\n\r\nTUNNEL DATA";
    ASSERT_EQ(HttpProxy::parse_response(SW_STRL(response), &response_length), SW_HTTP_PROXY_RESPONSE_READY);
    ASSERT_EQ(response_length, sizeof("HTTP/1.1 200 OK\r\nProxy-Agent: test\r\n\r\n") - 1);

    const char response_without_reason[] = "HTTP/1.1 200\r\n\r\n";
    ASSERT_EQ(HttpProxy::parse_response(SW_STRL(response_without_reason), &response_length),
              SW_HTTP_PROXY_RESPONSE_READY);
    ASSERT_EQ(response_length, sizeof(response_without_reason) - 1);
}
