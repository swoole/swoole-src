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
#include "swoole_server.h"

#ifndef _WIN32
#include <sys/mman.h>
#include <unistd.h>
#endif

using swoole::ListenPort;

TEST(ssl_wildcard, overlapping_prefix_and_suffix_do_not_read_past_the_name) {
#ifndef _WIN32
    EXPECT_EXIT(
        {
            const long page_size = sysconf(_SC_PAGESIZE);
            if (page_size <= 0) {
                _exit(2);
            }
            auto *storage = static_cast<char *>(
                mmap(nullptr, page_size * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
            if (storage == MAP_FAILED || mprotect(storage + page_size, page_size, PROT_NONE) != 0) {
                _exit(2);
            }
            char *subject = storage + page_size - 4;
            memcpy(subject, "abc", 4);
            const bool matched = ListenPort::ssl_matches_wildcard_name(subject, "ab*bc");
            munmap(storage, page_size * 2);
            _exit(matched ? 1 : 0);
        },
        testing::ExitedWithCode(0),
        "");
#else
    EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("abc", "ab*bc"));
#endif
}

TEST(ssl_wildcard, existing_literal_and_wildcard_matches_keep_their_behavior) {
    struct Match {
        const char *subject;
        const char *pattern;
        bool expected;
    };
    const Match cases[] = {
        {"www.example.com", "www.example.com", true},
        {"WWW.EXAMPLE.COM", "www.example.com", true},
        {"www.example.com", "*.example.com", true},
        {"foo.example.com", "foo*.example.com", true},
        {"foobar.example.com", "foo*bar.example.com", true},
        {"foo.bar.example.com", "foo*.example.com", false},
        {"foo.bar.example.com", "*.example.com", false},
        {"example.com", "*.example.com", false},
        {"www.example.com", "*.other.com", false},
        {"localhost", "*", true},
        {"", "*", true},
        {"abc", "ab*c", true},
    };
    for (const auto &entry : cases) {
        SCOPED_TRACE(entry.subject);
        SCOPED_TRACE(entry.pattern);
        EXPECT_EQ(ListenPort::ssl_matches_wildcard_name(entry.subject, entry.pattern), entry.expected);
    }
}
