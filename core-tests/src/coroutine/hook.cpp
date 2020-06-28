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
  | @license  https://github.com/swoole/library/blob/master/LICENSE      |
  | @Author   Tianfeng Han  <mikan.tenny@gmail.com>                      |
  +----------------------------------------------------------------------+
*/

#include "test_coroutine.h"

using swoole::Coroutine;
using swoole::coroutine::System;
using swoole::test::coroutine;

const char *host_1 = "www.baidu.com";
const char *host_2 = "www.xxxxxxxxxxxxxxxxxxxxx00000xxxxxxxxx----not_found.com";

TEST(coroutine_hook, gethostbyname)
{
    coroutine::run([](void *arg)
    {
        auto result1 = swoole_coroutine_gethostbyname(host_1);
        ASSERT_NE(result1, nullptr);

        auto result2 = swoole_coroutine_gethostbyname(host_2);
        ASSERT_EQ(result2, nullptr);
        ASSERT_EQ(h_errno, HOST_NOT_FOUND);
    });
}

TEST(coroutine_hook, getaddrinfo)
{
    coroutine::run([](void *arg)
    {
        struct addrinfo hints;
        sw_memset_zero(&hints, sizeof(struct addrinfo));
        hints.ai_family = AF_INET; /* Allow IPv4 or IPv6 */
        hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
        hints.ai_flags = AI_PASSIVE; /* For wildcard IP address */
        hints.ai_protocol = 0; /* Any protocol */
        hints.ai_canonname = NULL;
        hints.ai_addr = NULL;
        hints.ai_next = NULL;

        struct addrinfo *result, *curr;
        int count;

        result = nullptr;
        auto result1 = swoole_coroutine_getaddrinfo(host_1, nullptr, &hints, &result);
        ASSERT_EQ(result1, 0);

        curr = result;
        count = 0;
        while (curr && curr->ai_addr)
        {
            curr = curr->ai_next;
            count ++;
        }
        ASSERT_GE(count, 1);
        freeaddrinfo(result);

        result = nullptr;
        auto result2 = swoole_coroutine_getaddrinfo(host_2, nullptr, &hints, &result);
        ASSERT_EQ(result2, EAI_NONAME);
        ASSERT_EQ(result, nullptr);
        freeaddrinfo(result);
    });
}
