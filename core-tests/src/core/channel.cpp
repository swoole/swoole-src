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
  | @author   Tianfeng Han  <mikan.tenny@gmail.com>                      |
  +----------------------------------------------------------------------+
*/

#include "tests.h"

using namespace std;

const int N = 10000000;

TEST(channel, push) {
    auto c = swChannel_new(128 * 1024, 8192, SW_CHAN_LOCK | SW_CHAN_NOTIFY);
    map<int, string> m;

    size_t bytes = 0;
    int index = 0;

    while (bytes < N) {
        char buf[8000];
        int n = swoole_random_bytes(buf, (rand() % (sizeof(buf) / 2)) + (sizeof(buf) / 2));
        if (n <= 0) {
            swTrace("no enough data, n=%d, errno=%d\n", n, errno);
            continue;
        }
        m[index++] = string(buf, n);
        bytes += n;
    }

    swTrace("size=%d\n", m.size());

    thread t1([&]()
    {
        auto next = m.find(0);
        int index = 1;
        size_t bytes = 0;

        while(bytes < N) {
            if (swChannel_push(c, next->second.c_str(), next->second.length()) == SW_OK) {
                swTrace("[PUSH] index=%d, size=%d\n", index, next.length());
                bytes += next->second.length();
                next = m.find(index++);
                if (next == m.end()) {
                    break;
                }
            } else {
                usleep(10);
            }
        }
    });

    thread t2([&]()
    {
        char buf[8000];
        size_t bytes = 0;
        int index = 0;
        while(bytes < N) {
            int retval = swChannel_pop(c, buf, sizeof(buf));
            if (retval > 0) {
                swTrace("[POP] index=%d, size=%ld\n", index, retval);
                string &_data = m[index++];
                bytes += retval;
                ASSERT_EQ(_data, string(buf, retval));
            } else {
                usleep(10);
            }
        }
    });

    t1.join();
    t2.join();
}
