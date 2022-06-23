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
#include "swoole_memory.h"
#include "swoole_buffer.h"

using namespace std;
using namespace swoole;

TEST(buffer, append_iov) {
    Buffer buf(1024);

    int iovcnt = 4;
    iovec v[iovcnt];

    v[0].iov_len = swoole_rand(99, 4095);
    v[1].iov_len = swoole_rand(99, 4095);
    v[2].iov_len = swoole_rand(99, 4095);
    v[3].iov_len = swoole_rand(99, 4095);

    unique_ptr<char> s1(new char[v[0].iov_len]);
    unique_ptr<char> s2(new char[v[1].iov_len]);
    unique_ptr<char> s3(new char[v[2].iov_len]);
    unique_ptr<char> s4(new char[v[3].iov_len]);

    v[0].iov_base = s1.get();
    v[1].iov_base = s2.get();
    v[2].iov_base = s3.get();
    v[3].iov_base = s4.get();

    memset(v[0].iov_base, 'A', v[0].iov_len);
    memset(v[1].iov_base, 'B', v[1].iov_len);
    memset(v[2].iov_base, 'C', v[2].iov_len);
    memset(v[3].iov_base, 'D', v[3].iov_len);

    buf.append(v, iovcnt, 0);

    ASSERT_EQ(buf.length(), v[0].iov_len + v[1].iov_len + v[2].iov_len+ v[3].iov_len);

    String str(buf.length());

    while(!buf.empty()) {
        auto chunk = buf.front();
        str.append(chunk->value.ptr, chunk->length);
        buf.pop();
    }

    size_t offset = 0;

    SW_LOOP_N (iovcnt) {
        ASSERT_EQ(memcmp(str.str + offset, v[i].iov_base, v[i].iov_len), 0);
        offset += v[i].iov_len;
    }
}
