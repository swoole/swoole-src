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

TEST(socket, swSocket_unix_sendto) {
    int fd1, fd2, ret;
    struct sockaddr_un un1, un2;
    char sock1_path[] = "/tmp/udp_unix1.sock";
    char sock2_path[] = "/tmp/udp_unix2.sock";
    char test_data[] = "swoole";

    sw_memset_zero(&un1, sizeof(struct sockaddr_un));
    sw_memset_zero(&un2, sizeof(struct sockaddr_un));

    un1.sun_family = AF_UNIX;
    un2.sun_family = AF_UNIX;

    unlink(sock1_path);
    unlink(sock2_path);

    fd1 = socket(AF_UNIX, SOCK_DGRAM, 0);
    strncpy(un1.sun_path, sock1_path, sizeof(un1.sun_path) - 1);
    bind(fd1, (struct sockaddr *) &un1, sizeof(un1));

    fd2 = socket(AF_UNIX, SOCK_DGRAM, 0);
    strncpy(un2.sun_path, sock2_path, sizeof(un2.sun_path) - 1);
    bind(fd2, (struct sockaddr *) &un2, sizeof(un2));

    ret = swSocket_unix_sendto(fd1, sock2_path, test_data, strlen(test_data));
    ASSERT_GT(ret, 0);

    unlink(sock1_path);
    unlink(sock2_path);
}
