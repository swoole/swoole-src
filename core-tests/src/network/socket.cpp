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

#include "test_core.h"

using namespace std;
using namespace swoole;

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

TEST(socket, sendfile_blocking) {
    string file = test::get_root_path() + "/examples/test.jpg";
    mutex m;
    m.lock();

    String *str = swoole_file_get_contents(file.c_str());

    thread t1 ([&m, str](){
        auto svr = make_server_socket(SW_SOCK_TCP, TEST_HOST, TEST_PORT);
        m.unlock();
        auto cli = svr->accept();
        int len;
        cli->recv_blocking(&len, sizeof(len), MSG_WAITALL);
        int _len = ntohl(len);
        ASSERT_EQ(_len, str->get_length());
        ASSERT_LT(_len, 1024 * 1024);
        std::unique_ptr<char> data(new char[_len]);
        cli->recv_blocking(data.get(), _len, MSG_WAITALL);
        ASSERT_STREQ(data.get(), str->value());
    });

    thread t2([&m, &file, str](){
        m.lock();
        auto cli = make_socket(SW_SOCK_TCP, SW_FD_STREAM_CLIENT, 0);
        network::Address addr;
        addr.assign(SW_SOCK_TCP, TEST_HOST, TEST_PORT);
        ASSERT_EQ(cli->connect(addr), SW_OK);
        int len = htonl(str->get_length());
        cli->send(&len, sizeof(len), 0);
        ASSERT_EQ(cli->sendfile_blocking(file.c_str(), 0, 0, -1), SW_OK);
        cli->free();
    });

    t1.join();
    t2.join();
    delete str;
}