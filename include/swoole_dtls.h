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

#pragma once

#include "swoole_api.h"
#include "swoole_ssl.h"

#ifdef SW_SUPPORT_DTLS
#include <deque>

namespace swoole {
namespace dtls {
//-------------------------------------------------------------------------------
using Socket = network::Socket;

int BIO_write(BIO *b, const char *data, int dlen);
int BIO_read(BIO *b, char *data, int dlen);
long BIO_ctrl(BIO *b, int cmd, long larg, void *pargs);
int BIO_create(BIO *b);
int BIO_destroy(BIO *b);
BIO_METHOD *BIO_get_methods(void);
void BIO_meth_free(void);

struct Buffer {
    uint16_t length;
    uchar data[0];
};

struct Session {
    SSLContext *ctx;
    bool listened = false;
    Socket *socket;
    std::deque<Buffer *> rxqueue;
    bool peek_mode = false;

    Session(Socket *_sock, SSLContext *_ctx) {
        socket = _sock;
        ctx = _ctx;
    }

    ~Session() {
        while (!rxqueue.empty()) {
            Buffer *buffer = rxqueue.front();
            rxqueue.pop_front();
            sw_free(buffer);
        }
    }

    bool init();
    bool listen();

    void append(const char *data, ssize_t len);

    inline void append(Buffer *buffer) {
        rxqueue.push_back(buffer);
    }

    inline size_t get_buffer_length() {
        size_t total_length = 0;
        for (auto i : rxqueue) {
            total_length += i->length;
        }
        return total_length;
    }
};
//-------------------------------------------------------------------------------
}  // namespace dtls
}  // namespace swoole
#endif
