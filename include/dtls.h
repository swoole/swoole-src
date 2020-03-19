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
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole_api.h"

#ifdef SW_HAVE_DTLS
#include <deque>

namespace swoole { namespace dtls {
//-------------------------------------------------------------------------------

int BIO_write(BIO *b, const char *data, int dlen);
int BIO_read(BIO *b, char *data, int dlen);
int BIO_gets(BIO *b, char *data, int size);
int BIO_puts(BIO *b, const char *data);
long BIO_ctrl(BIO *b, int cmd, long larg, void *pargs);
int BIO_create(BIO *b);
int BIO_destroy(BIO *b);
long BIO_callback_ctrl(BIO *, int, BIO_info_cb *);
BIO_METHOD *BIO_get_methods(void);
void BIO_meth_free(void);

struct Buffer
{
    uint16_t length;
    uchar data[0];
};

struct Session
{
    SSL_CTX *ctx;
    bool listened = false;
    swSocket *socket;
    std::deque<Buffer*> rxqueue;
    bool peek_mode = false;

    Session(swSocket *_sock, SSL_CTX *_ctx)
    {
        socket = _sock;
        ctx = _ctx;
    }

    ~Session()
    {
        while(!rxqueue.empty())
        {
            Buffer *buffer = rxqueue.front();
            rxqueue.pop_front();
            delete buffer;
        }
    }

    bool init();
    bool listen();

    void append(const char* data, ssize_t len);
};
//-------------------------------------------------------------------------------
}}
#endif
