/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
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

#include "php_swoole_cxx.h"

#include "swoole_websocket.h"

#define SW_WEBSOCKET_DEFAULT_BUFFER 4096

namespace swoole {
namespace websocket {
void apply_setting(WebSocketSettings &settings, zend_array *vht, bool in_server);
void recv_frame(const WebSocketSettings &settings,
                std::shared_ptr<String> &frame_buffer,
                coroutine::Socket *sock,
                zval *return_value,
                double timeout);
ssize_t send_frame(const WebSocketSettings &settings,
                   coroutine::Socket *sock,
                   uchar opcode,
                   uchar flags,
                   const char *payload,
                   size_t payload_length);
void construct_frame(zval *zframe, zend_long opcode, zval *zpayload, uint8_t flags);

#ifdef SW_HAVE_ZLIB
bool message_compress(String *buffer, const char *data, size_t length, int level);
bool message_uncompress(String *buffer, const char *in, size_t in_len);
#endif

struct FrameObject {
    uint8_t opcode;
    uint8_t flags;
    uint16_t code;
    zval *data;

    FrameObject(zval *data, zend_long _opcode = 0, zend_long _flags = 0, zend_long _code = 0);
    size_t get_data_size() {
        return (data && ZVAL_IS_STRING(data)) ? Z_STRLEN_P(data) : 0;
    }
    bool pack(String *buffer);
    static bool uncompress(zval *zpayload, const char *data, size_t length);
};
}  // namespace websocket
}  // namespace swoole
