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
  | Author: NathanFreeman  <mariasocute@163.com>                         |
  +----------------------------------------------------------------------+
*/

#ifndef SWOOLE_LLHTTP_H
#define SWOOLE_LLHTTP_H

#include "swoole.h"
#include "thirdparty/llhttp/llhttp.h"

static sw_inline void swoole_llhttp_parser_init(llhttp_t *parser, llhttp_type_t type, void *ctx) {
    llhttp_init(parser, type, nullptr);
    parser->data = ctx;
}

static sw_inline size_t swoole_llhttp_parser_execute(llhttp_t *parser,
                                                     const llhttp_settings_t *settings,
                                                     const char *data,
                                                     size_t length) {
    parser->settings = (void *) settings;
    const llhttp_errno_t result = llhttp_execute(parser, data, length);

    if (result == HPE_OK) {
        return length;
    }

    const size_t parsed_length = llhttp_get_error_pos(parser) - data;
    switch (result) {
    case HPE_PAUSED:
        llhttp_resume(parser);
        break;
    case HPE_PAUSED_UPGRADE:
        llhttp_resume_after_upgrade(parser);
        break;
    default:
        break;
    }

    return parsed_length;
}

#endif  // SWOOLE_LLHTTP_H
