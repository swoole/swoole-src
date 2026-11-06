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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Twosee  <twose@qq.com>                                       |
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "php_swoole_cxx.h"
#include "swoole_process_pool.h"

#include <limits>
#include <type_traits>

enum PipeType {
    PIPE_TYPE_NONE = 0,
    PIPE_TYPE_STREAM = 1,
    PIPE_TYPE_DGRAM = 2,
};

/**
 * SysV message queue keys are bit patterns. Preserve both the signed key_t
 * range and values representable by its unsigned counterpart.
 */
static sw_inline bool php_swoole_msgqueue_key_is_valid(zend_long key) {
    using unsigned_key_t = typename std::make_unsigned<key_t>::type;

    if (key < 0) {
        return std::numeric_limits<key_t>::is_signed && key >= std::numeric_limits<key_t>::min();
    }

    return static_cast<zend_ulong>(key) <= std::numeric_limits<unsigned_key_t>::max();
}

void php_swoole_process_clean();
void php_swoole_process_signal_clean();
int php_swoole_process_start(swoole::Worker *process, zval *zobject);
swoole::Worker *php_swoole_process_get_worker(const zval *zobject);
void php_swoole_process_set_worker(const zval *zobject, swoole::Worker *worker, bool enable_coroutine, int pipe_type);

swoole::ProcessPool *sw_process_pool();
