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

#ifdef SW_THREAD

typedef uint32_t ThreadResourceId;
struct ThreadResource;

ThreadResourceId php_swoole_thread_resource_insert(ThreadResource *res);
bool php_swoole_thread_resource_free(ThreadResourceId resource_id, ThreadResource *res);
ThreadResource *php_swoole_thread_resource_fetch(ThreadResourceId resource_id);

void php_swoole_thread_start(zend_string *file, zend_string *argv);
zend_string *php_swoole_thread_serialize(zval *zdata);
bool php_swoole_thread_unserialize(zend_string *data, zval *zv);

zval *php_swoole_thread_get_arguments();

#define EMSG_NO_RESOURCE "resource not found"
#define ECODE_NO_RESOURCE -2

#define IS_SERIALIZED_OBJECT 99

struct ThreadResource {
    uint32_t ref_count;

    ThreadResource() {
        ref_count = 1;
    }

    uint32_t add_ref() {
        return ++ref_count;
    }

    uint32_t del_ref() {
        return --ref_count;
    }
};

#endif
