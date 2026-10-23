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

#include "php_swoole_cxx.h"

extern zend_class_entry *swoole_sendfile_ce;

bool php_swoole_sendfile_get_options(
    zend_object *object, zend_string **filename, zend_long *offset, zend_long *length, bool *delete_file);
bool php_swoole_sendfile_acquire(zend_object *object);
void php_swoole_sendfile_release(zend_object *object);
