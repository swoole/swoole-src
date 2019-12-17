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

bool swoole_mime_type_add(const char *suffix, const char *mime_type);
void swoole_mime_type_set(const char *suffix, const char *mime_type);
bool swoole_mime_type_delete(const char *suffix, const char *mime_type);
const char* swoole_mime_type_get(const char *file);
bool swoole_mime_type_exists(const char *filename);
