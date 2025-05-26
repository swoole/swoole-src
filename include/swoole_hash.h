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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#ifndef SW_HASH_H_
#define SW_HASH_H_

uint64_t swoole_hash_jenkins(const char *key, size_t keylen);
uint64_t swoole_hash_php(const char *key, size_t len);
uint64_t swoole_hash_austin(const char *key, size_t keylen);
uint32_t swoole_crc32(const char *data, size_t size);

#endif /* SW_HASH_H_ */
