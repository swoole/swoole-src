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

#include "swoole.h"
#include "swoole_hash.h"

static const int CRC32_TABLE_SIZE = 256;
static uint32_t crc32_table[CRC32_TABLE_SIZE];
static bool generated = false;

static void generate_table(uint32_t (&table)[CRC32_TABLE_SIZE]) {
    uint32_t polynomial = 0xEDB88320;
    for (uint32_t i = 0; i < CRC32_TABLE_SIZE; i++) {
        uint32_t c = i;
        for (size_t j = 0; j < 8; j++) {
            if (c & 1) {
                c = polynomial ^ (c >> 1);
            } else {
                c >>= 1;
            }
        }
        table[i] = c;
    }
}

uint32_t swoole_crc32(const char *data, uint32_t size) {
    if (sw_unlikely(!generated)) {
        generate_table(crc32_table);
    }

    uint32_t crcinit = 0;
    uint32_t crc = crcinit ^ 0xffffffff;
    for (; size--; ++data) {
        crc = ((crc >> 8) & 0x00ffffff) ^ crc32_table[(crc ^ (*data)) & 0xff];
    }

    return (crc ^ 0xffffffff);
}
