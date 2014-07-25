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
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "swoole.h"

typedef struct
{
    swLock lock;
    size_t size;
} swMemoryTable;

swMemoryTable* swMemoryTable_new(size_t size)
{
    swMemoryTable *table = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swMemoryTable));
    if (table == NULL)
    {
        return NULL;
    }
    if (swMutex_create(&table->lock, 1) < 0)
    {
        return NULL;
    }
    table->size = size;
    return table;
}
