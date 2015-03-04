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

#include "swoole.h"

static void* swMalloc_alloc(swMemoryPool *pool, uint32_t size);
static void swMalloc_free(swMemoryPool *pool, void *ptr);
static void swMalloc_destroy(swMemoryPool *pool);

swMemoryPool* swMalloc_new()
{
    swMemoryPool *pool = sw_malloc(sizeof(swMemoryPool));
    if (pool == NULL)
    {
        swSysError("mallc() failed.");
        return NULL;
    }
    pool->alloc = swMalloc_alloc;
    pool->free = swMalloc_free;
    pool->destroy = swMalloc_destroy;
    return pool;
}

static void* swMalloc_alloc(swMemoryPool *pool, uint32_t size)
{
    return sw_malloc(size);
}

static void swMalloc_free(swMemoryPool *pool, void *ptr)
{
    sw_free(ptr);
}

static void swMalloc_destroy(swMemoryPool *pool)
{
    sw_free(pool);
}
