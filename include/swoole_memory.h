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
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole.h"

//-------------------memory manager-------------------------
struct swMemoryPool {
    void *object;
    void* (*alloc)(swMemoryPool *pool, uint32_t size);
    void (*free)(swMemoryPool *pool, void *ptr);
    void (*destroy)(swMemoryPool *pool);
};

struct swFixedPool_slice {
    uint8_t lock;
    swFixedPool_slice *next;
    swFixedPool_slice *pre;
    char data[0];
};

struct swFixedPool {
    void *memory;
    size_t size;

    swFixedPool_slice *head;
    swFixedPool_slice *tail;

    /**
     * total memory size
     */
    uint32_t slice_num;

    /**
     * memory usage
     */
    uint32_t slice_use;

    /**
     * Fixed slice size, not include the memory used by swFixedPool_slice
     */
    uint32_t slice_size;

    /**
     * use shared memory
     */
    uint8_t shared;
};

/**
 * FixedPool, random alloc/free fixed size memory
 */
swMemoryPool *swFixedPool_new(uint32_t slice_num, uint32_t slice_size, uint8_t shared);
swMemoryPool *swFixedPool_new2(uint32_t slice_size, void *memory, size_t size);

/**
 * RingBuffer, In order for malloc / free
 */
swMemoryPool *swRingBuffer_new(uint32_t size, uint8_t shared);

/**
 * Global memory, the program life cycle only malloc / free one time
 */
swMemoryPool *swMemoryGlobal_new(uint32_t pagesize, uint8_t shared);

void swFixedPool_debug(swMemoryPool *pool);
void *sw_shm_malloc(size_t size);
void sw_shm_free(void *ptr);
void *sw_shm_calloc(size_t num, size_t _size);
int sw_shm_protect(void *addr, int flags);
void *sw_shm_realloc(void *ptr, size_t new_size);
