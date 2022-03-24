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
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole.h"

//-------------------memory manager-------------------------
namespace swoole {

class MemoryPool {
  public:
    virtual ~MemoryPool(){};
    virtual void *alloc(uint32_t size) = 0;
    virtual void free(void *ptr) = 0;

  protected:
    MemoryPool(){};
};

struct FixedPoolImpl;

class FixedPool : public MemoryPool {
  private:
    FixedPoolImpl *impl;

  public:
    FixedPool(uint32_t slice_num, uint32_t slice_size, bool shared);
    FixedPool(uint32_t slice_size, void *memory, size_t size, bool shared);
    ~FixedPool();
    void *alloc(uint32_t size);
    void free(void *ptr);
    void debug(int max_lines = 100);
    uint32_t get_number_of_spare_slice();
    uint32_t get_number_of_total_slice();
    uint32_t get_slice_size();
    static size_t sizeof_struct_slice();
    static size_t sizeof_struct_impl();
};

struct RingBufferImpl;

// RingBuffer, In order for malloc / free
class RingBuffer : public MemoryPool {
  private:
    RingBufferImpl *impl;

  public:
    RingBuffer(uint32_t size, bool shared);
    ~RingBuffer();
    void *alloc(uint32_t size);
    void free(void *ptr);
};

struct GlobalMemoryImpl;

// Global memory, the program life cycle only malloc / free one time
class GlobalMemory : public MemoryPool {
  private:
    GlobalMemoryImpl *impl;

  public:
    GlobalMemory(uint32_t page_size, bool shared);
    ~GlobalMemory();
    void *alloc(uint32_t size);
    void free(void *ptr);
    void destroy();
    size_t capacity();
    size_t get_memory_size();
};
}  // namespace swoole

void *sw_shm_malloc(size_t size);
void sw_shm_free(void *ptr);
void *sw_shm_calloc(size_t num, size_t _size);
int sw_shm_protect(void *ptr, int flags);
void *sw_shm_realloc(void *ptr, size_t new_size);
