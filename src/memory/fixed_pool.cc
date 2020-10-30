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
#include "swoole_memory.h"

namespace swoole {

struct FixedPoolSlice {
    uint8_t lock;
    FixedPoolSlice *next;
    FixedPoolSlice *pre;
    char data[0];
};

struct FixedPoolImpl {
    void *memory;
    size_t size;

    FixedPoolSlice *head;
    FixedPoolSlice *tail;

    // total memory size
    uint32_t slice_num;

    // memory usage
    uint32_t slice_use;

    // Fixed slice size, not include the memory used by FixedPoolSlice
    uint32_t slice_size;
    bool shared;
    bool allocated;

    void init();
};

/**
 * create new FixedPool, random alloc/free fixed size memory
 */
FixedPool::FixedPool(uint32_t slice_num, uint32_t slice_size, bool shared) {
    slice_size = SW_MEM_ALIGNED_SIZE(slice_size);
    size_t size = slice_num * (sizeof(FixedPoolSlice) + slice_size);
    size_t alloc_size = size + sizeof(*impl);
    void *memory = shared ? ::sw_shm_malloc(alloc_size) : ::sw_malloc(alloc_size);
    if (!memory) {
        throw std::bad_alloc();
    }

    impl = (FixedPoolImpl *) memory;
    memory = (char *) memory + sizeof(*impl);
    sw_memset_zero(impl, sizeof(*impl));

    impl->shared = shared;
    impl->slice_num = slice_num;
    impl->slice_size = slice_size;
    impl->size = size;
    impl->memory = memory;
    impl->allocated = true;
    impl->init();
}

/**
 * create new FixedPool, Using the given memory
 */
FixedPool::FixedPool(uint32_t slice_size, void *memory, size_t size, bool shared) {
    impl = (FixedPoolImpl*) memory;
    memory = (char*) memory + sizeof(*impl);
    sw_memset_zero(impl, sizeof(*impl));

    impl->shared = shared;
    impl->slice_size = slice_size;
    impl->size = size - sizeof(*impl);
    impl->slice_num = impl->size / (slice_size + sizeof(FixedPoolSlice));
    impl->memory = memory;
    impl->allocated = false;
    impl->init();
}

size_t FixedPool::sizeof_struct_slice() {
    return sizeof(FixedPoolSlice);
}

size_t FixedPool::sizeof_struct_impl() {
    return sizeof(FixedPoolImpl);
}

/**
 * linked list
 */
void FixedPoolImpl::init() {
    FixedPoolSlice *slice;
    void *cur = memory;
    void *max = (char *) memory + size;
    do {
        slice = (FixedPoolSlice *) cur;
        sw_memset_zero(slice, sizeof(FixedPoolSlice));

        if (head != nullptr) {
            head->pre = slice;
            slice->next = head;
        } else {
            tail = slice;
        }

        head = slice;
        cur = (char *) cur + (sizeof(FixedPoolSlice) + slice_size);

        if (cur < max) {
            slice->pre = (FixedPoolSlice *) cur;
        } else {
            slice->pre = nullptr;
            break;
        }

    } while (1);
}

void *FixedPool::alloc(uint32_t size) {
    FixedPoolSlice *slice;

    slice = impl->head;

    if (slice->lock == 0) {
        slice->lock = 1;
        impl->slice_use++;
        /**
         * move next slice to head (idle list)
         */
        impl->head = slice->next;
        slice->next->pre = nullptr;

        /*
         * move this slice to tail (busy list)
         */
        impl->tail->next = slice;
        slice->next = nullptr;
        slice->pre = impl->tail;
        impl->tail = slice;

        return slice->data;
    } else {
        return nullptr;
    }
}

void FixedPool::free(void *ptr) {
    FixedPoolSlice *slice;

    assert(ptr > impl->memory && (char *) ptr < (char *) impl->memory + impl->size);

    slice = (FixedPoolSlice *) ((char *) ptr - sizeof(FixedPoolSlice));

    if (slice->lock) {
        impl->slice_use--;
    }

    slice->lock = 0;

    // list head, AB
    if (slice->pre == nullptr) {
        return;
    }
    // list tail, DE
    if (slice->next == nullptr) {
        slice->pre->next = nullptr;
        impl->tail = slice->pre;
    }
    // middle BCD
    else {
        slice->pre->next = slice->next;
        slice->next->pre = slice->pre;
    }

    slice->pre = nullptr;
    slice->next = impl->head;
    impl->head->pre = slice;
    impl->head = slice;
}

FixedPool::~FixedPool() {
    if (!impl->allocated) {
        return;
    }
    if (impl->shared) {
        ::sw_shm_free(impl);
    } else {
        ::sw_free(impl);
    }
}

void FixedPool::debug() {
    int line = 0;
    FixedPoolSlice *slice = impl->head;

    printf("===============================%s=================================\n", __FUNCTION__);
    while (slice != nullptr) {
        if (slice->next == slice) {
            printf("-------------------@@@@@@@@@@@@@@@@@@@@@@----------------\n");
        }

        printf("#%d\t", line);
        printf("Slab[%p]\t", slice);
        printf("pre=%p\t", slice->pre);
        printf("next=%p\t", slice->next);
        printf("tag=%d\t", slice->lock);
        printf("data=%p\n", slice->data);

        slice = slice->next;
        line++;
        if (line > 100) break;
    }
}

}
