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

#include "swoole.h"
#include "swoole_memory.h"

namespace swoole {

struct FixedPoolSlice {
    uint8_t lock;
    FixedPoolSlice *next;
    FixedPoolSlice *prev;
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
    if (slice_num < 2) {
        throw Exception(SW_ERROR_INVALID_PARAMS);
    }
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
    impl = (FixedPoolImpl *) memory;
    memory = (char *) memory + sizeof(*impl);
    sw_memset_zero(impl, sizeof(*impl));
    impl->shared = shared;
    impl->slice_size = slice_size;
    impl->size = size - sizeof(*impl);
    uint32_t slice_num = impl->size / (slice_size + sizeof(FixedPoolSlice));
    if (slice_num < 2) {
        throw Exception(SW_ERROR_INVALID_PARAMS);
    }
    impl->slice_num = slice_num;
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
            head->prev = slice;
            slice->next = head;
        } else {
            tail = slice;
        }

        head = slice;
        cur = (char *) cur + (sizeof(FixedPoolSlice) + slice_size);

        if (cur < max) {
            slice->prev = (FixedPoolSlice *) cur;
        } else {
            slice->prev = nullptr;
            break;
        }

    } while (1);
}

uint32_t FixedPool::get_number_of_spare_slice() {
    return impl->slice_num - impl->slice_use;
}

uint32_t FixedPool::get_number_of_total_slice() {
    return impl->slice_num;
}

uint32_t FixedPool::get_slice_size() {
    return impl->slice_size;
}

void *FixedPool::alloc(uint32_t size) {
    FixedPoolSlice *slice = impl->head;
    if (slice->lock) {
        swoole_set_last_error(SW_ERROR_MALLOC_FAIL);
        assert(get_number_of_spare_slice() == 0);
        return nullptr;
    }

    slice->lock = 1;
    impl->slice_use++;

    // move next slice to head (idle list)
    impl->head = slice->next;
    impl->head->prev = nullptr;

    // move this slice to tail (busy list)
    impl->tail->next = slice;
    slice->next = nullptr;
    slice->prev = impl->tail;
    impl->tail = slice;

    return slice->data;
}

void FixedPool::free(void *ptr) {
    FixedPoolSlice *slice = (FixedPoolSlice *) ((char *) ptr - sizeof(FixedPoolSlice));

    assert(ptr > impl->memory && (char *) ptr < (char *) impl->memory + impl->size);
    assert(slice->lock == 1);

    impl->slice_use--;
    slice->lock = 0;

    if (slice == impl->head) {
        return;
    }

    if (slice == impl->tail) {
        slice->prev->next = nullptr;
        impl->tail = slice->prev;
    } else {
        slice->prev->next = slice->next;
        slice->next->prev = slice->prev;
    }

    // move slice to head (idle)
    slice->prev = nullptr;
    slice->next = impl->head;
    impl->head->prev = slice;
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

void FixedPool::debug(int max_lines) {
    int line = 0;
    FixedPoolSlice *slice = impl->head;

    printf("===============================%s=================================\n", __FUNCTION__);
    while (slice != nullptr) {
        if (slice->next == slice) {
            printf("-------------------@@@@@@@@@@@@@@@@@@@@@@----------------\n");
        }

        printf("#%d\t", line);
        printf("slice[%p]\t", slice);
        printf("prev=%p\t", slice->prev);
        printf("next=%p\t", slice->next);
        printf("tag=%d\t", slice->lock);
        printf("data=%p\n", slice->data);

        slice = slice->next;
        if (line++ > max_lines) {
            break;
        }
    }
}

}  // namespace swoole
