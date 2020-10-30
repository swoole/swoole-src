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

#if defined(MAP_ANON) && !defined(MAP_ANONYMOUS)
#define MAP_ANONYMOUS MAP_ANON
#endif

#if defined(MAP_HUGETLB) || defined(MAP_ALIGNED_SUPER)
#define MAP_HUGE_PAGE 1
#endif

#include <sys/mman.h>

#define SW_SHM_MMAP_FILE_LEN 64

namespace swoole {

struct SharedMemory {
    size_t size_;
#ifndef MAP_ANONYMOUS
    char mapfile_[SW_SHM_MMAP_FILE_LEN];
    int tmpfd_;
#endif

    static void *alloc(size_t size, const char *mapfile);
    static void free(void *ptr);

    static SharedMemory *fetch_object(void *ptr) {
        return (SharedMemory *) ((char *) ptr - sizeof(SharedMemory));
    }
};

void *SharedMemory::alloc(size_t size, const char *mapfile) {
    void *mem;
    int tmpfd = -1;
    int flag = MAP_SHARED;
    SharedMemory object;

    size = SW_MEM_ALIGNED_SIZE(size);
    size += sizeof(SharedMemory);

#ifdef MAP_ANONYMOUS
    flag |= MAP_ANONYMOUS;
#else
    if (mapfile == nullptr) {
        mapfile = "/dev/zero";
    }
    if ((tmpfd = open(mapfile, O_RDWR)) < 0) {
        return nullptr;
    }
    sw_strlcpy(object->mapfile_, mapfile, SW_SHM_MMAP_FILE_LEN);
    object->tmpfd_ = tmpfd;
#endif

#if defined(SW_USE_HUGEPAGE) && defined(MAP_HUGE_PAGE)
    if (size > 2 * 1024 * 1024) {
#if defined(MAP_HUGETLD)
        flag |= MAP_HUGETLB;
#elif defined(MAP_ALIGNED_SUPER)
        flag &= ~MAP_ANONYMOUS;
        flag |= MAP_ALIGNED_SUPER;
#endif
    }
#endif

    mem = mmap(nullptr, size, PROT_READ | PROT_WRITE, flag, tmpfd, 0);
#ifdef MAP_FAILED
    if (mem == MAP_FAILED)
#else
    if (!mem)
#endif
    {
        swSysWarn("mmap(%lu) failed", size);
        return nullptr;
    } else {
        object.size_ = size;
        memcpy(mem, &object, sizeof(object));
        return (char *) mem + sizeof(object);
    }
}

void SharedMemory::free(void *ptr) {
    SharedMemory *object = SharedMemory::fetch_object(ptr);
    size_t size = object->size_;
    if (munmap(object, size) < 0) {
        swSysWarn("munmap(%p, %lu) failed", object, size);
    }
}

}  // namespace swoole

using swoole::SharedMemory;

void *sw_shm_malloc(size_t size) {
    return SharedMemory::alloc(size, nullptr);
}

void *sw_shm_calloc(size_t num, size_t _size) {
    return SharedMemory::alloc(num * _size, nullptr);
}

int sw_shm_protect(void *ptr, int flags) {
    SharedMemory *object = SharedMemory::fetch_object(ptr);
    return mprotect(object, object->size_, flags);
}

void sw_shm_free(void *ptr) {
    SharedMemory::free(ptr);
}

void *sw_shm_realloc(void *ptr, size_t new_size) {
    SharedMemory *object = SharedMemory::fetch_object(ptr);
    void *new_ptr = sw_shm_malloc(new_size);
    if (new_ptr == nullptr) {
        return nullptr;
    }
    memcpy(new_ptr, ptr, object->size_);
    SharedMemory::free(ptr);
    return new_ptr;
}
