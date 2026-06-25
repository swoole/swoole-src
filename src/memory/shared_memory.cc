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

#include "swoole_memory.h"

#include <limits>

#ifndef _WIN32
#include <sys/mman.h>

#if defined(MAP_ANON) && !defined(MAP_ANONYMOUS)
#define MAP_ANONYMOUS MAP_ANON
#endif
#endif

namespace swoole {

struct SharedMemory {
    size_t size_;

    static void *alloc(size_t size);
    static void free(void *ptr);

    static SharedMemory *fetch_object(void *ptr) {
        return reinterpret_cast<SharedMemory *>(static_cast<char *>(ptr) - sizeof(SharedMemory));
    }
};

void *SharedMemory::alloc(size_t size) {
    void *mem;
    SharedMemory object;

    if (sw_unlikely(size > std::numeric_limits<size_t>::max() - SW_DEFAULT_ALIGNMENT + 1)) {
        return nullptr;
    }
    size = SW_MEM_ALIGNED_SIZE(size);
    if (sw_unlikely(size > std::numeric_limits<size_t>::max() - sizeof(SharedMemory))) {
        return nullptr;
    }
    size += sizeof(SharedMemory);

#ifdef _WIN32
    mem = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem)
#else
    int tmpfd = -1;
    int flags = MAP_SHARED;
#ifdef MAP_ANONYMOUS
    flags |= MAP_ANONYMOUS;
#else
    File zerofile("/dev/zero", O_RDWR);
    if (!zerofile.ready()) {
        return nullptr;
    }
    tmpfd = zerofile.get_fd();
#endif
    mem = mmap(nullptr, size, PROT_READ | PROT_WRITE, flags, tmpfd, 0);
#ifdef MAP_FAILED
    if (mem == MAP_FAILED)
#else
    if (!mem)
#endif
#endif
    {
        swoole_sys_warning("mmap(%lu) failed", size);
        return nullptr;
    } else {
        object.size_ = size;
        memcpy(mem, &object, sizeof(object));
        return static_cast<char *>(mem) + sizeof(object);
    }
}

void SharedMemory::free(void *ptr) {
    SharedMemory *object = SharedMemory::fetch_object(ptr);
    size_t size = object->size_;
#ifdef _WIN32
    if (!VirtualFree(object, 0, MEM_RELEASE)) {
        swoole_sys_warning("VirtualFree(%p, %lu) failed", object, size);
    }
#else
    if (munmap(object, size) < 0) {
        swoole_sys_warning("munmap(%p, %lu) failed", object, size);
    }
#endif
}

}  // namespace swoole

using swoole::SharedMemory;

void *sw_shm_malloc(size_t size) {
    return SharedMemory::alloc(size);
}

void *sw_shm_calloc(size_t num, size_t _size) {
    if (sw_unlikely(num != 0 && _size > std::numeric_limits<size_t>::max() / num)) {
        return nullptr;
    }
    // mmap MAP_ANONYMOUS / VirtualAlloc guarantee zero-filled pages, so no explicit memset needed
    return SharedMemory::alloc(num * _size);
}

int sw_shm_protect(void *ptr, int flags) {
    SharedMemory *object = SharedMemory::fetch_object(ptr);
#ifdef _WIN32
    DWORD winprot;
    if ((flags & PROT_READ) && (flags & PROT_WRITE)) {
        winprot = PAGE_READWRITE;
    } else if (flags & PROT_READ) {
        winprot = PAGE_READONLY;
    } else {
        winprot = PAGE_NOACCESS;
    }
    DWORD oldprot;
    return VirtualProtect(object, object->size_, winprot, &oldprot) ? 0 : -1;
#else
    return mprotect(object, object->size_, flags);
#endif
}

void sw_shm_free(void *ptr) {
    SharedMemory::free(ptr);
}

void *sw_shm_realloc(void *ptr, size_t new_size) {
    SharedMemory *object = SharedMemory::fetch_object(ptr);
    size_t old_size = object->size_ - sizeof(SharedMemory);
    if (sw_unlikely(new_size < old_size)) {
        // Shared memory realloc is grow-only; callers must allocate/copy/free explicitly to shrink.
        return nullptr;
    }
    void *new_ptr = sw_shm_malloc(new_size);
    if (new_ptr == nullptr) {
        return nullptr;
    }
    memcpy(new_ptr, ptr, old_size);
    SharedMemory::free(ptr);
    return new_ptr;
}
