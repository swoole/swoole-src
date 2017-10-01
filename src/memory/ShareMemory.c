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
#include <sys/shm.h>

void* sw_shm_malloc(size_t size)
{
    swShareMemory object;
    void *mem;
    size += sizeof(swShareMemory);
    mem = swShareMemory_mmap_create(&object, size, NULL);
    if (mem == NULL)
    {
        return NULL;
    }
    else
    {
        memcpy(mem, &object, sizeof(swShareMemory));
        return mem + sizeof(swShareMemory);
    }
}

void* sw_shm_calloc(size_t num, size_t _size)
{
    swShareMemory object;
    void *mem;
    void *ret_mem;
    int size = sizeof(swShareMemory) + (num * _size);
    mem = swShareMemory_mmap_create(&object, size, NULL);
    if (mem == NULL)
    {
        return NULL;
    }
    else
    {
        memcpy(mem, &object, sizeof(swShareMemory));
        ret_mem = mem + sizeof(swShareMemory);
        bzero(ret_mem, size - sizeof(swShareMemory));
        return ret_mem;
    }
}

int sw_shm_protect(void *addr, int flags)
{
    swShareMemory *object = (swShareMemory *) (addr - sizeof(swShareMemory));
    return mprotect(object, object->size, flags);
}

void sw_shm_free(void *ptr)
{
    swShareMemory *object = ptr - sizeof(swShareMemory);
    swShareMemory_mmap_free(object);
}

void* sw_shm_realloc(void *ptr, size_t new_size)
{
    swShareMemory *object = ptr - sizeof(swShareMemory);
    void *new_ptr;
    new_ptr = sw_shm_malloc(new_size);
    if (new_ptr == NULL)
    {
        return NULL;
    }
    else
    {
        memcpy(new_ptr, ptr, object->size);
        sw_shm_free(ptr);
        return new_ptr;
    }
}

void *swShareMemory_mmap_create(swShareMemory *object, size_t size, char *mapfile)
{
    void *mem;
    int tmpfd = -1;
    int flag = MAP_SHARED;
    bzero(object, sizeof(swShareMemory));

#ifdef MAP_ANONYMOUS
    flag |= MAP_ANONYMOUS;
#else
    if (mapfile == NULL)
    {
        mapfile = "/dev/zero";
    }
    if ((tmpfd = open(mapfile, O_RDWR)) < 0)
    {
        return NULL;
    }
    strncpy(object->mapfile, mapfile, SW_SHM_MMAP_FILE_LEN);
    object->tmpfd = tmpfd;
#endif

#if defined(SW_USE_HUGEPAGE) && defined(MAP_HUGETLB)
    if (size > 2 * 1024 * 1024)
    {
        flag |= MAP_HUGETLB;
    }
#endif

    mem = mmap(NULL, size, PROT_READ | PROT_WRITE, flag, tmpfd, 0);
#ifdef MAP_FAILED
    if (mem == MAP_FAILED)
#else
    if (!mem)
#endif
    {
        swWarn("mmap(%ld) failed. Error: %s[%d]", size, strerror(errno), errno);
        return NULL;
    }
    else
    {
        object->size = size;
        object->mem = mem;
        return mem;
    }
}

int swShareMemory_mmap_free(swShareMemory *object)
{
    return munmap(object->mem, object->size);
}

void *swShareMemory_sysv_create(swShareMemory *object, size_t size, int key)
{
    int shmid;
    void *mem;
    bzero(object, sizeof(swShareMemory));

    if (key == 0)
    {
        key = IPC_PRIVATE;
    }
    //SHM_R | SHM_W
    if ((shmid = shmget(key, size, IPC_CREAT)) < 0)
    {
        swSysError("shmget(%d, %ld) failed.", key, size);
        return NULL;
    }
    if ((mem = shmat(shmid, NULL, 0)) == (void *) -1)
    {
        swWarn("shmat() failed. Error: %s[%d]", strerror(errno), errno);
        return NULL;
    }
    else
    {
        object->key = key;
        object->shmid = shmid;
        object->size = size;
        object->mem = mem;
        return mem;
    }
}

int swShareMemory_sysv_free(swShareMemory *object, int rm)
{
    int shmid = object->shmid;
    int ret = shmdt(object->mem);
    if (rm == 1)
    {
        shmctl(shmid, IPC_RMID, NULL);
    }
    return ret;
}
