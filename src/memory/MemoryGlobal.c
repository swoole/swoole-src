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

#define SW_PAGE_SIZE  256

typedef struct _swMemoryGlobal
{
    int size;
    void *mem;
    int offset;
    char shared;
    int pagesize;
    swLock lock;
    void *root_page;
    void *cur_page;
} swMemoryGlobal;

static void *swMemoryGlobal_alloc(swMemoryPool *pool, uint32_t size);
static void swMemoryGlobal_free(swMemoryPool *pool, void *ptr);
static void swMemoryGlobal_destroy(swMemoryPool *poll);
static void* swMemoryGlobal_new_page(swMemoryGlobal *gm);

swMemoryPool* swMemoryGlobal_new(int pagesize, char shared)
{
    swMemoryGlobal gm, *gm_ptr;
    assert(pagesize >= SW_PAGE_SIZE);
    bzero(&gm, sizeof(swMemoryGlobal));
    gm.shared = shared;
    gm.pagesize = pagesize;
    void *first_page = swMemoryGlobal_new_page(&gm);
    if (first_page == NULL)
    {
        return NULL;
    }
    if (swMutex_create(&gm.lock, shared) < 0)
    {
        return NULL;
    }
    //root
    gm.root_page = first_page;
    gm.cur_page = first_page;

    gm_ptr = (swMemoryGlobal *) gm.mem;
    gm.offset += sizeof(swMemoryGlobal);

    swMemoryPool *allocator = (swMemoryPool *) (gm.mem + gm.offset);
    gm.offset += sizeof(swMemoryPool);

    allocator->object = gm_ptr;
    allocator->alloc = swMemoryGlobal_alloc;
    allocator->destroy = swMemoryGlobal_destroy;
    allocator->free = swMemoryGlobal_free;

    memcpy(gm_ptr, &gm, sizeof(gm));
    return allocator;
}

static void* swMemoryGlobal_new_page(swMemoryGlobal *gm)
{
    void *page = (gm->shared == 1) ? sw_shm_malloc(gm->pagesize) : sw_malloc(gm->pagesize);
    if (page == NULL)
    {
        return NULL;
    }
    bzero(page, gm->pagesize);
    //set next page to NULL
    //save the next pointer with the first 8 bytes
    ((void **) page)[0] = NULL;

    gm->offset = 0;
    gm->size = gm->pagesize - sizeof(void*);
    gm->mem = page + sizeof(void*);
    return page;
}

static void *swMemoryGlobal_alloc(swMemoryPool *pool, uint32_t size)
{
    swMemoryGlobal *gm = pool->object;
    gm->lock.lock(&gm->lock);
    if (size > gm->pagesize)
    {
        swWarn("failed to alloc %d bytes, exceed the maximum size[%d].", size, gm->pagesize);
        gm->lock.unlock(&gm->lock);
        return NULL;
    }
    if (gm->offset + size > gm->size)
    {
        swWarn("failed to alloc new page, size=%d|offset=%d|alloc=%d", gm->size, gm->offset, size);
        void *page = swMemoryGlobal_new_page(gm);
        if (page == NULL)
        {
            swWarn("swMemoryGlobal_alloc alloc memory error.");
            gm->lock.unlock(&gm->lock);
            return NULL;
        }
        ((void **) gm->cur_page)[0] = page;
        gm->cur_page = page;
    }
    void *mem = gm->mem + gm->offset;
    gm->offset += size;
    gm->lock.unlock(&gm->lock);
    return mem;
}

static void swMemoryGlobal_free(swMemoryPool *pool, void *ptr)
{
    swWarn("swMemoryGlobal Allocator don't need to release.");
}

static void swMemoryGlobal_destroy(swMemoryPool *poll)
{
    swMemoryGlobal *gm = poll->object;
    void *page = gm->root_page;
    void *next =((void **)page)[0];
    while(next != NULL)
    {
        next = ((void **)next)[0];
        sw_shm_free(page);
        swTrace("swMemoryGlobal free=%p", next);
    }
}

