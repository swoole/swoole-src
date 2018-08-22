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

#define SW_MIN_PAGE_SIZE  4096

typedef struct _swMemoryGlobal_page
{
    struct _swMemoryGlobal_page *next;
    char memory[0];
} swMemoryGlobal_page;

typedef struct _swMemoryGlobal
{
    uint8_t shared;
    uint32_t pagesize;
    swLock lock;
    swMemoryGlobal_page *root_page;
    swMemoryGlobal_page *current_page;
    uint32_t current_offset;
} swMemoryGlobal;

static void *swMemoryGlobal_alloc(swMemoryPool *pool, uint32_t size);
static void swMemoryGlobal_free(swMemoryPool *pool, void *ptr);
static void swMemoryGlobal_destroy(swMemoryPool *poll);
static swMemoryGlobal_page* swMemoryGlobal_new_page(swMemoryGlobal *gm);

swMemoryPool* swMemoryGlobal_new(uint32_t pagesize, uint8_t shared)
{
    swMemoryGlobal gm, *gm_ptr;
    assert(pagesize >= SW_MIN_PAGE_SIZE);
    bzero(&gm, sizeof(swMemoryGlobal));

    gm.shared = shared;
    gm.pagesize = pagesize;

    swMemoryGlobal_page *page = swMemoryGlobal_new_page(&gm);
    if (page == NULL)
    {
        return NULL;
    }
    if (swMutex_create(&gm.lock, shared) < 0)
    {
        return NULL;
    }

    gm.root_page = page;

    gm_ptr = (swMemoryGlobal *) page->memory;
    gm.current_offset += sizeof(swMemoryGlobal);

    swMemoryPool *allocator = (swMemoryPool *) (page->memory + gm.current_offset);
    gm.current_offset += sizeof(swMemoryPool);

    allocator->object = gm_ptr;
    allocator->alloc = swMemoryGlobal_alloc;
    allocator->destroy = swMemoryGlobal_destroy;
    allocator->free = swMemoryGlobal_free;

    memcpy(gm_ptr, &gm, sizeof(gm));
    return allocator;
}

static swMemoryGlobal_page* swMemoryGlobal_new_page(swMemoryGlobal *gm)
{
    swMemoryGlobal_page *page = (gm->shared == 1) ? sw_shm_malloc(gm->pagesize) : sw_malloc(gm->pagesize);
    if (page == NULL)
    {
        return NULL;
    }
    bzero(page, gm->pagesize);
    page->next = NULL;

    if (gm->current_page != NULL)
    {
        gm->current_page->next = page;
    }

    gm->current_page = page;
    gm->current_offset = 0;

    return page;
}

static void *swMemoryGlobal_alloc(swMemoryPool *pool, uint32_t size)
{
    swMemoryGlobal *gm = pool->object;
    gm->lock.lock(&gm->lock);
    if (size > gm->pagesize - sizeof(swMemoryGlobal_page))
    {
        swWarn("failed to alloc %d bytes, exceed the maximum size[%d].", size, gm->pagesize - (int) sizeof(swMemoryGlobal_page));
        gm->lock.unlock(&gm->lock);
        return NULL;
    }
    if (gm->current_offset + size > gm->pagesize - sizeof(swMemoryGlobal_page))
    {
        swMemoryGlobal_page *page = swMemoryGlobal_new_page(gm);
        if (page == NULL)
        {
            swWarn("swMemoryGlobal_alloc alloc memory error.");
            gm->lock.unlock(&gm->lock);
            return NULL;
        }
        gm->current_page = page;
    }
    void *mem = gm->current_page->memory + gm->current_offset;
    gm->current_offset += size;
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
    swMemoryGlobal_page *page = gm->root_page;
    swMemoryGlobal_page *next;

    do
    {
        next = page->next;
        sw_shm_free(page);
        page = next;
    } while (page);
}
