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

#include <vector>
#include <list>
#include <mutex>

using namespace std;

#define SW_MIN_PAGE_SIZE  4096
#define SW_MIN_EXPONENT   5     //32
#define SW_MAX_EXPONENT   21    //2M

struct MemoryBlock;

struct MemoryPool
{
    pid_t create_pid;
    bool shared;
    uint32_t pagesize;
    mutex lock;
    vector<char *> pages;
    vector<list<MemoryBlock *>> pool;
    uint32_t alloc_offset;
    swMemoryPool allocator;
};

struct MemoryBlock
{
    uint32_t size;
    uint32_t index;
    bool shared;
    pid_t create_pid;
    char memory[0];
};

static void *swMemoryGlobal_alloc(swMemoryPool *pool, uint32_t size);
static void swMemoryGlobal_free(swMemoryPool *pool, void *ptr);
static void swMemoryGlobal_destroy(swMemoryPool *pool);
static char *swMemoryGlobal_new_page(MemoryPool *gm);

swMemoryPool *swMemoryGlobal_new(uint32_t pagesize, uint8_t shared)
{
    assert(pagesize >= SW_MIN_PAGE_SIZE);

    MemoryPool *gm = new MemoryPool();

    gm->shared = shared;
    gm->pagesize = SW_MEM_ALIGNED_SIZE_EX(pagesize, SwooleG.pagesize);
    gm->create_pid = SwooleG.pid;
    gm->pool.resize(20);

    char *page = swMemoryGlobal_new_page(gm);
    if (page == nullptr)
    {
        return nullptr;
    }

    swMemoryPool *allocator = &gm->allocator;
    allocator->object = gm;
    allocator->alloc = swMemoryGlobal_alloc;
    allocator->destroy = swMemoryGlobal_destroy;
    allocator->free = swMemoryGlobal_free;

    return allocator;
}

static char *swMemoryGlobal_new_page(MemoryPool *gm)
{
    char *page = (char *) (gm->shared ? sw_shm_malloc(gm->pagesize) : sw_malloc(gm->pagesize));
    if (page == nullptr)
    {
        return nullptr;
    }
    sw_memset_zero(page, gm->pagesize);

    gm->pages.push_back(page);
    gm->alloc_offset = 0;

    return page;
}

static void *swMemoryGlobal_alloc(swMemoryPool *pool, uint32_t size)
{
    MemoryPool *gm = (MemoryPool *) pool->object;
    MemoryBlock *block;
    uint32_t alloc_size = sizeof(MemoryBlock) + size;
    unique_lock<mutex> lock(gm->lock);

    if (alloc_size > gm->pagesize)
    {
        swWarn("failed to alloc %d bytes, exceed the maximum size[%d]", size, gm->pagesize);
        return nullptr;
    }

    int index = SW_MIN_EXPONENT;
    if (alloc_size > (1 << SW_MIN_EXPONENT))
    {
        for (; index <= SW_MAX_EXPONENT; index++)
        {
            if ((alloc_size >> index) == 1)
            {
                break;
            }
        }
        index++;
    }
    alloc_size = 1 << (index);
    swTrace("alloc_size = %d, size=%d, index=%d\n", alloc_size, size, index);
    index -= SW_MIN_EXPONENT;

    list<MemoryBlock *> &free_blocks = gm->pool.at(index);
    if (!free_blocks.empty())
    {
        block = free_blocks.back();
        free_blocks.pop_back();
        return block->memory;
    }

    if (gm->alloc_offset + alloc_size > gm->pagesize)
    {
        char *page = swMemoryGlobal_new_page(gm);
        if (page == nullptr)
        {
            swWarn("alloc memory error");
            return nullptr;
        }
    }

    block = (MemoryBlock *) gm->pages.back() + gm->alloc_offset;
    gm->alloc_offset += alloc_size;

    block->size = size;
    block->index = index;
    block->shared = gm->shared;
    block->create_pid = SwooleG.pid;

    return block->memory;
}

static void swMemoryGlobal_free(swMemoryPool *pool, void *ptr)
{
    MemoryPool *gm = (MemoryPool *) pool->object;
    MemoryBlock *block = (MemoryBlock *) ((char*) ptr - sizeof(*block));
    unique_lock<mutex> lock(gm->lock);

    swTrace("[PID=%d] gm->create_pid=%d, block->create_pid=%d, SwooleG.pid=%d\n", getpid(), gm->create_pid,
            block->create_pid, SwooleG.pid);

    if (block->shared && (gm->create_pid != block->create_pid or block->create_pid != SwooleG.pid))
    {
        return;
    }

    swTrace("[PID=%d] free block\n", getpid());

    list<MemoryBlock *> &free_blocks = gm->pool.at(block->index);
    free_blocks.push_back(block);
}

static void swMemoryGlobal_destroy(swMemoryPool *pool)
{
    MemoryPool *gm = (MemoryPool *) pool->object;

    if (gm->shared and gm->create_pid != SwooleG.pid)
    {
        delete gm;
        return;
    }

    for (auto page : gm->pages)
    {
        gm->shared ? sw_shm_free(page) : sw_free(page);
    }
    delete gm;
}
