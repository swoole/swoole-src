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
#include "heap.h"

#define left(i)   ((i) << 1)
#define right(i)  (((i) << 1) + 1)
#define parent(i) ((i) >> 1)

static void swHeap_bubble_up(swHeap *heap, uint32_t i);
static uint32_t swHeap_maxchild(swHeap *heap, uint32_t i);
static void swHeap_percolate_down(swHeap *heap, uint32_t i);
static int subtree_is_valid(swHeap *heap, uint32_t pos);

swHeap *swHeap_new(size_t n, uint8_t type)
{
    swHeap *heap = sw_malloc(sizeof(swHeap));
    if (!heap)
    {
        return NULL;
    }
    if (!(heap->nodes = sw_malloc((n + 1) * sizeof(void *))))
    {
        sw_free(heap);
        return NULL;
    }

    heap->size = 1;
    heap->avail = heap->step = (n + 1);
    heap->type = type;
    return heap;
}

void swHeap_free(swHeap *heap)
{
    sw_free(heap->nodes);
    sw_free(heap);
}

static sw_inline int swHeap_compare(uint8_t type, uint32_t next, uint32_t curr)
{
    if (type == SW_MIN_HEAP)
    {
        return next > curr;
    }
    else
    {
        return next < curr;
    }
}

uint32_t swHeap_size(swHeap *q)
{
    return (q->size - 1);
}

static void swHeap_bubble_up(swHeap *heap, uint32_t i)
{
    swHeap_node *moving_node = heap->nodes[i];
    uint32_t moving_pri = moving_node->priority;

    uint32_t parent_i;
    for (parent_i = parent(i); (i > 1) && swHeap_compare(heap->type, heap->nodes[parent_i]->priority, moving_pri); i =
            parent_i, parent_i = parent(i))
    {
        heap->nodes[i] = heap->nodes[parent_i];
        heap->nodes[i]->position = i;
    }

    heap->nodes[i] = moving_node;
    moving_node->position = i;
}

static uint32_t swHeap_maxchild(swHeap *heap, uint32_t i)
{
    uint32_t child_i = left(i);
    swHeap_node * child_node = heap->nodes[child_i];

    if (child_i >= heap->size)
    {
        return 0;
    }
    if ((child_i + 1) < heap->size
            && swHeap_compare(heap->type, child_node->priority, heap->nodes[child_i + 1]->priority))
    {
        child_i++;
    }
    return child_i;
}

static void swHeap_percolate_down(swHeap *heap, uint32_t i)
{
    uint32_t child_i;
    swHeap_node *moving_node = heap->nodes[i];
    uint32_t moving_pri = moving_node->priority;

    while ((child_i = swHeap_maxchild(heap, i))
            && swHeap_compare(heap->type, moving_pri, heap->nodes[child_i]->priority))
    {
        heap->nodes[i] = heap->nodes[child_i];
        heap->nodes[i]->position = i;
        i = child_i;
    }

    heap->nodes[i] = moving_node;
    moving_node->position = i;
}

void* swHeap_insert(swHeap *heap, uint32_t priority, void *data)
{
    void *tmp;
    uint32_t i;
    uint32_t newsize;

    if (heap->size >= heap->avail)
    {
        newsize = heap->size + heap->step;
        if (!(tmp = sw_realloc(heap->nodes, sizeof(void *) * newsize)))
        {
            return NULL;
        }
        heap->nodes = tmp;
        heap->avail = newsize;
    }

    swHeap_node *node = sw_malloc(sizeof(swHeap_node));
    if (!node)
    {
        return NULL;
    }
    node->priority = priority;
    node->data = data;
    i = heap->size++;
    heap->nodes[i] = node;
    swHeap_bubble_up(heap, i);
    return node;
}

void swHeap_change_priority(swHeap *heap, uint32_t new_pri, void* ptr)
{
    swHeap_node *node = ptr;
    uint32_t pos = node->position;
    uint32_t old_pri = node->priority;

    node->priority = new_pri;
    if (swHeap_compare(heap->type, old_pri, new_pri))
    {
        swHeap_bubble_up(heap, pos);
    }
    else
    {
        swHeap_percolate_down(heap, pos);
    }
}

int swHeap_remove(swHeap *heap, void* ptr)
{
    swHeap_node *node = ptr;
    uint32_t pos = node->position;
    heap->nodes[pos] = heap->nodes[--heap->size];

    if (swHeap_compare(heap->type, node->priority, heap->nodes[pos]->priority))
    {
        swHeap_bubble_up(heap, pos);
    }
    else
    {
        swHeap_percolate_down(heap, pos);
    }
    return SW_OK;
}

void *swHeap_pop(swHeap *heap)
{
    swHeap_node *head;
    if (!heap || heap->size == 1)
    {
        return NULL;
    }

    head = heap->nodes[1];
    heap->nodes[1] = heap->nodes[--heap->size];
    swHeap_percolate_down(heap, 1);

    void *data = head->data;
    sw_free(head);
    return data;
}

void *swHeap_peek(swHeap *heap)
{
    swHeap_node *d;
    if (!heap || heap->size == 1)
    {
        return NULL;
    }
    d = heap->nodes[1];
    return d->data;
}

static int subtree_is_valid(swHeap *heap, uint32_t pos)
{
    if (left(pos) < heap->size)
    {
        if (swHeap_compare(heap->type, heap->nodes[pos]->priority, heap->nodes[left(pos)]->priority))
        {
            return 0;
        }
        if (!subtree_is_valid(heap, left(pos)))
        {
            return 0;
        }
    }
    if (right(pos) < heap->size)
    {
        if (swHeap_compare(heap->type, heap->nodes[pos]->priority, heap->nodes[right(pos)]->priority))
        {
            return 0;
        }
        if (!subtree_is_valid(heap, right(pos)))
        {
            return 0;
        }
    }
    return 1;
}

int swHeap_is_valid(swHeap *q)
{
    return subtree_is_valid(q, 1);
}
