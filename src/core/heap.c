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
    heap->num = 1;
    heap->size = (n + 1);
    heap->type = type;
    return heap;
}

void swHeap_free(swHeap *heap)
{
    sw_free(heap->nodes);
    sw_free(heap);
}

static sw_inline int swHeap_compare(uint8_t type, uint64_t a, uint64_t b)
{
    if (type == SW_MIN_HEAP)
    {
        return a > b;
    }
    else
    {
        return a < b;
    }
}

uint32_t swHeap_size(swHeap *q)
{
    return (q->num - 1);
}

static uint32_t swHeap_maxchild(swHeap *heap, uint32_t i)
{
    uint32_t child_i = left(i);
    swHeap_node * child_node = heap->nodes[child_i];

    if (child_i >= heap->num)
    {
        return 0;
    }

    if ((child_i + 1) < heap->num && swHeap_compare(heap->type, child_node->priority, heap->nodes[child_i + 1]->priority))
    {
        child_i++;
    }
    return child_i;
}

static void swHeap_bubble_up(swHeap *heap, uint32_t i)
{
    swHeap_node *moving_node = heap->nodes[i];
    uint32_t parent_i;

    for (parent_i = parent(i);
            (i > 1) && swHeap_compare(heap->type, heap->nodes[parent_i]->priority, moving_node->priority);
            i = parent_i, parent_i = parent(i))
    {
        heap->nodes[i] = heap->nodes[parent_i];
        heap->nodes[i]->position = i;
    }

    heap->nodes[i] = moving_node;
    moving_node->position = i;
}

static void swHeap_percolate_down(swHeap *heap, uint32_t i)
{
    uint32_t child_i;
    swHeap_node *moving_node = heap->nodes[i];

    while ((child_i = swHeap_maxchild(heap, i))
            && swHeap_compare(heap->type, moving_node->priority, heap->nodes[child_i]->priority))
    {
        heap->nodes[i] = heap->nodes[child_i];
        heap->nodes[i]->position = i;
        i = child_i;
    }

    heap->nodes[i] = moving_node;
    moving_node->position = i;
}

swHeap_node* swHeap_push(swHeap *heap, uint64_t priority, void *data)
{
    void *tmp;
    uint32_t i;
    uint32_t newsize;

    if (heap->num >= heap->size)
    {
        newsize = heap->size * 2;
        if (!(tmp = sw_realloc(heap->nodes, sizeof(void *) * newsize)))
        {
            return NULL;
        }
        heap->nodes = tmp;
        heap->size = newsize;
    }

    swHeap_node *node = sw_malloc(sizeof(swHeap_node));
    if (!node)
    {
        return NULL;
    }
    node->priority = priority;
    node->data = data;
    i = heap->num++;
    heap->nodes[i] = node;
    swHeap_bubble_up(heap, i);
    return node;
}

void swHeap_change_priority(swHeap *heap, uint64_t new_priority, void* ptr)
{
    swHeap_node *node = ptr;
    uint32_t pos = node->position;
    uint64_t old_pri = node->priority;

    node->priority = new_priority;
    if (swHeap_compare(heap->type, old_pri, new_priority))
    {
        swHeap_bubble_up(heap, pos);
    }
    else
    {
        swHeap_percolate_down(heap, pos);
    }
}

int swHeap_remove(swHeap *heap, swHeap_node *node)
{
    uint32_t pos = node->position;
    heap->nodes[pos] = heap->nodes[--heap->num];

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
    if (!heap || heap->num == 1)
    {
        return NULL;
    }

    head = heap->nodes[1];
    heap->nodes[1] = heap->nodes[--heap->num];
    swHeap_percolate_down(heap, 1);

    void *data = head->data;
    sw_free(head);
    return data;
}

void *swHeap_peek(swHeap *heap)
{
    if (heap->num == 1)
    {
        return NULL;
    }
    swHeap_node *node = heap->nodes[1];
    if (!node)
    {
        return NULL;
    }
    return node->data;
}

void swHeap_print(swHeap *heap)
{
    int i;
    for(i = 1; i < heap->num; i++)
    {
        printf("#%d\tpriority=%ld, data=%p\n", i, heap->nodes[i]->priority, heap->nodes[i]->data);
    }
}
