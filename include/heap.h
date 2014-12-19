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
 | license@php.net so we can mail you a copy immediately.               |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#ifndef SW_MINHEAP_H_
#define SW_MINHEAP_H_

enum swHeap_type
{
    SW_MIN_HEAP, SW_MAX_HEAP,
};

typedef struct swHeap_node
{
    uint32_t priority;
    uint32_t position;
    void *data;
} swHeap_node;

typedef struct _swHeap
{
    uint32_t size;
    uint32_t avail;
    uint32_t step;
    uint8_t type;
    swHeap_node **nodes;
} swHeap;

swHeap *swHeap_new(size_t n, uint8_t type);
void swHeap_free(swHeap *q);
uint32_t swHeap_size(swHeap *q);
void* swHeap_insert(swHeap *q, uint32_t priority, void *data);
void swHeap_change_priority(swHeap *q, uint32_t new_pri, void* ptr);
void *swHeap_pop(swHeap *q);
int swHeap_remove(swHeap *heap, void* ptr);
void *swHeap_peek(swHeap *q);
int swHeap_is_valid(swHeap *q);

#endif /* SW_MINHEAP_H_ */
