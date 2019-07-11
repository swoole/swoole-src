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
#include <stdio.h>
#include "swoole.h"
#include "ring_queue.h"

int swRingQueue_init(swRingQueue *queue, int buffer_size)
{
    queue->data = sw_calloc(buffer_size, sizeof(void*));
    if (queue->data == NULL)
    {
        swWarn("malloc failed");
        return -1;
    }
    queue->size = buffer_size;
    queue->head = 0;
    queue->tail = 0;
    queue->tag = 0;
    return 0;
}

void swRingQueue_free(swRingQueue *queue)
{
    sw_free(queue->data);
}

int swRingQueue_push(swRingQueue *queue, void *push_data)
{
    if (swRingQueue_full(queue))
    {
        return SW_ERR;
    }

    queue->data[queue->tail] = push_data;
    queue->tail = (queue->tail + 1) % queue->size;

    if (queue->tail == queue->head)
    {
        queue->tag = 1;
    }
    return SW_OK;
}

int swRingQueue_pop(swRingQueue *queue, void **pop_data)
{
    if (swRingQueue_empty(queue))
    {
        return SW_ERR;
    }

    *pop_data = queue->data[queue->head];
    queue->head = (queue->head + 1) % queue->size;

    if (queue->tail == queue->head)
    {
        queue->tag = 0;
    }
    return SW_OK;
}
