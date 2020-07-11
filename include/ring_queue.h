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

#ifndef _SW_RINGQUEUE_H_
#define _SW_RINGQUEUE_H_

struct swRingQueue {
    int head;
    int tail;
    /**
     * empty or full
     */
    int tag;
    int size;
    void **data;
};

int swRingQueue_init(swRingQueue *queue, int buffer_size);
int swRingQueue_push(swRingQueue *queue, void *);
int swRingQueue_pop(swRingQueue *queue, void **);
void swRingQueue_free(swRingQueue *queue);

static inline int swRingQueue_count(swRingQueue *queue) {
    if (queue->tail > queue->head) {
        return queue->tail - queue->head;
    } else if (queue->head == queue->tail) {
        return queue->tag == 1 ? queue->size : 0;
    } else {
        return queue->tail + queue->size - queue->head;
    }
}

#define swRingQueue_empty(q) ((q->head == q->tail) && (q->tag == 0))
#define swRingQueue_full(q) ((q->head == q->tail) && (q->tag == 1))
#endif
