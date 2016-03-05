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

#define SW_CHANNEL_MIN_MEM (1024*64)   //最小内存分配

#define swChannel_empty(q) (q->num == 0)
#define swChannel_full(q) ((q->head == q->tail) && (q->tail_tag != q->head_tag))

typedef struct _swChannel_item
{
    int length;
    char data[0];
} swChannel_item;

int swChannel_pop(swChannel *object, void *out, int buffer_length);
int swChannel_push(swChannel *object, void *in, int data_length);
int swChannel_out(swChannel *object, void *out, int buffer_length);
int swChannel_in(swChannel *object, void *in, int data_length);
int swChannel_wait(swChannel *object);
int swChannel_notify(swChannel *object);
void swChannel_free(swChannel *object);

void swChannel_debug(swChannel *chan)
{
    printf("RingBuffer: num=%d|head=%d|tail=%d|tail_tag=%d|head_tag=%d\n", chan->num, chan->head, chan->tail, (int)chan->tail_tag, (int)chan->head_tag);
}

swChannel* swChannel_new(int size, int maxlen, int flag)
{
    assert(size > SW_CHANNEL_MIN_MEM + maxlen);
    int ret;
    void *mem;

    //use shared memory
    if (flag & SW_CHAN_SHM)
    {
        mem = sw_shm_malloc(size);
    }
    else
    {
        mem = sw_malloc(size);
    }

    if (mem == NULL)
    {
        swWarn("swChannel_create: malloc fail");
        return NULL;
    }
    swChannel *object = mem;
    mem += sizeof(swChannel);

    bzero(object, sizeof(swChannel));

    //overflow space
    object->size = size - maxlen;
    object->mem = mem;
    object->maxlen = maxlen;
    object->flag = flag;

    //use lock
    if (flag & SW_CHAN_LOCK)
    {
        //init lock
        if (swMutex_create(&object->lock, 1) < 0)
        {
            swWarn("swChannel_create: mutex init fail");
            return NULL;
        }
    }
    //use notify
    if (flag & SW_CHAN_NOTIFY)
    {
        ret = swPipeNotify_auto(&object->notify_fd, 1, 1);
        if (ret < 0)
        {
            swWarn("swChannel_create: notify_fd init fail");
            return NULL;
        }
    }
    return object;
}

/**
 * push data(no lock)
 */
int swChannel_in(swChannel *object, void *in, int data_length)
{
    assert(data_length < object->maxlen);
    //队列满了
    if (swChannel_full(object))
    {
        swWarn("queue full");
        swChannel_debug(object);
        //这里非常重要,避免此线程再次获得锁
        swYield();
        return SW_ERR;
    }
    swChannel_item *item;
    int msize = sizeof(item->length) + data_length;

    if (object->tail < object->head)
    {
        if ((object->head - object->tail) < msize)
        {
            //空间不足
            return SW_ERR;
        }
        item = object->mem + object->tail;
        object->tail += msize;
    }
    //这里tail必然小于size,无需判断,因为每次分配完会计算超过size后转到开始
    else
    {
        item = object->mem + object->tail;
        object->tail += msize;
        if (object->tail >= object->size)
        {
            object->tail = 0;
            object->tail_tag = 1 - object->tail_tag;
        }
    }
    object->num++;
    item->length = data_length;
    memcpy(item->data, in, data_length);
    return SW_OK;
}

/**
 * pop data(no lock)
 */
int swChannel_out(swChannel *object, void *out, int buffer_length)
{
    //队列为空
    if (swChannel_empty(object))
    {
        swWarn("queue empty");
        swChannel_debug(object);
        //这里非常重要,避免此线程再次获得锁
        swYield();
        return SW_ERR;
    }
    swChannel_item *item = object->mem + object->head;
    assert(buffer_length >= item->length);
//    swWarn("out,len=%d|data=%s", item->length, item->data);
    memcpy(out, item->data, item->length);
    object->head += (item->length + sizeof(item->length));
    if (object->head >= object->size)
    {
        object->head = 0;
        object->head_tag = 1 - object->head_tag;
    }
    object->num--;
    return item->length;
}

/**
 * wait notify
 */
int swChannel_wait(swChannel *object)
{
    assert(object->flag & SW_CHAN_NOTIFY);
    uint64_t flag;
    return object->notify_fd.read(&object->notify_fd, &flag, sizeof(flag));
}

/**
 * new data coming, notify to customer
 */
int swChannel_notify(swChannel *object)
{
    assert(object->flag & SW_CHAN_NOTIFY);
    uint64_t flag = 1;
    return object->notify_fd.write(&object->notify_fd, &flag, sizeof(flag));
}

/**
 * push data (lock)
 */
int swChannel_push(swChannel *object, void *in, int data_length)
{
    assert(object->flag & SW_CHAN_LOCK);
    object->lock.lock(&object->lock);
    int ret = swChannel_in(object, in, data_length);
    object->lock.unlock(&object->lock);
    return ret;
}

/**
 * free channel
 */
void swChannel_free(swChannel *object)
{
    if (object->flag & SW_CHAN_LOCK)
    {
        object->lock.free(&object->lock);
    }
    if (object->flag & SW_CHAN_NOTIFY)
    {
        object->notify_fd.close(&object->notify_fd);
    }
    if (object->flag & SW_CHAN_SHM)
    {
        sw_shm_free(object);
    }
    else
    {
        sw_free(object);
    }
}

/**
 * pop data (lock)
 */
int swChannel_pop(swChannel *object, void *out, int buffer_length)
{
    assert(object->flag & SW_CHAN_LOCK);
    object->lock.lock(&object->lock);
    int n = swChannel_out(object, out, buffer_length);
    object->lock.unlock(&object->lock);
    return n;
}

