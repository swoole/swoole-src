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

#define SW_CHANNEL_MIN_MEM (1024*64)

typedef struct _swChannel_item
{
    int length;
    char data[0];
} swChannel_item;

swChannel* swChannel_new(size_t size, int maxlen, int flags)
{
    assert(size >= maxlen);
    int ret;
    void *mem;

    //use shared memory
    if (flags & SW_CHAN_SHM)
    {
        /**
         * overflow space
         */
        mem = sw_shm_malloc(size + sizeof(swChannel) + maxlen + sizeof(swChannel_item));
    }
    else
    {
        mem = sw_malloc(size + sizeof(swChannel) + maxlen + sizeof(swChannel_item));
    }

    if (mem == NULL)
    {
        swWarn("swChannel_create: malloc(%ld) failed", size);
        return NULL;
    }
    swChannel *object = mem;
    mem = (char*) mem + sizeof(swChannel);

    bzero(object, sizeof(swChannel));

    //overflow space
    object->size = size;
    object->mem = mem;
    object->maxlen = maxlen;
    object->flag = flags;

    //use lock
    if (flags & SW_CHAN_LOCK)
    {
        //init lock
        if (swMutex_create(&object->lock, 1) < 0)
        {
            swWarn("mutex init failed");
            return NULL;
        }
    }
    //use notify
    if (flags & SW_CHAN_NOTIFY)
    {
        ret = swPipeNotify_auto(&object->notify_fd, 1, 1);
        if (ret < 0)
        {
            swWarn("notify_fd init failed");
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
    assert(data_length <= object->maxlen);
    if (swChannel_full(object))
    {
        return SW_ERR;
    }
    swChannel_item *item;
    int msize = sizeof(item->length) + data_length;

    if (object->tail < object->head)
    {
        //no enough memory space
        if ((object->head - object->tail) < msize)
        {
            return SW_ERR;
        }
        item = (swChannel_item *) ((char*) object->mem + object->tail);
        object->tail += msize;
    }
    else
    {
        item = (swChannel_item *) ((char*) object->mem + object->tail);
        object->tail += msize;
        if (object->tail >= object->size)
        {
            object->tail = 0;
            object->tail_tag = 1 - object->tail_tag;
        }
    }
    object->num++;
    object->bytes += data_length;
    item->length = data_length;
    memcpy(item->data, in, data_length);
    return SW_OK;
}

/**
 * pop data(no lock)
 */
int swChannel_out(swChannel *object, void *out, int buffer_length)
{
    if (swChannel_empty(object))
    {
        return SW_ERR;
    }

    swChannel_item *item = (swChannel_item *) ((char*) object->mem + object->head);
    assert(buffer_length >= item->length);
    memcpy(out, item->data, item->length);
    object->head += (item->length + sizeof(item->length));
    if (object->head >= object->size)
    {
        object->head = 0;
        object->head_tag = 1 - object->head_tag;
    }
    object->num--;
    object->bytes -= item->length;
    return item->length;
}

/**
 * peek data
 */
int swChannel_peek(swChannel *object, void *out, int buffer_length)
{
    if (swChannel_empty(object))
    {
        return SW_ERR;
    }

    int length;
    object->lock.lock(&object->lock);
    swChannel_item *item = (swChannel_item *) ((char*) object->mem + object->head);
    assert(buffer_length >= item->length);
    memcpy(out, item->data, item->length);
    length = item->length;
    object->lock.unlock(&object->lock);

    return length;
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

void swChannel_print(swChannel *chan)
{
    printf("swChannel\n{\n"
            "    off_t head = %ld;\n"
            "    off_t tail = %ld;\n"
            "    size_t size = %ld;\n"
            "    char head_tag = %d;\n"
            "    char tail_tag = %d;\n"
            "    int num = %d;\n"
            "    size_t bytes = %ld;\n"
            "    int flag = %d;\n"
            "    int maxlen = %d;\n"
            "\n}\n", (long)chan->head, (long)chan->tail, chan->size, chan->tail_tag, chan->head_tag, chan->num, chan->bytes,
            chan->flag, chan->maxlen);
}
