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
  | @link     https://www.swoole.com/                                    |
  | @contact  team@swoole.com                                            |
  | @license  https://github.com/swoole/swoole-src/blob/master/LICENSE   |
  | @author   Tianfeng Han  <mikan.tenny@gmail.com>                      |
  +----------------------------------------------------------------------+
*/

#include "swoole.h"
#include "swoole_memory.h"
#include "swoole_channel.h"
#include "swoole_lock.h"
#include "swoole_pipe.h"

namespace swoole {

#define SW_CHANNEL_MIN_MEM (1024 * 64)

struct ChannelSlice {
    int length;
    char data[0];
};

Channel *Channel::make(size_t size, size_t maxlen, int flags) {
    assert(size >= maxlen);
    void *mem;

    // use shared memory
    if (flags & SW_CHAN_SHM) {
        /**
         * overflow space
         */
        mem = sw_shm_malloc(size + sizeof(Channel) + maxlen + sizeof(ChannelSlice));
    } else {
        mem = sw_malloc(size + sizeof(Channel) + maxlen + sizeof(ChannelSlice));
    }

    if (mem == nullptr) {
        swoole_warning("alloc(%ld) failed", size);
        return nullptr;
    }

    Channel *object = (Channel *) mem;
    mem = (char *) mem + sizeof(Channel);

    *object = {};

    // overflow space
    object->size = size;
    object->mem = mem;
    object->maxlen = maxlen;
    object->flags = flags;

    // use lock
    if (flags & SW_CHAN_LOCK) {
        // init lock
        object->lock = new Mutex(Mutex::PROCESS_SHARED);
    }
    // use notify
    if (flags & SW_CHAN_NOTIFY) {
        object->notify_pipe = new Pipe(true);
        if (!object->notify_pipe->ready()) {
            swoole_warning("notify_fd init failed");
            delete object->notify_pipe;
            return nullptr;
        }
    }

    return object;
}

/**
 * push data(no lock)
 */
int Channel::in(const void *in_data, int data_length) {
    assert(data_length <= maxlen);
    if (full()) {
        return SW_ERR;
    }
    ChannelSlice *item;
    int msize = sizeof(item->length) + data_length;

    if (tail < head) {
        // no enough memory space
        if ((head - tail) < msize) {
            return SW_ERR;
        }
        item = (ChannelSlice *) ((char *) mem + tail);
        tail += msize;
    } else {
        item = (ChannelSlice *) ((char *) mem + tail);
        tail += msize;
        if (tail >= (off_t) size) {
            tail = 0;
            tail_tag = 1 - tail_tag;
        }
    }
    num++;
    bytes += data_length;
    item->length = data_length;
    memcpy(item->data, in_data, data_length);
    return SW_OK;
}

/**
 * pop data(no lock)
 */
int Channel::out(void *out_buf, int buffer_length) {
    if (empty()) {
        return SW_ERR;
    }

    ChannelSlice *item = (ChannelSlice *) ((char *) mem + head);
    assert(buffer_length >= item->length);
    memcpy(out_buf, item->data, item->length);
    head += (item->length + sizeof(item->length));
    if (head >= (off_t) size) {
        head = 0;
        head_tag = 1 - head_tag;
    }
    num--;
    bytes -= item->length;
    return item->length;
}

/**
 * peek data
 */
int Channel::peek(void *out, int buffer_length) {
    if (empty()) {
        return SW_ERR;
    }

    int length;
    lock->lock();
    ChannelSlice *item = (ChannelSlice *) ((char *) mem + head);
    assert(buffer_length >= item->length);
    memcpy(out, item->data, item->length);
    length = item->length;
    lock->unlock();

    return length;
}

/**
 * wait notify
 */
int Channel::wait() {
    assert(flags & SW_CHAN_NOTIFY);
    uint64_t value;
    return notify_pipe->read(&value, sizeof(value));
}

/**
 * new data coming, notify to customer
 */
int Channel::notify() {
    assert(flags & SW_CHAN_NOTIFY);
    uint64_t value = 1;
    return notify_pipe->write(&value, sizeof(value));
}

/**
 * push data (lock)
 */
int Channel::push(const void *in_data, int data_length) {
    assert(flags & SW_CHAN_LOCK);
    lock->lock();
    int ret = in(in_data, data_length);
    lock->unlock();
    return ret;
}

/**
 * free channel
 */
void Channel::destroy() {
    if (flags & SW_CHAN_LOCK) {
        delete lock;
    }
    if (flags & SW_CHAN_NOTIFY) {
        notify_pipe->close();
        delete notify_pipe;
    }
    if (flags & SW_CHAN_SHM) {
        sw_shm_free(this);
    } else {
        sw_free(this);
    }
}

/**
 * pop data (lock)
 */
int Channel::pop(void *out_buf, int buffer_length) {
    assert(flags & SW_CHAN_LOCK);
    lock->lock();
    int n = out(out_buf, buffer_length);
    lock->unlock();
    return n;
}

void Channel::print() {
    printf("Channel\n{\n"
           "    off_t head = %ld;\n"
           "    off_t tail = %ld;\n"
           "    size_t size = %ld;\n"
           "    char head_tag = %d;\n"
           "    char tail_tag = %d;\n"
           "    int num = %d;\n"
           "    size_t bytes = %ld;\n"
           "    int flag = %d;\n"
           "    int maxlen = %d;\n"
           "\n}\n",
           (long) head,
           (long) tail,
           size,
           tail_tag,
           head_tag,
           num,
           bytes,
           flags,
           maxlen);
}

}  // namespace swoole
