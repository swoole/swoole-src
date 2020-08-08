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

#pragma once

#include <stdio.h>

#include "swoole.h"
#include "swoole_log.h"

#define swRingQueue_empty() ((head == tail) && (tag == 0))
#define swRingQueue_full() ((head == tail) && (tag == 1))

namespace swoole {

template <typename T>
class RingQueue {
  private:
    int head;
    int tail;
    /**
     * empty or full
     */
    int tag;
    int size;
    T* data;
    /* data */
  public:
    RingQueue(int buffer_size);
    ~RingQueue();
    bool push(T push_data);
    T pop();
    int count();
    bool empty();
};

template <typename T>
RingQueue<T>::RingQueue(int buffer_size) {
    data = reinterpret_cast<T*>(sw_calloc(buffer_size, sizeof(T)));
    if (data == nullptr) {
        throw std::bad_alloc();
    }
    size = buffer_size;
    head = 0;
    tail = 0;
    tag = 0;
}

template <typename T>
RingQueue<T>::~RingQueue() {
    sw_free(data);
}

template <typename T>
bool RingQueue<T>::push(T push_data) {
    if (swRingQueue_full()) {
        return false;
    }

    data[tail] = push_data;
    tail = (tail + 1) % size;

    if (tail == head) {
        tag = 1;
    }
    return true;
}

template <typename T>
T RingQueue<T>::pop() {
    T pop_data = data[head];
    head = (head + 1) % size;

    if (tail == head) {
        tag = 0;
    }
    return pop_data;
}

template <typename T>
int RingQueue<T>::count() {
    if (tail > head) {
        return tail - head;
    } else if (head == tail) {
        return tag == 1 ? size : 0;
    } else {
        return tail + size - head;
    }
}

template <typename T>
bool RingQueue<T>::empty() {
    return swRingQueue_empty();
}

}  // namespace swoole
