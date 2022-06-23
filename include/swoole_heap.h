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
 | Author: Tianfeng Han  <rango@swoole.com>                             |
 +----------------------------------------------------------------------+
 */

#pragma once

namespace swoole {

struct HeapNode {
    uint64_t priority;
    uint32_t position;
    void *data;
};

class Heap {
 public:
    enum Type {
        MIN_HEAP,
        MAX_HEAP,
    };

    Heap(size_t _n, Type _type);
    ~Heap();

    size_t count() {
        return num - 1;
    }

    HeapNode *push(uint64_t priority, void *data);
    void *pop();
    void change_priority(uint64_t new_priority, HeapNode *ptr);
    void remove(HeapNode *node);
    void *peek();
    void print();
    int compare(uint64_t a, uint64_t b);

    HeapNode *top() {
        if (num == 1) {
            return nullptr;
        }
        return nodes[1];
    }

 private:
    uint32_t num;
    uint32_t size;
    enum Type type;
    HeapNode **nodes;

    void bubble_up(uint32_t i);
    uint32_t maxchild(uint32_t i);
    void percolate_down(uint32_t i);
};
}

