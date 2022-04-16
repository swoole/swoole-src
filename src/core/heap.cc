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
 | Author: Tianfeng Han  <rango@swoole.com>                             |
 +----------------------------------------------------------------------+
 */

#include "swoole.h"
#include "swoole_heap.h"

#define left(i) ((i) << 1)
#define right(i) (((i) << 1) + 1)
#define parent(i) ((i) >> 1)

namespace swoole {

Heap::Heap(size_t _n, Heap::Type _type) {
    if (!(nodes = (HeapNode **) sw_malloc((_n + 1) * sizeof(void *)))) {
        throw std::bad_alloc();
    }
    num = 1;
    size = (_n + 1);
    type = _type;
}

Heap::~Heap() {
    sw_free(nodes);
}

int Heap::compare(uint64_t a, uint64_t b) {
    if (type == Heap::MIN_HEAP) {
        return a > b;
    } else {
        return a < b;
    }
}

uint32_t Heap::maxchild(uint32_t i) {
    uint32_t child_i = left(i);
    if (child_i >= num) {
        return 0;
    }
    HeapNode *child_node = nodes[child_i];
    if ((child_i + 1) < num && compare(child_node->priority, nodes[child_i + 1]->priority)) {
        child_i++;
    }
    return child_i;
}

void Heap::bubble_up(uint32_t i) {
    HeapNode *moving_node = nodes[i];
    uint32_t parent_i;

    for (parent_i = parent(i); (i > 1) && compare(nodes[parent_i]->priority, moving_node->priority);
         i = parent_i, parent_i = parent(i)) {
        nodes[i] = nodes[parent_i];
        nodes[i]->position = i;
    }

    nodes[i] = moving_node;
    moving_node->position = i;
}

void Heap::percolate_down(uint32_t i) {
    uint32_t child_i;
    HeapNode *moving_node = nodes[i];

    while ((child_i = maxchild(i)) && compare(moving_node->priority, nodes[child_i]->priority)) {
        nodes[i] = nodes[child_i];
        nodes[i]->position = i;
        i = child_i;
    }

    nodes[i] = moving_node;
    moving_node->position = i;
}

HeapNode *Heap::push(uint64_t priority, void *data) {
    HeapNode **tmp;
    uint32_t i;
    uint32_t newsize;

    if (num >= size) {
        newsize = size * 2;
        if (!(tmp = (HeapNode **) sw_realloc(nodes, sizeof(HeapNode *) * newsize))) {
            return nullptr;
        }
        nodes = tmp;
        size = newsize;
    }

    HeapNode *node = new HeapNode;
    node->priority = priority;
    node->data = data;
    i = num++;
    nodes[i] = node;
    bubble_up(i);
    return node;
}

void Heap::change_priority(uint64_t new_priority, HeapNode *node) {
    uint32_t pos = node->position;
    uint64_t old_pri = node->priority;

    node->priority = new_priority;
    if (compare(old_pri, new_priority)) {
        bubble_up(pos);
    } else {
        percolate_down(pos);
    }
}

void Heap::remove(HeapNode *node) {
    uint32_t pos = node->position;
    nodes[pos] = nodes[--num];

    if (compare(node->priority, nodes[pos]->priority)) {
        bubble_up(pos);
    } else {
        percolate_down(pos);
    }
    delete node;
}

void *Heap::pop() {
    HeapNode *head;
    if (count() == 0) {
        return nullptr;
    }

    head = nodes[1];
    nodes[1] = nodes[--num];
    percolate_down(1);

    void *data = head->data;
    delete head;
    return data;
}

void *Heap::peek() {
    if (num == 1) {
        return nullptr;
    }
    HeapNode *node = nodes[1];
    if (!node) {
        return nullptr;
    }
    return node->data;
}

void Heap::print() {
    for (uint32_t i = 1; i < num; i++) {
        printf("#%u\tpriority=%ld, data=%p\n", i, (long) nodes[i]->priority, nodes[i]->data);
    }
}
}  // namespace swoole
