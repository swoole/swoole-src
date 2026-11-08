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

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace swoole {

static constexpr uint32_t max_heap_size = static_cast<uint32_t>(
    std::min<size_t>(std::numeric_limits<uint32_t>::max(), std::numeric_limits<size_t>::max() / sizeof(HeapNode *)));

void Heap::NodeArrayDeleter::operator()(HeapNode **ptr) const {
    sw_free(ptr);
}

Heap::Heap(size_t _n, Type _type) : num(1), size(0), type(_type) {
    // Slot zero is unused. Both the slot count and its allocation must fit before adding it.
    if (sw_unlikely(_n >= max_heap_size)) {
        throw std::length_error("heap capacity is too large");
    }
    size = static_cast<uint32_t>(_n + 1);
    nodes.reset(static_cast<HeapNode **>(sw_malloc(size * sizeof(HeapNode *))));
    if (sw_unlikely(!nodes)) {
        throw std::bad_alloc();
    }
}

Heap::~Heap() {
    for (uint32_t i = 1; i < num; i++) {
        delete nodes[i];
    }
}

int Heap::compare(uint64_t a, uint64_t b) const {
    if (type == MIN_HEAP) {
        return a > b;
    } else {
        return a < b;
    }
}

uint32_t Heap::maxchild(uint32_t i) const {
    // Check for a leaf before doubling, so large leaf positions cannot wrap to a live slot.
    if (i > (num - 1) / 2) {
        return 0;
    }
    uint32_t child_i = i * 2;
    HeapNode *child_node = nodes[child_i];
    if ((child_i + 1) < num && compare(child_node->priority, nodes[child_i + 1]->priority)) {
        child_i++;
    }
    return child_i;
}

void Heap::bubble_up(uint32_t i) const {
    HeapNode *moving_node = nodes[i];
    for (uint32_t parent_i = i / 2; i > 1 && compare(nodes[parent_i]->priority, moving_node->priority);
         i = parent_i, parent_i = i / 2) {
        nodes[i] = nodes[parent_i];
        nodes[i]->position = i;
    }

    nodes[i] = moving_node;
    moving_node->position = i;
}

void Heap::percolate_down(uint32_t i) const {
    uint32_t child_i;
    HeapNode *moving_node = nodes[i];

    while ((child_i = maxchild(i)) != 0 && compare(moving_node->priority, nodes[child_i]->priority)) {
        nodes[i] = nodes[child_i];
        nodes[i]->position = i;
        i = child_i;
    }

    nodes[i] = moving_node;
    moving_node->position = i;
}

bool Heap::grow() {
    if (sw_unlikely(size >= max_heap_size)) {
        errno = EOVERFLOW;
        return false;
    }
    const uint32_t new_size = size > max_heap_size / 2 ? max_heap_size : size * 2;
    auto *resized = static_cast<HeapNode **>(sw_realloc(nodes.get(), sizeof(HeapNode *) * new_size));
    if (sw_unlikely(!resized)) {
        return false;
    }
    // realloc has already released or reused the old allocation; only publish the new owner on success.
    (void) nodes.release();
    nodes.reset(resized);
    size = new_size;
    return true;
}

HeapNode *Heap::push(uint64_t priority, void *data) {
    if (sw_unlikely(num >= size) && !grow()) {
        return nullptr;
    }

    auto *node = new HeapNode{priority, num, data};
    nodes[num++] = node;
    bubble_up(node->position);
    return node;
}

void Heap::change_priority(uint64_t new_priority, HeapNode *node) const {
    if (new_priority == node->priority) {
        return;
    }
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
    uint32_t last = --num;
    auto *replacement = nodes[last];
    nodes[last] = nullptr;
    if (pos != last) {
        nodes[pos] = replacement;
        if (compare(node->priority, replacement->priority)) {
            bubble_up(pos);
        } else {
            percolate_down(pos);
        }
    }
    delete node;
}

void *Heap::pop() {
    auto *head = top();
    if (!head) {
        return nullptr;
    }

    void *data = head->data;
    remove(head);
    return data;
}

void *Heap::peek() const {
    const auto *node = top();
    return node ? node->data : nullptr;
}

void Heap::print() const {
    for (uint32_t i = 1; i < num; i++) {
        printf("#%u\tpriority=%" PRIu64 ", data=%p\n", i, nodes[i]->priority, nodes[i]->data);
    }
}
}  // namespace swoole
