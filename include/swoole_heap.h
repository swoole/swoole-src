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

#include <cstddef>
#include <cstdint>
#include <memory>

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

    // _n excludes the unused slot zero; an unrepresentable capacity throws std::length_error.
    Heap(size_t _n, Type _type);
    ~Heap();

    Heap(const Heap &) = delete;
    Heap &operator=(const Heap &) = delete;

    size_t count() const {
        return num - 1;
    }

    // Returns nullptr if the index array cannot grow; allocating a node can throw std::bad_alloc.
    HeapNode *push(uint64_t priority, void *data);
    void *pop();
    void change_priority(uint64_t new_priority, HeapNode *ptr) const;
    void remove(HeapNode *node);
    void *peek() const;
    void print() const;
    int compare(uint64_t a, uint64_t b) const;

    HeapNode *top() const {
        if (num == 1) {
            return nullptr;
        }
        return nodes[1];
    }

  private:
    struct NodeArrayDeleter {
        void operator()(HeapNode **ptr) const;
    };

    uint32_t num;
    uint32_t size;
    enum Type type;
    // Own the nodes and their index array; HeapNode::data remains caller-owned.
    std::unique_ptr<HeapNode *[], NodeArrayDeleter> nodes;

    bool grow();
    void bubble_up(uint32_t i) const;
    uint32_t maxchild(uint32_t i) const;
    void percolate_down(uint32_t i) const;
};
}  // namespace swoole
