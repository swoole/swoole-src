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

#pragma once

#include "swoole.h"

#include <vector>
#include <list>

namespace swoole {

struct WheelTimerNode;

using WheelTimerCallback = std::function<void(WheelTimerNode *)>;

struct WheelTimerNode {
    std::list<WheelTimerNode *>::iterator position_;
    uint16_t index_;
    WheelTimerCallback callback_;
};

class WheelTimer {
  private:
    uint64_t round_ = 0;
    uint16_t size_;
    std::vector<std::list<WheelTimerNode *>> buckets_;

    void push(WheelTimerNode *node) {
        node->index_ = (round_ + size_ - 1) % size_;
        buckets_[node->index_].push_front(node);
        node->position_ = buckets_[node->index_].begin();
    }

  public:
    WheelTimer(uint16_t size) {
        size_ = size;
        buckets_.resize(size);
    }

    uint64_t get_round() {
        return round_;
    }

    WheelTimerNode *add(const WheelTimerCallback &cb) {
        WheelTimerNode *node = new WheelTimerNode;
        push(node);
        node->callback_ = cb;
        return node;
    }

    void update(WheelTimerNode *node) {
        buckets_[node->index_].erase(node->position_);
        push(node);
    }

    void remove(WheelTimerNode *node) {
        buckets_[node->index_].erase(node->position_);
        delete node;
    }

    void next() {
        uint16_t current_index = round_ % size_;
        round_++;
        std::list<WheelTimerNode *> &_list = buckets_[current_index];
        for (auto node : _list) {
            node->callback_(node);
            delete node;
        }
        _list.clear();
    }
};
}  // namespace swoole
