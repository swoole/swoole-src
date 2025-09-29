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

#include <unordered_map>
#include <list>
#include <utility>
#include <memory>
#include <ctime>

namespace swoole {
/**
 * This cache isn't thread safe
 */
template <typename T>
class LRUCache {
    typedef std::pair<time_t, std::shared_ptr<T>> cache_node_t;
    typedef std::list<std::pair<std::string, cache_node_t>> cache_list_t;

    std::unordered_map<std::string, typename cache_list_t::iterator> cache_map;
    cache_list_t cache_list;
    size_t cache_capacity;

  public:
    explicit LRUCache(size_t capacity) {
        cache_capacity = capacity;
    }

    std::shared_ptr<T> get(const std::string &key) {
        auto iter = cache_map.find(key);
        if (iter == cache_map.end()) {
            return nullptr;
        }

        if (iter->second->second.first < ::time(nullptr) && iter->second->second.first > 0) {
            return nullptr;
        }

        cache_list.splice(cache_list.begin(), cache_list, iter->second);
        return iter->second->second.second;  // iter -> list::iter -> cache_node_t -> value
    }

    void set(const std::string &key, const std::shared_ptr<T> &val, time_t expire = 0) {
        time_t expire_time;

        if (expire <= 0) {
            expire_time = 0;
        } else {
            expire_time = ::time(nullptr) + expire;
        }

        auto iter = cache_map.find(key);
        if (iter != cache_map.end()) {
            iter->second->second.first = expire_time;
            iter->second->second.second = val;
            cache_list.splice(cache_list.begin(), cache_list, iter->second);
            return;
        }

        size_t size = cache_list.size();
        if (size == cache_capacity && size > 0) {
            auto del = cache_list.back();
            cache_map.erase(del.first);
            cache_list.pop_back();
        }

        cache_list.emplace_front(key, cache_node_t{expire_time, val});
        cache_map[key] = cache_list.begin();
    }

    void del(const std::string &key) {
        auto iter = cache_map.find(key);
        if (iter == cache_map.end()) {
            return;
        }

        cache_list.erase(iter->second);
        cache_map.erase(iter);
    }

    void clear() {
        cache_list.clear();
        cache_map.clear();
    }
};
}  // namespace swoole
