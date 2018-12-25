#pragma once

#include <unordered_map>
#include <list>

typedef void (*lru_cache_free_t)(void*);

namespace swoole
{
class LRUCache
{
private:
    std::unordered_map<std::string, std::list<std::pair<std::string, void*>>::iterator> cache_map;
    std::list<std::pair<std::string, void*>> cache_list;
    size_t cache_capacity;
    lru_cache_free_t cache_free;
public:
    LRUCache(size_t capacity, lru_cache_free_t free_callback)
    {
        cache_capacity = capacity;
        cache_free = free_callback;
    }

    inline void *get(const std::string &key)
    {
        auto iter = cache_map.find(key);
        if (iter == cache_map.end())
        {
            return nullptr;
        }

        cache_list.splice(cache_list.begin(), cache_list, iter->second);
        return iter->second->second;
    }

    inline void set(const std::string &key, void *val)
    {
        if (cache_capacity == 0)
        {
            return;
        }

        auto iter = cache_map.find(key);
        if (iter != cache_map.end())
        {
            cache_free(iter->second->second);
            iter->second->second = val;
            cache_list.splice(cache_list.begin(), cache_list, iter->second);
            return;
        }

        if (cache_list.size() == cache_capacity)
        {
            auto del = cache_list.back();
            cache_map.erase(del.first);
            cache_free(del.second);
            cache_list.pop_back();
        }

        cache_list.emplace_front(key, val);
        cache_map[key] = cache_list.begin();
    }

    inline void del(const std::string &key)
    {
        auto iter = cache_map.find(key);
        if (iter == cache_map.end())
        {
            return;
        }

        cache_free(iter->second->second);
        cache_list.erase(iter->second);
        cache_map.erase(iter->first);
    }

    inline void clear()
    {
        for (auto iter = cache_map.begin(); iter != cache_map.end(); ++iter)
        {
            cache_free(iter->second->second);
            cache_list.erase(iter->second);
            cache_map.erase(iter->first);
        }
    }
};
}