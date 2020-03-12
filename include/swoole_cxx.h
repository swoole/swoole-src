#pragma once

#include "swoole.h"

#include <list>
#include <memory>
#include <string>
#include <cstdio>
#include <functional>
#include <vector>
#include <set>

namespace swoole {
//-------------------------------------------------------------------------------
namespace cpp_string
{
template<typename ...Args>
inline std::string format(const char *format, Args ...args)
{
    size_t size = snprintf(nullptr, 0, format, args...) + 1; // Extra space for '\0'
    std::unique_ptr<char[]> buf(new char[size]);
    snprintf(buf.get(), size, format, args...);
    return std::string(buf.get(), buf.get() + size - 1); // We don't want the '\0' inside
}

inline std::string vformat(const char *format, va_list args)
{
    va_list _args;
    va_copy(_args, args);
    size_t size = vsnprintf(nullptr, 0, format, _args) + 1; // Extra space for '\0'
    va_end(_args);
    std::unique_ptr<char[]> buf(new char[size]);
    vsnprintf(buf.get(), size, format, args);
    return std::string(buf.get(), buf.get() + size - 1); // We don't want the '\0' inside
}
}

struct Callback
{
    swCallback callback;
    void *private_data;

    Callback(swCallback cb, void *_private_data)
    {
        callback = cb;
        private_data = _private_data;
    }
};

class CallbackManager
{
public:
    inline void append(swCallback cb, void *private_data)
    {
        list_.push_back(new Callback(cb, private_data));
    }
    inline void prepend(swCallback cb, void *private_data)
    {
        list_.push_front(new Callback(cb, private_data));
    }
    inline void execute()
    {
        while (!list_.empty())
        {
            Callback *task = list_.front();
            list_.pop_front();
            task->callback(task->private_data);
            delete task;
        }
    }
protected:
    std::list<Callback *> list_;
};

static inline int hook_add(void **hooks, int type, swCallback func, int push_back)
{
    if (hooks[type] == NULL)
    {
        hooks[type] = new std::list<swCallback>;
    }

    std::list<swCallback> *l = static_cast<std::list<swCallback>*>(hooks[type]);
    if (push_back)
    {
        l->push_back(func);
    }
    else
    {
        l->push_front(func);
    }

    return SW_OK;
}

static inline void hook_call(void **hooks, int type, void *arg)
{
    std::list<swCallback> *l = static_cast<std::list<swCallback>*>(hooks[type]);
    for (auto i = l->begin(); i != l->end(); i++)
    {
        (*i)(arg);
    }
}

typedef std::function<bool (char *, size_t)> StringExplodeHandler;
size_t string_split(swString *str, const char *delimiter, size_t delimiter_length, const StringExplodeHandler &handler);
std::string intersection(std::vector<std::string> &vec1, std::set<std::string> &vec2);

//-------------------------------------------------------------------------------
}
