#pragma once

#include "swoole.h"

#include <string>
#include <vector>
#include <memory>

#include "hiredis.h"

namespace swoole {

class RedisReply {
  private:
    redisReply *ptr_;

  public:
    RedisReply(void *ptr) : ptr_(reinterpret_cast<redisReply *>(ptr)) {}
    RedisReply(RedisReply &&_o) {
        ptr_ = _o.ptr_;
        _o.ptr_ = nullptr;
    }
    ~RedisReply() {
        if (ptr_) {
            freeReplyObject(ptr_);
        }
    }
    redisReply *operator->() {
        return ptr_;
    }

    inline bool empty() {
        return ptr_ == nullptr;
    }
    inline const char *str() {
        return ptr_->str;
    }
    inline size_t len() {
        return ptr_->len;
    }
    inline size_t type() {
        return ptr_->type;
    }
};

class RedisClient {
  private:
    redisContext *ctx = nullptr;

  public:
    RedisClient() = default;

    ~RedisClient() {
        if (ctx) {
            redisFree(ctx);
        }
    }

    RedisReply Request(const std::vector<std::string> &args);
    RedisReply Request(int argc, const char **argv, const size_t *argvlen);

    bool Connect(const std::string &host = "127.0.0.1", int port = 6379, struct timeval timeout = {});
    std::string Get(const std::string &key);
    bool Set(const std::string &key, const std::string &value);
};

}  // namespace swoole
