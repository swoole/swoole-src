#include "redis_client.h"
#include "test_core.h"

#include <memory>

using namespace std;

namespace swoole {
bool RedisClient::Connect(const string &host, int port, struct timeval timeout) {
    redisContext *c = redisConnectWithTimeout(host.c_str(), port, timeout);
    if (c == NULL) {
        printf("Connection error: can't allocate redis context\n");
        return false;
    }

    if (c->err) {
        printf("Connection error: %s\n", c->errstr);
        redisFree(c);
        return false;
    }

    ctx = c;
    return true;
}

string RedisClient::Get(const string &key) {
    const char *argv[] = {"GET", key.c_str()};
    size_t argvlen[] = {strlen(argv[0]), key.length()};

    auto reply = Request(SW_ARRAY_SIZE(argv), argv, argvlen);
    if (!reply.empty() && reply->str) {
        return string(reply->str, reply->len);
    } else {
        return "";
    }
}

bool RedisClient::Set(const string &key, const string &value) {
    const char *argv[] = {"SET", key.c_str(), value.c_str()};
    size_t argvlen[] = {strlen(argv[0]), key.length(), value.length()};

    auto reply = Request(SW_ARRAY_SIZE(argv), argv, argvlen);
    if (!reply.empty() && reply->type == REDIS_REPLY_STATUS && strncmp(reply->str, "OK", 2) == 0) {
        return true;
    } else {
        return false;
    }
}

RedisReply RedisClient::Request(int argc, const char **argv, const size_t *argvlen) {
    return redisCommandArgv(ctx, argc, argv, argvlen);
}

RedisReply RedisClient::Request(const vector<string> &args) {
    ctx->err = 0;

    size_t n = args.size();
    const char **argv = new const char *[n];
    size_t *argvlen = new size_t[n];

    for (size_t i = 0; i < args.size(); i++) {
        argv[i] = args[i].c_str();
        argvlen[i] = args[i].length();
    }

    auto reply = Request(args.size(), (const char **) argv, (const size_t *) argvlen);

    delete[] argv;
    delete[] argvlen;

    return std::move(reply);
}

}  // namespace swoole
