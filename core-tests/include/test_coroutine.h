#pragma once

#include "test_core.h"

#include "swoole_coroutine.h"
#include "swoole_coroutine_channel.h"
#include "swoole_coroutine_system.h"
#include "swoole_coroutine_socket.h"
#include "swoole_coroutine_api.h"

namespace swoole {
namespace test {

class coroutine {
  public:
    coroutine(const CoroutineFunc &_fn, void *_arg, int *_complete_num)
        : fn(_fn), arg(_arg), complete_num(_complete_num) {}

    void start() {
        fn(arg);
        (*complete_num)++;
    }

    inline static void create(const CoroutineFunc &fn, void *arg, int *complete_num) {
        auto test = new coroutine(fn, arg, complete_num);

        long cid = swoole::Coroutine::create(
            [](void *arg) {
                ((coroutine *) arg)->start();
                delete (coroutine *) arg;
            },
            test);
        ASSERT_GT(cid, 0);
    }

    inline static void run(std::initializer_list<std::pair<CoroutineFunc, void *>> args) {
        int complete_num = 0;
        swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);
        Coroutine::activate();
        for (const auto &arg : args) {
            create(arg.first, arg.second, &complete_num);
        }
        swoole_event_wait();
        Coroutine::deactivate();
    }

    inline static void run(std::initializer_list<CoroutineFunc> fns) {
        int complete_num = 0;
        swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);
        Coroutine::activate();
        for (const auto &fn : fns) {
            create(fn, nullptr, &complete_num);
        }
        swoole_event_wait();
        Coroutine::deactivate();
    }

    inline static void run(const CoroutineFunc &fn, void *arg = nullptr) {
        int complete_num = 0;
        swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);
        Coroutine::activate();
        create(fn, arg, &complete_num);
        swoole_event_wait();
        Coroutine::deactivate();
    }

  private:
    CoroutineFunc fn;
    void *arg;
    int *complete_num;
};
}  // namespace test
}  // namespace swoole
