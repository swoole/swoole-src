#include "test_core.h"
#include "swoole_server.h"
#include "swoole_util.h"

#include <memory>
#include <stdexcept>
#include <thread>

using namespace swoole;

namespace {
class ServerCommandTest : public testing::Test {
  protected:
    void SetUp() override {
        previous_worker = SwooleWG.worker;
        previous_shutdown = SwooleWG.shutdown;
        SwooleWG.shutdown = false;
        SwooleWG.worker = &worker;
        ASSERT_TRUE(server.add_command(
            "echo", Server::Command::ALL_PROCESS, [](Server *, const std::string &message) { return message; }));
        server.set_started(true);
    }
    void TearDown() override {
        server.set_started(false);
        SwooleWG.worker = previous_worker;
        SwooleWG.shutdown = previous_shutdown;
    }

    Server server{Server::MODE_BASE};
    Worker worker{};
    Worker *previous_worker = nullptr;
    bool previous_shutdown = false;
};

class ThreadCommandTest : public testing::Test {
  protected:
    void SetUp() override {
        previous_thread_type = swoole_get_thread_type();
        swoole_set_thread_type(Server::THREAD_MASTER);
        ASSERT_TRUE(server.add_command(
            "echo", Server::Command::ALL_PROCESS, [](Server *, const std::string &message) { return message; }));
        command_pipe.reset(server.pipe_command);
        server.set_started(true);
    }

    void TearDown() override {
        server.set_started(false);
        server.pipe_command = nullptr;
        swoole_set_thread_type(previous_thread_type);
    }

    Server server{Server::MODE_THREAD};
    std::unique_ptr<UnixSocket> command_pipe;
    uint8_t previous_thread_type = 0;
};
}  // namespace

TEST_F(ThreadCommandTest, master_command_executes_and_completes_on_its_owner) {
    const auto owner = std::this_thread::get_id();
    size_t calls = 0;
    server.command_handlers.at(server.commands.at("echo").id) = [owner](Server *, const std::string &message) {
        EXPECT_EQ(std::this_thread::get_id(), owner);
        return message;
    };
    EXPECT_TRUE(server.command(0, Server::Command::MASTER, "echo", "message", [&](Server *, const std::string &reply) {
        EXPECT_EQ(std::this_thread::get_id(), owner);
        EXPECT_EQ(reply, "message");
        calls++;
    }));
    EXPECT_EQ(calls, 1u);
    EXPECT_TRUE(server.command_callbacks.empty());
}

TEST_F(ThreadCommandTest, unsupported_targets_do_not_allocate_requests) {
    const auto initial_id = server.command_current_request_id;
    for (const auto target : {Server::Command::MANAGER,
                              Server::Command::EVENT_WORKER,
                              Server::Command::TASK_WORKER,
                              Server::Command::REACTOR_THREAD}) {
        EXPECT_FALSE(server.command(0, target, "echo", "message", [](Server *, const std::string &) {
            ADD_FAILURE() << "unexpected response";
        }));
        EXPECT_ERREQ(SW_ERROR_OPERATION_NOT_SUPPORT);
        EXPECT_EQ(server.command_current_request_id, initial_id);
        EXPECT_TRUE(server.command_callbacks.empty());
    }
}

TEST_F(ThreadCommandTest, other_threads_cannot_access_the_request_registry) {
    const auto initial_id = server.command_current_request_id;
    std::thread caller([this] {
        for (const auto role : {Server::THREAD_NORMAL, Server::THREAD_WORKER, Server::THREAD_REACTOR}) {
            swoole_set_thread_type(role);
            EXPECT_FALSE(
                server.command(0, Server::Command::MASTER, "echo", "message", [](Server *, const std::string &) {
                    ADD_FAILURE() << "unexpected response";
                }));
            EXPECT_ERREQ(SW_ERROR_SERVER_UNRELATED_THREAD);
        }
    });
    caller.join();
    EXPECT_EQ(server.command_current_request_id, initial_id);
    EXPECT_TRUE(server.command_callbacks.empty());
}

TEST(server_command, callback_is_consumed_before_invocation) {
    Server server(Server::MODE_BASE);
    int calls = 0;
    auto owner = std::make_shared<int>(42);
    std::weak_ptr<int> lifetime = owner;
    server.command_callbacks.emplace(7, [owner, &calls](Server *server, const std::string &result) {
        EXPECT_EQ(result, "first");
        EXPECT_EQ(server->command_callbacks.count(7), 0u);
        ++calls;
        server->command_callbacks.emplace(7, [&calls](Server *, const std::string &) { ++calls; });
    });
    owner.reset();
    server.call_command_callback(7, "first");
    EXPECT_EQ(calls, 1);
    EXPECT_TRUE(lifetime.expired());
    ASSERT_EQ(server.command_callbacks.count(7), 1u);
    server.call_command_callback(7, "second");
    EXPECT_EQ(calls, 2);
    EXPECT_TRUE(server.command_callbacks.empty());
}

TEST(server_command, throwing_callback_releases_captures) {
    Server server(Server::MODE_BASE);
    auto owner = std::make_shared<int>(42);
    std::weak_ptr<int> lifetime = owner;
    server.command_callbacks.emplace(7,
                                     [owner](Server *, const std::string &) { throw std::runtime_error("callback"); });
    owner.reset();
    EXPECT_THROW(server.call_command_callback(7, "result"), std::runtime_error);
    EXPECT_TRUE(server.command_callbacks.empty());
    EXPECT_TRUE(lifetime.expired());
}

TEST_F(ServerCommandTest, synchronous_commands_release_callbacks) {
    int calls = 0;
    for (int i = 0; i < 64; ++i) {
        auto owner = std::make_shared<int>(i);
        std::weak_ptr<int> lifetime = owner;
        Server::Command::Callback callback = [owner, &calls](Server *server, const std::string &result) {
            EXPECT_EQ(result, "message");
            EXPECT_TRUE(server->command_callbacks.empty());
            ++calls;
        };
        owner.reset();
        EXPECT_TRUE(server.command(0, Server::Command::MASTER, "echo", "message", callback));
        callback = nullptr;
        EXPECT_TRUE(lifetime.expired());
        EXPECT_TRUE(server.command_callbacks.empty());
    }
    EXPECT_TRUE(server.command(
        0, Server::Command::EVENT_WORKER, "echo", "message", [&](Server *, const std::string &) { ++calls; }));
    EXPECT_EQ(calls, 65);
}

TEST_F(ServerCommandTest, handler_and_callback_exceptions_do_not_leave_pending_requests) {
    EXPECT_THROW(server.command(0,
                                Server::Command::MASTER,
                                "echo",
                                "message",
                                [](Server *, const std::string &) { throw std::runtime_error("callback"); }),
                 std::runtime_error);
    EXPECT_TRUE(server.command_callbacks.empty());
    server.command_handlers.at(server.commands.at("echo").id) = [](Server *, const std::string &) -> std::string {
        throw std::runtime_error("handler");
    };
    EXPECT_THROW(server.command(0,
                                Server::Command::MASTER,
                                "echo",
                                "message",
                                [](Server *, const std::string &) { ADD_FAILURE() << "unexpected response"; }),
                 std::runtime_error);
    EXPECT_TRUE(server.command_callbacks.empty());
}

TEST_F(ServerCommandTest, invalid_dispatch_does_not_retain_callback) {
    const std::pair<Server::Command::ProcessType, WorkerId> targets[] = {
        {Server::Command::EVENT_WORKER, server.worker_num},
        {Server::Command::TASK_WORKER, server.task_worker_num},
        {Server::Command::REACTOR_THREAD, 0},
        {static_cast<Server::Command::ProcessType>(0), 0},
    };
    for (const auto &target : targets) {
        EXPECT_FALSE(server.command(target.second, target.first, "echo", "message", [](Server *, const std::string &) {
            ADD_FAILURE() << "unexpected response";
        }));
        EXPECT_TRUE(server.command_callbacks.empty());
    }
    EventData packet{};
    EXPECT_FALSE(server.command(
        0, Server::Command::MANAGER, "echo", std::string(sizeof(packet.data), 'x'), [](Server *, const std::string &) {
            ADD_FAILURE() << "unexpected response";
        }));
    EXPECT_TRUE(server.command_callbacks.empty());
}

TEST_F(ServerCommandTest, callback_copy_failure_does_not_publish_empty_request) {
    struct Callback {
        bool &fail;
        explicit Callback(bool &fail) : fail(fail) {}
        Callback(const Callback &other) : fail(other.fail) {
            if (fail) {
                throw std::runtime_error("copy");
            }
        }
        void operator()(Server *, const std::string &) const {}
    };
    bool fail = false;
    Server::Command::Callback callback = Callback(fail);
    fail = true;
    EXPECT_THROW(server.command(0, Server::Command::MASTER, "echo", "message", callback), std::runtime_error);
    EXPECT_TRUE(server.command_callbacks.empty());
}

TEST(server_command, handler_copy_failure_rolls_back_registration) {
    struct Handler {
        bool &fail;
        explicit Handler(bool &fail) : fail(fail) {}
        Handler(const Handler &other) : fail(other.fail) {
            if (fail) {
                throw std::runtime_error("copy");
            }
        }
        std::string operator()(Server *, const std::string &message) const {
            return message;
        }
    };
    Server server(Server::MODE_BASE);
    bool fail = false;
    Server::Command::Handler handler = Handler(fail);
    fail = true;
    EXPECT_THROW(server.add_command("echo", Server::Command::MASTER, handler), std::runtime_error);
    EXPECT_TRUE(server.commands.empty());
    EXPECT_TRUE(server.command_handlers.empty());
    fail = false;
    EXPECT_TRUE(server.add_command("echo", Server::Command::MASTER, handler));
}

TEST(server_command, cancel_retires_reply_and_releases_its_resources_once) {
    Server server(Server::MODE_BASE);
    auto owner = std::make_shared<int>(42);
    std::weak_ptr<int> lifetime = owner;
    server.command_callbacks.emplace(7, [owner](Server *, const std::string &) { ADD_FAILURE(); });
    owner.reset();
    EXPECT_TRUE(server.cancel_command(7));
    EXPECT_TRUE(lifetime.expired());
    EXPECT_FALSE(server.cancel_command(7));
    server.call_command_callback(7, "late reply");
    EXPECT_TRUE(server.command_callbacks.empty());
}

TEST(server_command, shutdown_detaches_requests_before_failure_callbacks) {
    Server server(Server::MODE_BASE);
    int failed = 0;
    for (int64_t id : {7, 8}) {
        server.command_callbacks.emplace(id,
                                         Server::Command::Request([](Server *, const std::string &) { ADD_FAILURE(); },
                                                                  [&](Server *server) {
                                                                      EXPECT_TRUE(server->command_callbacks.empty());
                                                                      EXPECT_FALSE(server->cancel_command(7));
                                                                      server->call_command_callback(8, "late reply");
                                                                      server->cancel_all_commands();
                                                                      ++failed;
                                                                  }));
    }
    server.cancel_all_commands();
    EXPECT_EQ(failed, 2);
    server.cancel_all_commands();
    EXPECT_EQ(failed, 2);
}

TEST_F(ServerCommandTest, reports_the_registered_request_id) {
    int64_t request_id = -1;
    bool completed = false;
    EXPECT_TRUE(server.command(
        0,
        Server::Command::MASTER,
        "echo",
        "message",
        [&](Server *, const std::string &) {
            EXPECT_GE(request_id, 0);
            EXPECT_EQ(server.command_callbacks.count(request_id), 0u);
            completed = true;
        },
        &request_id,
        [](Server *) { ADD_FAILURE(); }));
    EXPECT_TRUE(completed);
}

TEST_F(ServerCommandTest, stopped_owner_cannot_register_more_commands) {
    server.running = false;
    EXPECT_FALSE(server.command(
        0, Server::Command::MASTER, "echo", "message", [](Server *, const std::string &) { ADD_FAILURE(); }));
    EXPECT_ERREQ(SW_ERROR_WRONG_OPERATION);
    EXPECT_TRUE(server.command_callbacks.empty());
    server.running = true;
    SwooleWG.shutdown = true;
    EXPECT_FALSE(server.command(
        0, Server::Command::MASTER, "echo", "message", [](Server *, const std::string &) { ADD_FAILURE(); }));
    EXPECT_TRUE(server.command_callbacks.empty());
}
