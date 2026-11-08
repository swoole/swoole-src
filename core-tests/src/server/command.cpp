#include "test_core.h"
#include "swoole_server.h"
#include "swoole_util.h"

#include <memory>
#include <stdexcept>

using namespace swoole;

namespace {
class ServerCommandTest : public testing::Test {
  protected:
    void SetUp() override {
        previous_worker = SwooleWG.worker;
        SwooleWG.worker = &worker;
        ASSERT_TRUE(server.add_command(
            "echo", Server::Command::ALL_PROCESS, [](Server *, const std::string &message) { return message; }));
        server.gs->start = 1;
    }
    void TearDown() override {
        server.gs->start = 0;
        SwooleWG.worker = previous_worker;
    }

    Server server{Server::MODE_BASE};
    Worker worker{};
    Worker *previous_worker = nullptr;
};
}  // namespace

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
