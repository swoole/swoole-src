#include "test_core.h"
#include "swoole_api.h"
#include "swoole_channel.h"
#include "swoole_message_bus.h"
#include "swoole_pipe.h"
#include "swoole_process_pool.h"
#include "swoole_protocol.h"
#include "swoole_signal.h"
#include "swoole_timer.h"
#include "swoole_websocket.h"

#include <condition_variable>
#include <queue>
#include <unordered_set>

#define private public
#include "swoole_server.h"
#undef private

using namespace swoole;

namespace {
class TaskResult : public testing::Test {
  protected:
    std::unique_ptr<Server> server;
    std::unique_ptr<Reactor> reactor;
    Reactor *saved_reactor = nullptr;
    Timer *saved_timer = nullptr;
    WorkerGlobal saved_worker{};
    Server *saved_server = nullptr;
    std::vector<network::Socket *> peers;
    std::vector<std::string> files;
    std::vector<EventData> received;
    uint32_t saved_buffer_size = 0;
    // The endpoint lives in this test's private directory; no real process is signalled.
    const pid_t owner = 1;

    void SetUp() override {
        saved_reactor = SwooleTG.reactor;
        saved_timer = SwooleTG.timer;
        saved_worker = SwooleWG;
        saved_server = SwooleG.server;
        saved_buffer_size = network::Socket::default_buffer_size;
        SwooleTG.timer = nullptr;
        SwooleWG = {};
        SwooleWG.type = SW_EVENT_WORKER;
        SwooleWG.pid = getpid();
        server.reset(new Server(Server::MODE_PROCESS));
        server->task_worker_num = 1;
        server->max_wait_time = 10;
        ASSERT_TRUE(server->create_task_result_directory(geteuid(), getegid()));
        reactor.reset(new Reactor());
        ASSERT_TRUE(reactor->ready());
        reactor->ptr = server.get();
        SwooleTG.reactor = reactor.get();
        server->onFinish = [this](Server *, EventData *result) {
            received.push_back(*result);
            return SW_OK;
        };
    }

    void TearDown() override {
        if (server) {
            server->cleanup_task_result_socket(getpid());
            server->task_result_channel_.reset();
        }
        for (auto *peer : peers) {
            peer->free();
        }
        if (reactor) {
            reactor->execute_end_callbacks();
        }
        if (server) {
            server->destroy();
            server->destroy_task_result_directory();
            server.reset();
        }
        reactor.reset();
        // A channel may have used a manually triggered timer without reactor ownership.
        if (swoole_timer_is_available()) {
            swoole_timer_free();
        }
        for (const auto &path : files) {
            unlink(path.c_str());
        }
        network::Socket::default_buffer_size = saved_buffer_size;
        SwooleTG.reactor = saved_reactor;
        SwooleTG.timer = saved_timer;
        SwooleWG = saved_worker;
        SwooleG.server = saved_server;
    }

    EventData result(TaskId id, uint16_t flags = SW_TASK_CALLBACK, pid_t pid = 1) {
        EventData message{};
        message.info.type = SW_SERVER_EVENT_FINISH;
        message.info.fd = id;
        message.info.ext_flags = flags;
        message.info.task_source_pid = pid;
        message.info.len = 1024;
        memset(message.data, static_cast<unsigned char>(id), message.info.len);
        return message;
    }

    EventData large_result(TaskId id) {
        char path[] = "/tmp/swoole-task-result-XXXXXX";
        int fd = mkstemp(path);
        EXPECT_GE(fd, 0);
        if (fd >= 0) {
            EXPECT_EQ(write(fd, "result", 6), 6);
            close(fd);
        }
        files.emplace_back(path);
        PacketTask packet{};
        packet.length = 6;
        swoole_strlcpy(packet.tmpfile, path, sizeof(packet.tmpfile));
        auto message = result(id, SW_TASK_CALLBACK | SW_TASK_TMPFILE, owner);
        message.info.len = sizeof(packet);
        memcpy(message.data, &packet, sizeof(packet));
        return message;
    }

    network::Socket *listen_as_owner() {
        auto *socket = make_socket(SW_SOCK_UNIX_DGRAM, SW_FD_TASK_RESULT, SW_SOCK_NONBLOCK | SW_SOCK_CLOEXEC);
        if (!socket) {
            return nullptr;
        }
        peers.push_back(socket);
        if (!socket->set_buffer_size(2048) || socket->bind(server->get_task_result_socket_path(owner)) < 0) {
            return nullptr;
        }
        return socket;
    }

    network::Socket *channel_socket(int events) {
        for (auto &entry : reactor->get_sockets()) {
            auto *socket = entry.second;
            if (socket->fd_type == SW_FD_TASK_RESULT && (socket->events & events)) {
                return socket;
            }
        }
        return nullptr;
    }

    void trigger(network::Socket *socket, EventType type) {
        ASSERT_NE(socket, nullptr);
        Event event{};
        event.fd = socket->fd;
        event.socket = socket;
        ASSERT_EQ(reactor->get_handler(SW_FD_TASK_RESULT, type)(reactor.get(), &event), SW_OK);
    }

    void send_to_receiver(const void *data, size_t length) {
        auto *peer = make_socket(SW_SOCK_UNIX_DGRAM, SW_FD_TASK_RESULT, SW_SOCK_NONBLOCK | SW_SOCK_CLOEXEC);
        ASSERT_NE(peer, nullptr);
        peers.push_back(peer);
        ASSERT_EQ(peer->connect(server->get_task_result_socket_path(getpid()), 0), SW_OK);
        ASSERT_EQ(peer->send(data, length, 0), static_cast<ssize_t>(length));
        trigger(channel_socket(SW_EVENT_READ), SW_EVENT_READ);
    }

    size_t fill_queue() {
        // Bound the work and use a small receiving buffer to get real EAGAIN,
        // rather than assuming a particular OS datagram-queue capacity.
        size_t count = 0;
        while (!channel_socket(SW_EVENT_WRITE) && count < 256) {
            auto message = result(++count);
            server->finish_task(&message);
        }
        EXPECT_NE(channel_socket(SW_EVENT_WRITE), nullptr);
        return count;
    }

    std::vector<TaskId> drain(network::Socket *peer) {
        std::vector<TaskId> ids;
        for (size_t round = 0; round < 512; round++) {
            EventData message{};
            ssize_t n;
            while ((n = peer->recv(&message, sizeof(message), 0)) >= 0) {
                EXPECT_EQ(n, static_cast<ssize_t>(message.size()));
                EXPECT_EQ(message.info.type, SW_SERVER_EVENT_FINISH);
                EXPECT_EQ(message.info.task_source_pid, static_cast<uint32_t>(owner));
                ids.push_back(message.info.fd);
                if (!(message.info.ext_flags & SW_TASK_TMPFILE)) {
                    EXPECT_EQ(std::string(message.data, message.info.len),
                              std::string(1024, static_cast<unsigned char>(message.info.fd)));
                }
            }
            EXPECT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);
            auto *sender = channel_socket(SW_EVENT_WRITE);
            if (!sender) {
                return ids;
            }
            trigger(sender, SW_EVENT_WRITE);
        }
        ADD_FAILURE() << "forwarding queue did not drain";
        return ids;
    }

    TimerNode *expiry() {
        if (!sw_timer() || sw_timer()->count() != 1) {
            ADD_FAILURE() << "expected exactly one forwarding timer";
            return nullptr;
        }
        return sw_timer()->get_map().begin()->second;
    }

    void expire_now(TimerNode *node) {
        ASSERT_NE(node, nullptr);
        node->exec_msec = 0;
        sw_timer()->update(node);
        // A timer added this round is eligible in the next reactor round.
        reactor->execute_end_callbacks();
        reactor->execute_end_callbacks();
    }
};
}  // namespace

TEST_F(TaskResult, private_directory_and_socket_lifecycle) {
    const auto directory = server->task_result_directory_;
    struct stat metadata{};
    ASSERT_EQ(stat(directory.c_str(), &metadata), 0);
    EXPECT_EQ(metadata.st_mode & 0777, 0700);
    EXPECT_EQ(metadata.st_uid, geteuid());
    const auto path = server->get_task_result_socket_path(getpid());
    EXPECT_EQ(path, directory + '/' + std::to_string(getpid()) + ".sock");
    ASSERT_TRUE(server->prepare_task_result_channel());
    auto *receiver = channel_socket(SW_EVENT_READ);
    ASSERT_NE(receiver, nullptr);
    const int fd = receiver->fd;
    EXPECT_EQ(fcntl(fd, F_GETFL) & O_NONBLOCK, O_NONBLOCK);
    EXPECT_EQ(fcntl(fd, F_GETFD) & FD_CLOEXEC, FD_CLOEXEC);
    ASSERT_EQ(stat(path.c_str(), &metadata), 0);
    EXPECT_TRUE(S_ISSOCK(metadata.st_mode));
    EXPECT_TRUE(reactor->if_exit());
    ASSERT_TRUE(server->prepare_task_result_channel());
    EXPECT_EQ(channel_socket(SW_EVENT_READ), receiver);
    server->cleanup_task_result_socket(getpid());
    EXPECT_EQ(access(path.c_str(), F_OK), -1);
    EXPECT_EQ(fcntl(fd, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
    server->cleanup_task_result_socket(getpid());
    server->destroy_task_result_directory();
    EXPECT_EQ(access(directory.c_str(), F_OK), -1);
    server->destroy_task_result_directory();
}

TEST_F(TaskResult, receiver_is_only_created_for_process_event_workers_with_tasks) {
    for (auto mode : {Server::MODE_BASE, Server::MODE_THREAD}) {
        server->mode_ = mode;
        EXPECT_TRUE(server->prepare_task_result_channel());
        EXPECT_EQ(server->task_result_channel_, nullptr);
        // Binding cleanup in these modes must not touch the PROCESS counter.
        server->complete_task();
    }
    server->mode_ = Server::MODE_PROCESS;
    SwooleWG.type = SW_TASK_WORKER;
    EXPECT_TRUE(server->prepare_task_result_channel());
    EXPECT_EQ(server->task_result_channel_, nullptr);
    SwooleWG.type = SW_EVENT_WORKER;
    server->task_worker_num = 0;
    EXPECT_TRUE(server->prepare_task_result_channel());
    EXPECT_EQ(server->task_result_channel_, nullptr);
}

TEST_F(TaskResult, local_and_global_results_do_not_create_a_forwarder) {
    for (auto mode : {Server::MODE_PROCESS, Server::MODE_BASE, Server::MODE_THREAD}) {
        server->mode_ = mode;
        for (uint16_t flags : std::vector<uint16_t>{0, SW_TASK_CALLBACK, SW_TASK_COROUTINE}) {
            for (pid_t pid : {pid_t{0}, getpid()}) {
                auto message = result(received.size(), flags, pid);
                server->finish_task(&message);
            }
        }
        auto global = result(100, 0, owner);
        server->finish_task(&global);
        EXPECT_EQ(server->task_result_channel_, nullptr);
    }
    EXPECT_EQ(received.size(), 21u);
}

TEST_F(TaskResult, receiver_validates_datagrams_before_delivering_results) {
    ASSERT_TRUE(server->prepare_task_result_channel());
    auto message = result(42, SW_TASK_COROUTINE, getpid());
    send_to_receiver(&message, message.size());
    ASSERT_EQ(received.size(), 1u);
    EXPECT_MEMEQ(&received[0], &message, message.size());

    send_to_receiver(&message, sizeof(DataHead) - 1);
    send_to_receiver(&message, message.size() - 1);
    std::vector<char> oversized(sizeof(EventData) + 1);
    send_to_receiver(oversized.data(), oversized.size());
    message.info.len = sizeof(message.data) + 1;
    send_to_receiver(&message, sizeof(message));
    message = result(43, SW_TASK_CALLBACK, owner);
    send_to_receiver(&message, message.size());
    message.info.task_source_pid = getpid();
    message.info.type = SW_SERVER_EVENT_RECV_DATA;
    send_to_receiver(&message, message.size());
    EXPECT_EQ(received.size(), 1u);

    message = result(44, SW_TASK_CALLBACK, getpid());
    send_to_receiver(&message, message.size());
    ASSERT_EQ(received.size(), 2u);
    EXPECT_EQ(received.back().info.fd, 44);
    // Spurious readiness with no data must be harmless.
    trigger(channel_socket(SW_EVENT_READ), SW_EVENT_READ);
}

TEST_F(TaskResult, pending_contexts_block_exit_until_completion_or_failed_dispatch) {
    // Use real task IPC for the count, without starting any worker processes.
    server->destroy_task_result_directory();
    server->worker_num = server->reactor_num = 1;
    ASSERT_NE(server->add_port(SW_SOCK_TCP, TEST_HOST, 0), nullptr);
    ASSERT_EQ(server->create(), SW_OK);
    ASSERT_TRUE(server->prepare_task_result_channel());
    EXPECT_TRUE(reactor->if_exit());
    for (uint16_t flags : {SW_TASK_CALLBACK, SW_TASK_COROUTINE}) {
        EventData message{};
        ASSERT_TRUE(Server::task_pack(&message, "task", 4));
        EXPECT_EQ(message.info.task_source_pid, static_cast<uint32_t>(getpid()));
        message.info.ext_flags |= SW_TASK_NONBLOCK | flags;
        int destination = 0;
        ASSERT_TRUE(server->task(&message, &destination));
        EXPECT_EQ(server->pending_task_count_, 1u);
        EXPECT_FALSE(reactor->if_exit());
        server->complete_task();
        EXPECT_TRUE(reactor->if_exit());
    }
    auto global = result(100, SW_TASK_NONBLOCK, getpid());
    int destination = 0;
    ASSERT_TRUE(server->task(&global, &destination));
    EXPECT_EQ(server->pending_task_count_, 0u);
    EXPECT_TRUE(reactor->if_exit());

    server->get_task_worker_pool()->workers[0].pipe_master->close_fd();
    for (uint16_t flags : {SW_TASK_CALLBACK, SW_TASK_COROUTINE}) {
        auto message = result(101, SW_TASK_NONBLOCK | flags, getpid());
        destination = 0;
        EXPECT_FALSE(server->task(&message, &destination));
        EXPECT_EQ(server->pending_task_count_, 0u);
        EXPECT_TRUE(reactor->if_exit());
    }
}

TEST_F(TaskResult, forwarding_preserves_payload_and_reuses_the_original_expiry) {
    auto *peer = listen_as_owner();
    ASSERT_NE(peer, nullptr);
    auto message = result(10);
    server->finish_task(&message);
    auto *node = expiry();
    ASSERT_NE(node, nullptr);
    const auto id = node->id;
    const auto deadline = node->exec_msec;
    EXPECT_LE(deadline - sw_timer()->get_relative_msec(), 20000);
    EXPECT_GE(deadline - sw_timer()->get_relative_msec(), 19000);
    for (uint16_t flags : {SW_TASK_CALLBACK, SW_TASK_COROUTINE}) {
        message = result(11, flags);
        server->finish_task(&message);
        EXPECT_EQ(sw_timer()->count(), 1u);
        EXPECT_EQ(sw_timer()->get(id), node);
        EXPECT_EQ(node->exec_msec, deadline);
    }
    auto ids = drain(peer);
    EXPECT_EQ(ids, (std::vector<TaskId>{10, 11, 11}));
    EXPECT_TRUE(received.empty());
    EXPECT_EQ(channel_socket(SW_EVENT_WRITE), nullptr);
    // Cached-socket housekeeping must not delay this worker's own shutdown.
    ASSERT_TRUE(server->prepare_task_result_channel());
    EXPECT_EQ(sw_timer()->count(), 0u);
    reactor->execute_end_callbacks();
    EXPECT_TRUE(reactor->if_exit());
}

TEST_F(TaskResult, backpressure_preserves_fifo_and_blocks_exit_without_write_interest) {
    auto *peer = listen_as_owner();
    ASSERT_NE(peer, nullptr);
    const auto queued = fill_queue();
    auto *sender = channel_socket(SW_EVENT_WRITE);
    ASSERT_NE(sender, nullptr);
    for (size_t i = 1; i <= 3; i++) {
        auto message = result(queued + i);
        server->finish_task(&message);
    }
    ASSERT_TRUE(server->prepare_task_result_channel());
    EXPECT_EQ(sw_timer()->count(), 0u);
    EXPECT_FALSE(reactor->if_exit());
    // The explicit queued-byte condition must work independently of WRITE events.
    ASSERT_EQ(reactor->del(sender), SW_OK);
    EXPECT_FALSE(reactor->if_exit());
    ASSERT_EQ(reactor->add(sender, SW_EVENT_WRITE), SW_OK);
    // Still blocked before the peer reads anything.
    trigger(sender, SW_EVENT_WRITE);
    auto ids = drain(peer);
    ASSERT_EQ(ids.size(), queued + 3);
    for (size_t i = 0; i < ids.size(); i++) {
        EXPECT_EQ(ids[i], static_cast<TaskId>(i + 1));
    }
    EXPECT_EQ(channel_socket(SW_EVENT_WRITE), nullptr);
    reactor->execute_end_callbacks();
    EXPECT_TRUE(reactor->if_exit());
}

TEST_F(TaskResult, full_queue_discards_large_results_without_leaking_files) {
    auto *peer = listen_as_owner();
    ASSERT_NE(peer, nullptr);
    const auto count = fill_queue();
    auto message = large_result(1000);
    // The descriptor cannot fit; exercise both the single-packet and total-byte limits.
    network::Socket::default_buffer_size = message.size() - 1;
    server->finish_task(&message);
    EXPECT_EQ(access(files.back().c_str(), F_OK), -1);
    message = large_result(1001);
    network::Socket::default_buffer_size = message.size();
    server->finish_task(&message);
    EXPECT_EQ(access(files.back().c_str(), F_OK), -1);
    EXPECT_EQ(drain(peer).size(), count);
    EXPECT_TRUE(received.empty());
}

TEST_F(TaskResult, unreachable_owner_discards_large_result_without_global_fallback) {
    auto message = large_result(1);
    server->finish_task(&message);
    EXPECT_EQ(access(files.back().c_str(), F_OK), -1);
    EXPECT_TRUE(received.empty());
    EXPECT_EQ(channel_socket(SW_EVENT_WRITE), nullptr);
    EXPECT_FALSE(swoole_timer_is_available());
}

TEST_F(TaskResult, closed_owner_removes_cached_sender_and_its_timer) {
    auto *peer = listen_as_owner();
    ASSERT_NE(peer, nullptr);
    auto message = result(1);
    server->finish_task(&message);
    ASSERT_NE(expiry(), nullptr);
    peer->close_fd();
    message = large_result(2);
    server->finish_task(&message);
    EXPECT_EQ(access(files.back().c_str(), F_OK), -1);
    EXPECT_EQ(sw_timer()->count(), 0u);
    EXPECT_TRUE(received.empty());
}

TEST_F(TaskResult, queued_send_error_cleans_up_every_large_result) {
    auto *peer = listen_as_owner();
    ASSERT_NE(peer, nullptr);
    fill_queue();
    for (TaskId id : {1000, 1001}) {
        auto message = large_result(id);
        server->finish_task(&message);
        EXPECT_EQ(access(files.back().c_str(), F_OK), 0);
    }
    auto *sender = channel_socket(SW_EVENT_WRITE);
    ASSERT_NE(sender, nullptr);
    peer->close_fd();
    trigger(sender, SW_EVENT_ERROR);
    EXPECT_EQ(sw_timer()->count(), 0u);
    EXPECT_EQ(channel_socket(SW_EVENT_WRITE), nullptr);
    for (const auto &path : files) {
        EXPECT_EQ(access(path.c_str(), F_OK), -1);
    }
    ASSERT_TRUE(server->prepare_task_result_channel());
    reactor->execute_end_callbacks();
    EXPECT_TRUE(reactor->if_exit());
}

TEST_F(TaskResult, expiration_discards_queued_files_and_allows_a_fresh_sender) {
    auto *peer = listen_as_owner();
    ASSERT_NE(peer, nullptr);
    fill_queue();
    auto message = large_result(1000);
    server->finish_task(&message);
    EXPECT_EQ(access(files.back().c_str(), F_OK), 0);
    expire_now(expiry());
    EXPECT_EQ(sw_timer()->count(), 0u);
    EXPECT_EQ(channel_socket(SW_EVENT_WRITE), nullptr);
    EXPECT_EQ(access(files.back().c_str(), F_OK), -1);
    drain(peer);
    message = result(2000);
    server->finish_task(&message);
    EXPECT_EQ(sw_timer()->count(), 1u);
    EXPECT_EQ(drain(peer), (std::vector<TaskId>{2000}));
}

TEST_F(TaskResult, worker_cleanup_discards_queued_files_and_cancels_expiry) {
    ASSERT_NE(listen_as_owner(), nullptr);
    fill_queue();
    auto message = large_result(1000);
    server->finish_task(&message);
    EXPECT_EQ(access(files.back().c_str(), F_OK), 0);
    server->cleanup_task_result_socket(getpid());
    reactor->execute_end_callbacks();
    EXPECT_EQ(access(files.back().c_str(), F_OK), -1);
    EXPECT_EQ(sw_timer()->count(), 0u);
    EXPECT_TRUE(reactor->if_exit());
}

TEST_F(TaskResult, cleanup_tolerates_a_timer_already_freed_at_worker_shutdown) {
    ASSERT_NE(listen_as_owner(), nullptr);
    auto message = result(1);
    server->finish_task(&message);
    ASSERT_NE(expiry(), nullptr);
    // Reactor destruction does not dispatch these callbacks after freeing its timer.
    reactor->erase_end_callback(Reactor::PRIORITY_TIMER);
    reactor->remove_exit_condition(Reactor::EXIT_CONDITION_TIMER);
    swoole_timer_free();
    server->cleanup_task_result_socket(getpid());
    EXPECT_FALSE(swoole_timer_is_available());
}

TEST_F(TaskResult, failed_bind_can_be_retried_without_leaking_a_receiver) {
    const auto path = server->get_task_result_socket_path(getpid());
    auto *occupant = make_socket(SW_SOCK_UNIX_DGRAM, SW_FD_TASK_RESULT, SW_SOCK_NONBLOCK | SW_SOCK_CLOEXEC);
    ASSERT_NE(occupant, nullptr);
    peers.push_back(occupant);
    ASSERT_EQ(occupant->bind(path), SW_OK);
    EXPECT_FALSE(server->prepare_task_result_channel());
    EXPECT_EQ(channel_socket(SW_EVENT_READ), nullptr);
    reactor->execute_end_callbacks();
    occupant->close_fd();
    EXPECT_TRUE(server->prepare_task_result_channel());
    EXPECT_NE(channel_socket(SW_EVENT_READ), nullptr);
}

TEST_F(TaskResult, manager_unlinks_only_the_reaped_workers_endpoint) {
    auto *peer = listen_as_owner();
    ASSERT_NE(peer, nullptr);
    ASSERT_TRUE(server->prepare_task_result_channel());
    server->cleanup_task_result_socket(owner);
    EXPECT_EQ(access(server->get_task_result_socket_path(owner).c_str(), F_OK), -1);
    EXPECT_EQ(access(server->get_task_result_socket_path(getpid()).c_str(), F_OK), 0);
    EXPECT_NE(channel_socket(SW_EVENT_READ), nullptr);
}
