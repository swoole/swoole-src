#include "test_core.h"
#include "swoole_server.h"
#include "swoole_api.h"

#include <stdexcept>
#include <atomic>
#include <thread>

using namespace swoole;

namespace {
class CloseFactory : public Factory {
  public:
    size_t notifications = 0;
    bool reject_notification = false;
    bool throw_notification = false;
    bool reject_close_command = false;
    bool defer_close_command = false;
    std::atomic<size_t> close_commands{0};
    std::atomic<uint32_t> close_flags{0};

    explicit CloseFactory(Server *server) : Factory(server) {}
    bool start() override {
        return true;
    }
    bool shutdown() override {
        return true;
    }
    bool dispatch(SendData *) override {
        return true;
    }
    bool notify(DataHead *) override {
        notifications++;
        if (throw_notification) {
            throw std::runtime_error("notification failed");
        }
        return !reject_notification;
    }
    bool finish(SendData *data) override {
        close_commands++;
        close_flags = data->info.ext_flags;
        return !reject_close_command && (defer_close_command || server_->send_to_connection(data) == SW_OK);
    }
    bool end(SessionId id, int flags) override {
        return server_->finish_close(id, flags);
    }
};

class ConnectionState : public testing::Test {
  protected:
    std::unique_ptr<Server> server;
    std::unique_ptr<Reactor> reactor;
    std::unique_ptr<CloseFactory> factory;
    Factory *original_factory = nullptr;
    Reactor *saved_reactor = nullptr;
    WorkerGlobal saved_worker{};
    Worker worker{};
    ListenPort *port = nullptr;
    std::vector<network::Socket *> peers;
    size_t callbacks = 0;

    virtual Server::Mode server_mode() const {
        return Server::MODE_BASE;
    }

    void SetUp() override {
        saved_reactor = SwooleTG.reactor;
        saved_worker = SwooleWG;
        SwooleWG.id = 0;
        server.reset(new Server(server_mode()));
        server->worker_num = server->reactor_num = 1;
        port = server->add_port(SW_SOCK_TCP, TEST_HOST, 0);
        ASSERT_NE(port, nullptr);
        ASSERT_EQ(server->create(), SW_OK);
        SwooleWG.worker = &worker;
        SwooleWG.pid = getpid();
        ASSERT_EQ(port->listen(), SW_OK);
        // The production start loop registers listen-port metadata before accepting sessions.
        server->get_connection(port->get_fd())->object = port;
        server->get_connection(port->get_fd())->info.assign(port->type, port->host, port->port);
        server->set_minfd(port->get_fd());
        server->set_maxfd(port->get_fd());
        reactor.reset(new Reactor());
        ASSERT_TRUE(reactor->ready());
        reactor->ptr = server.get();
        reactor->id = 0;
        reactor->close = Server::close_connection;
        SwooleTG.reactor = reactor.get();
        server->init_reactor(reactor.get());
        original_factory = server->factory_;
        factory.reset(new CloseFactory(server.get()));
        server->factory_ = factory.get();
        server->onClose = [&](Server *, DataHead *) { callbacks++; };
    }

    network::Socket *open_peer() {
        auto *peer = swoole::make_socket(SW_SOCK_TCP, SW_FD_SESSION, 0);
        if (!peer) {
            return nullptr;
        }
        peers.push_back(peer);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port->port);
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::connect(peer->fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0) {
            return nullptr;
        }
        return peer;
    }

    Connection *connect() {
        return open_peer() ? accept_connection() : nullptr;
    }

    Connection *accept_connection() {
        auto *socket = port->socket->accept();
        if (!socket) {
            return nullptr;
        }
        socket->fd_type = SW_FD_SESSION;
        auto *conn = server->add_connection(port, socket, port->get_fd());
        if (!conn) {
            socket->free();
            return nullptr;
        }
        if (reactor->add(socket, SW_EVENT_READ) != SW_OK) {
            Server::close_connection(reactor.get(), socket);
            return nullptr;
        }
        return conn;
    }

    int control(Connection *conn, ServerEventType type, uint32_t flags = 0) {
        SendData event{};
        event.info.fd = conn->session_id;
        event.info.type = type;
        event.info.ext_flags = flags;
        return server->send_to_connection(&event);
    }

    void TearDown() override {
        if (server && reactor) {
            server->foreach_connection(
                [&](Connection *conn) { Server::close_connection(reactor.get(), conn->socket); });
            reactor->execute_end_callbacks();
        }
        for (auto *peer : peers) {
            peer->free();
        }
        if (server && original_factory) {
            server->factory_ = original_factory;
        }
        factory.reset();
        if (server && server->workers) {
            server->destroy();
        }
        server.reset();
        reactor.reset();
        SwooleTG.reactor = saved_reactor;
        SwooleWG = saved_worker;
    }
};
}  // namespace

TEST_F(ConnectionState, paused_timeout_waits_for_one_worker_close) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    const auto id = conn->session_id;
    EXPECT_EQ(control(conn, SW_SERVER_EVENT_PAUSE_RECV), SW_OK);
    EXPECT_TRUE(conn->recv_paused);
    EXPECT_TRUE(conn->socket->removed);
    EXPECT_EQ(server->request_close(reactor.get(), conn, ConnectionCloseReason::IDLE_TIMEOUT), SW_OK);
    EXPECT_EQ(factory->notifications, 1u);
    EXPECT_TRUE(conn->active);
    EXPECT_TRUE(conn->close_waiting_worker);
    EXPECT_FALSE(conn->is_close_reset());
    EXPECT_FALSE(conn->close_worker_received);
    EXPECT_EQ(conn->close_callback_state, CloseCallbackState::NONE);
    EXPECT_EQ(control(conn, SW_SERVER_EVENT_RESUME_RECV), SW_ERR);
    EXPECT_TRUE(conn->socket->removed);
    EXPECT_EQ(server->request_close(reactor.get(), conn, ConnectionCloseReason::SOCKET_EVENT), SW_OK);
    EXPECT_EQ(server->request_close(reactor.get(), conn, ConnectionCloseReason::IDLE_TIMEOUT), SW_OK);
    EXPECT_EQ(factory->notifications, 1u);
    EXPECT_TRUE(conn->active);
    EXPECT_TRUE(server->finish_close(id, 0));
    EXPECT_EQ(callbacks, 1u);
    EXPECT_EQ(server->get_connection_verify_no_ssl(id), nullptr);
}

TEST_F(ConnectionState, activity_check_does_not_dereference_a_socket) {
    Connection candidate{};
    EXPECT_FALSE(Server::is_valid_connection(nullptr));
    EXPECT_FALSE(Server::is_valid_connection(&candidate));
    candidate.active = 1;
    EXPECT_TRUE(Server::is_valid_connection(&candidate));
    candidate.socket = reinterpret_cast<network::Socket *>(uintptr_t{1});
    EXPECT_TRUE(Server::is_valid_connection(&candidate));
    candidate.active = 0;
    EXPECT_FALSE(Server::is_valid_connection(&candidate));
}

TEST_F(ConnectionState, repeated_force_ends_io_but_reserves_the_session_for_one_late_callback) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    const auto id = conn->session_id;
    auto *socket = conn->socket;
    socket->out_buffer = new Buffer(SW_SEND_BUFFER_SIZE);
    socket->out_buffer->append("pending", 7);
    conn->send_queued_bytes = 7;
    ASSERT_EQ(server->request_force_close(reactor.get(), conn, ConnectionCloseReason::IDLE_TIMEOUT), SW_OK);
    ASSERT_EQ(factory->notifications, 1u);
    EXPECT_TRUE(conn->is_close_aborting());
    ASSERT_EQ(server->request_force_close(reactor.get(), conn, ConnectionCloseReason::IDLE_TIMEOUT), SW_OK);
    EXPECT_EQ(socket->out_buffer, nullptr);
    EXPECT_EQ(conn->send_queued_bytes, 0u);
    EXPECT_EQ(server->get_connection_verify_no_ssl(id), conn);
    EXPECT_EQ(factory->notifications, 1u);
    EXPECT_EQ(callbacks, 0u);
    char byte;
    EXPECT_EQ(::recv(peers.back()->fd, &byte, 1, MSG_DONTWAIT), 0);
    EXPECT_TRUE(server->finish_close(id, 0));
    EXPECT_EQ(callbacks, 1u);
    EXPECT_FALSE(server->finish_close(id, 0));
    EXPECT_EQ(callbacks, 1u);
}

TEST_F(ConnectionState, force_does_not_repeat_an_already_dispatched_callback) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    const auto id = conn->session_id;
    factory->defer_close_command = true;
    ASSERT_EQ(server->request_close(reactor.get(), conn, ConnectionCloseReason::PEER_EOF), SW_OK);
    ASSERT_TRUE(server->finish_close(id, 0));
    EXPECT_EQ(callbacks, 1u);
    ASSERT_EQ(server->request_force_close(reactor.get(), conn, ConnectionCloseReason::IDLE_TIMEOUT), SW_OK);
    EXPECT_EQ(server->get_connection_verify_no_ssl(id), nullptr);
    EXPECT_EQ(conn->close_reason, static_cast<sw_atomic_t>(ConnectionCloseReason::PEER_EOF));
    EXPECT_FALSE(server->finish_close(id, 0));
    EXPECT_EQ(callbacks, 1u);
}

TEST_F(ConnectionState, force_aborts_a_graceful_close_with_pending_output) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    const auto id = conn->session_id;
    conn->socket->out_buffer = new Buffer(SW_SEND_BUFFER_SIZE);
    conn->socket->out_buffer->append("pending", 7);
    ASSERT_TRUE(server->finish_close(id, Server::CLOSE_ACTIVELY));
    ASSERT_TRUE(conn->active);
    ASSERT_TRUE(conn->close_queued);
    EXPECT_EQ(callbacks, 1u);
    EXPECT_EQ(server->request_force_close(reactor.get(), conn, ConnectionCloseReason::IDLE_TIMEOUT), SW_OK);
    EXPECT_EQ(server->get_connection_verify_no_ssl(id), nullptr);
    EXPECT_EQ(conn->close_reason, static_cast<sw_atomic_t>(ConnectionCloseReason::APPLICATION));
    EXPECT_EQ(callbacks, 1u);
}

TEST_F(ConnectionState, heartbeat_honors_protect_and_notifies_once_after_expiry) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    port->heartbeat_idle_time = 1;
    server->heartbeat_check_interval = 1;
    server->max_wait_time = 6;
    conn->set_last_recv_time(microtime() - 2);
    conn->protect = 1;
    server->check_idle_connections(reactor.get());
    EXPECT_FALSE(conn->is_close_requested());
    EXPECT_EQ(factory->notifications, 0u);
    conn->protect = 0;
    server->check_idle_connections(reactor.get());
    server->check_idle_connections(reactor.get());
    EXPECT_EQ(conn->close_reason, static_cast<sw_atomic_t>(ConnectionCloseReason::IDLE_TIMEOUT));
    EXPECT_EQ(factory->notifications, 1u);
    EXPECT_TRUE(server->finish_close(conn->session_id, 0));
    EXPECT_EQ(callbacks, 1u);
}

TEST_F(ConnectionState, background_heartbeat_snapshots_only_expired_unprotected_sessions) {
    auto *expired = connect();
    auto *recent = connect();
    auto *protected_conn = connect();
    ASSERT_NE(expired, nullptr);
    ASSERT_NE(recent, nullptr);
    ASSERT_NE(protected_conn, nullptr);
    port->heartbeat_idle_time = 1;
    const double now = microtime();
    expired->set_last_recv_time(now - 2);
    recent->set_last_recv_time(now);
    protected_conn->set_last_recv_time(now - 2);
    protected_conn->protect = 1;
    const auto owner_thread = std::this_thread::get_id();
    std::vector<std::pair<SessionId, ReactorId>> candidates;
    std::thread scanner([&]() {
        server->foreach_idle_connection(now, [&](SessionId id, ReactorId owner) {
            EXPECT_NE(std::this_thread::get_id(), owner_thread);
            // IPC may block; the snapshot callback must run after releasing the slot lock.
            const bool released = sw_atomic_cmp_set(&expired->lock, 0, 1);
            EXPECT_TRUE(released);
            if (released) {
                sw_spinlock_release(&expired->lock);
            }
            candidates.emplace_back(id, owner);
            return true;
        });
    });
    scanner.join();
    ASSERT_EQ(candidates.size(), 1u);
    EXPECT_EQ(candidates.front().first, expired->session_id);
    EXPECT_EQ(candidates.front().second, expired->reactor_id);
    EXPECT_FALSE(expired->is_close_requested());
    EXPECT_EQ(factory->notifications, 0u);
    EXPECT_EQ(callbacks, 0u);
    server->close_idle_connection(reactor.get(), candidates.front().first);
    EXPECT_EQ(factory->notifications, 1u);
    EXPECT_TRUE(server->finish_close(expired->session_id, 0));
    EXPECT_EQ(callbacks, 1u);
}

TEST_F(ConnectionState, background_heartbeat_recent_activity_filter_does_not_acquire_the_slot_lock) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    port->heartbeat_idle_time = 1;
    const double now = microtime();
    conn->set_last_recv_time(now);
    sw_spinlock(&conn->lock);
    ON_SCOPE_EXIT {
        sw_spinlock_release(&conn->lock);
    };
    size_t candidates = 0;
    server->foreach_idle_connection(now, [&](SessionId, ReactorId) {
        candidates++;
        return true;
    });
    EXPECT_EQ(candidates, 0u);
}

TEST_F(ConnectionState, delayed_heartbeat_close_rechecks_activity_and_protection) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    port->heartbeat_idle_time = 1;
    const double now = microtime();
    conn->set_last_recv_time(now - 2);
    SessionId candidate = 0;
    server->foreach_idle_connection(now, [&](SessionId id, ReactorId) {
        candidate = id;
        return true;
    });
    ASSERT_EQ(candidate, conn->session_id);
    // New input arrives while the heartbeat request is waiting in the pipe.
    conn->set_last_recv_time(microtime());
    server->close_idle_connection(reactor.get(), candidate);
    EXPECT_FALSE(conn->is_close_requested());
    EXPECT_EQ(factory->notifications, 0u);
    conn->set_last_recv_time(now - 2);
    conn->protect = 1;
    server->close_idle_connection(reactor.get(), candidate);
    EXPECT_FALSE(conn->is_close_requested());
    EXPECT_EQ(factory->notifications, 0u);
    conn->protect = 0;
    server->close_idle_connection(reactor.get(), candidate);
    EXPECT_TRUE(conn->is_close_requested());
    EXPECT_EQ(factory->notifications, 1u);
}

TEST_F(ConnectionState, background_heartbeat_can_stop_between_close_requests) {
    auto *first = connect();
    auto *second = connect();
    ASSERT_NE(first, nullptr);
    ASSERT_NE(second, nullptr);
    port->heartbeat_idle_time = 1;
    const double now = microtime();
    first->set_last_recv_time(now - 2);
    second->set_last_recv_time(now - 2);
    size_t candidates = 0;
    server->foreach_idle_connection(now, [&](SessionId, ReactorId) {
        candidates++;
        return false;
    });
    EXPECT_EQ(candidates, 1u);
    EXPECT_EQ(factory->notifications, 0u);
}

TEST_F(ConnectionState, force_deadline_retires_a_session_whose_worker_never_responds) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    const auto id = conn->session_id;
    port->heartbeat_idle_time = 1;
    server->heartbeat_check_interval = 1;
    server->max_wait_time = 1;
    conn->set_last_recv_time(microtime() - 5);
    server->check_idle_connections(reactor.get());
    EXPECT_EQ(factory->notifications, 1u);
    EXPECT_TRUE(conn->active);
    server->check_idle_connections(reactor.get());
    EXPECT_EQ(server->get_connection_verify_no_ssl(id), nullptr);
    EXPECT_FALSE(server->finish_close(id, 0));
    EXPECT_EQ(callbacks, 0u);
}

TEST_F(ConnectionState, stale_force_command_cannot_close_a_reused_descriptor) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    const auto old_id = conn->session_id;
    const auto old_fd = conn->fd;
    ASSERT_NE(open_peer(), nullptr);
    ASSERT_TRUE(server->finish_close(old_id, Server::CLOSE_ACTIVELY));
    reactor->execute_end_callbacks();
    auto *replacement = accept_connection();
    ASSERT_NE(replacement, nullptr);
    ASSERT_EQ(replacement->fd, old_fd);
    ASSERT_NE(replacement->session_id, old_id);
    server->close_idle_connection(reactor.get(), old_id);
    EXPECT_EQ(server->get_thread(0)->close_connection(reactor.get(), old_id, ConnectionCloseReason::IDLE_TIMEOUT),
              SW_OK);
    EXPECT_TRUE(replacement->active);
    EXPECT_FALSE(replacement->is_close_requested());
    EXPECT_EQ(callbacks, 1u);
    EXPECT_EQ(factory->notifications, 0u);
}

TEST_F(ConnectionState, pause_backpressure_and_shutdown_are_independent) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    EXPECT_EQ(control(conn, SW_SERVER_EVENT_PAUSE_RECV), SW_OK);
    conn->recv_throttled = 1;
    EXPECT_EQ(control(conn, SW_SERVER_EVENT_RESUME_RECV), SW_OK);
    EXPECT_FALSE(conn->recv_paused);
    EXPECT_TRUE(conn->recv_throttled);
    EXPECT_TRUE(conn->socket->removed);
    conn->recv_throttled = 0;
    EXPECT_EQ(server->update_recv_interest(reactor.get(), conn), SW_OK);
    EXPECT_TRUE(conn->socket->events & SW_EVENT_READ);
    conn->recv_shutdown = 1;
    EXPECT_EQ(server->update_recv_interest(reactor.get(), conn), SW_OK);
    EXPECT_EQ(control(conn, SW_SERVER_EVENT_RESUME_RECV), SW_OK);
    EXPECT_TRUE(conn->socket->removed);
    EXPECT_TRUE(conn->recv_shutdown);
}

TEST_F(ConnectionState, output_drain_does_not_clear_application_pause) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    EXPECT_EQ(control(conn, SW_SERVER_EVENT_PAUSE_RECV), SW_OK);
    EXPECT_EQ(reactor->add(conn->socket, SW_EVENT_WRITE), SW_OK);
    EXPECT_FALSE(conn->socket->removed);
    EXPECT_TRUE(conn->recv_paused);
    EXPECT_EQ(server->update_recv_interest(reactor.get(), conn, true), SW_OK);
    EXPECT_TRUE(conn->socket->removed);
    EXPECT_TRUE(conn->recv_paused);
}

TEST_F(ConnectionState, graceful_close_has_one_marker_and_abort_does_not_repeat_callback) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    const auto id = conn->session_id;
    conn->socket->out_buffer = new Buffer(SW_SEND_BUFFER_SIZE);
    conn->socket->out_buffer->append("pending", 7);
    EXPECT_TRUE(server->finish_close(id, Server::CLOSE_ACTIVELY));
    ASSERT_TRUE(conn->active);
    EXPECT_TRUE(conn->close_worker_received);
    EXPECT_TRUE(conn->close_queued);
    EXPECT_FALSE(conn->socket->events & SW_EVENT_READ);
    EXPECT_TRUE(conn->socket->events & SW_EVENT_WRITE);
    EXPECT_EQ(conn->socket->out_buffer->count(), 2u);
    EXPECT_FALSE(server->finish_close(id, Server::CLOSE_ACTIVELY));
    EXPECT_EQ(swoole_get_last_error(), SW_ERROR_SESSION_CLOSED);
    EXPECT_EQ(control(conn, SW_SERVER_EVENT_CLOSE), SW_OK);
    EXPECT_EQ(conn->socket->out_buffer->count(), 2u);
    EXPECT_EQ(control(conn, SW_SERVER_EVENT_RESUME_RECV), SW_ERR);
    EXPECT_EQ(server->request_close(reactor.get(), conn, ConnectionCloseReason::SOCKET_EVENT), SW_OK);
    EXPECT_EQ(callbacks, 1u);
    EXPECT_EQ(factory->notifications, 0u);
    EXPECT_EQ(server->get_connection_verify_no_ssl(id), nullptr);
}

TEST_F(ConnectionState, failed_notification_releases_transport_without_waiting_for_ack) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    const auto id = conn->session_id;
    factory->reject_notification = true;
    EXPECT_EQ(server->request_close(reactor.get(), conn, ConnectionCloseReason::SOCKET_EVENT), SW_OK);
    EXPECT_EQ(factory->notifications, 1u);
    EXPECT_EQ(callbacks, 0u);
    EXPECT_EQ(server->get_connection_verify_no_ssl(id), nullptr);
}

TEST_F(ConnectionState, throwing_notification_releases_transport_before_propagating) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    const auto id = conn->session_id;
    factory->throw_notification = true;
    EXPECT_THROW(server->request_close(reactor.get(), conn, ConnectionCloseReason::SOCKET_EVENT), std::runtime_error);
    EXPECT_EQ(server->get_connection_verify_no_ssl(id), nullptr);
}

TEST_F(ConnectionState, failed_close_command_can_retry_without_another_callback) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    const auto id = conn->session_id;
    factory->reject_close_command = true;
    EXPECT_FALSE(server->finish_close(id, Server::CLOSE_ACTIVELY));
    EXPECT_TRUE(conn->is_close_requested());
    EXPECT_FALSE(conn->is_close_worker_claimed());
    EXPECT_EQ(callbacks, 1u);
    factory->reject_close_command = false;
    EXPECT_TRUE(server->finish_close(id, Server::CLOSE_ACTIVELY));
    EXPECT_EQ(callbacks, 1u);
    EXPECT_EQ(server->get_connection_verify_no_ssl(id), nullptr);
}

TEST_F(ConnectionState, late_close_cleans_worker_resources_without_replaying_the_callback) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    const auto id = conn->session_id;
    size_t cleanups = 0;
    server->cleanup_connection = [&](Server *, SessionId session_id) {
        EXPECT_EQ(session_id, id);
        cleanups++;
    };
    ASSERT_EQ(Server::close_connection(reactor.get(), conn->socket), SW_OK);
    DataHead event{};
    event.type = SW_SERVER_EVENT_CLOSE;
    event.fd = id;
    server->worker_accept_event(&event);
    server->worker_accept_event(&event);
    EXPECT_EQ(cleanups, 2u);
    EXPECT_EQ(callbacks, 0u);
}

TEST_F(ConnectionState, close_callback_receives_protocol_context_captured_with_the_claim) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    conn->websocket_status = websocket::STATUS_ACTIVE;
    conn->http2_stream = true;
    server->onClose = [&](Server *, DataHead *info) {
        callbacks++;
        ASSERT_EQ(Server::close_connection(reactor.get(), conn->socket), SW_OK);
        EXPECT_EQ(server->get_connection_verify_no_ssl(info->fd), nullptr);
        EXPECT_TRUE(info->ext_flags & Server::CLOSE_CALLBACK_WEBSOCKET);
        EXPECT_TRUE(info->ext_flags & Server::CLOSE_CALLBACK_HTTP2);
    };
    EXPECT_TRUE(server->finish_close(conn->session_id, Server::CLOSE_ACTIVELY));
    EXPECT_EQ(callbacks, 1u);
}

TEST_F(ConnectionState, published_abort_counts_only_as_a_close) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    const auto id = conn->session_id;
    server->abort_connection(reactor.get(), port, conn->socket);
    EXPECT_EQ(server->get_connection_verify_no_ssl(id), nullptr);
    EXPECT_EQ(server->gs->accept_count, 1);
    EXPECT_EQ(port->gs->accept_count, 1);
    EXPECT_EQ(server->gs->close_count, 1);
    EXPECT_EQ(port->gs->close_count, 1);
    EXPECT_EQ(server->gs->abort_count, 0);
    EXPECT_EQ(port->gs->abort_count, 0);
}

#ifdef SW_SUPPORT_DTLS
TEST_F(ConnectionState, dtls_read_without_a_session_retires_the_connection) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    // Simulate a published transport whose DTLS map entry is missing.
    port->ssl = true;
    port->ssl_context = std::make_shared<SSLContext>();
    port->ssl_context->protocols = SW_SSL_DTLS;
    port->dtls_sessions = new std::unordered_map<int, dtls::Session *>;
    const auto id = conn->session_id;
    Event event{};
    event.fd = conn->fd;
    event.socket = conn->socket;
    auto handler = reactor->get_handler(SW_FD_SESSION, SW_EVENT_READ);
    ASSERT_NE(handler, nullptr);
    EXPECT_EQ(handler(reactor.get(), &event), SW_OK);
    EXPECT_EQ(server->get_connection_verify_no_ssl(id), nullptr);
}
#endif

TEST_F(ConnectionState, stale_socket_identity_cannot_release_current_session) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    const auto id = conn->session_id;
    network::Socket stale{};
    stale.fd = conn->fd;
    stale.object = conn;
    EXPECT_EQ(Server::close_connection(reactor.get(), &stale), SW_OK);
    EXPECT_EQ(server->get_connection_verify_no_ssl(id), conn);
    EXPECT_TRUE(conn->active);
}

TEST_F(ConnectionState, reentrant_reset_cannot_deliver_callback_twice) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    const auto id = conn->session_id;
    server->onClose = [&](Server *, DataHead *) {
        callbacks++;
        EXPECT_FALSE(server->finish_close(id, Server::CLOSE_ACTIVELY));
        EXPECT_EQ(swoole_get_last_error(), SW_ERROR_SESSION_CLOSING);
        EXPECT_TRUE(server->finish_close(id, Server::CLOSE_ACTIVELY | Server::CLOSE_RESET));
    };
    EXPECT_TRUE(server->finish_close(id, Server::CLOSE_ACTIVELY));
    EXPECT_EQ(callbacks, 1u);
    EXPECT_EQ(server->get_connection_verify_no_ssl(id), nullptr);
}

TEST_F(ConnectionState, connect_callback_is_claimed_once_and_late_events_are_discarded) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    const auto id = conn->session_id;
    size_t connects = 0;
    server->onConnect = [&](Server *, DataHead *) { connects++; };
    DataHead event{};
    event.type = SW_SERVER_EVENT_CONNECT;
    event.fd = id;
    server->worker_accept_event(&event);
    server->worker_accept_event(&event);
    EXPECT_EQ(connects, 1u);
    EXPECT_TRUE(server->finish_close(id, Server::CLOSE_ACTIVELY));
    server->worker_accept_event(&event);
    EXPECT_EQ(connects, 1u);
    EXPECT_EQ(callbacks, 1u);

    auto *replacement = connect();
    ASSERT_NE(replacement, nullptr);
    EXPECT_NE(replacement->session_id, id);
    server->worker_accept_event(&event);
    EXPECT_FALSE(replacement->connect_callback_claimed);
    event.fd = replacement->session_id;
    server->worker_accept_event(&event);
    server->worker_accept_event(&event);
    EXPECT_EQ(connects, 2u);
}

TEST_F(ConnectionState, simultaneous_peer_and_application_close_claims_callback_once) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    const auto id = conn->session_id;
    factory->defer_close_command = true;
    std::atomic<bool> start{false};
    std::vector<std::thread> workers;
    for (size_t i = 0; i < 8; i++) {
        workers.emplace_back([&] {
            while (!start.load()) {
                std::this_thread::yield();
            }
            server->finish_close(id, Server::CLOSE_ACTIVELY);
        });
    }
    start = true;
    EXPECT_EQ(server->request_close(reactor.get(), conn, ConnectionCloseReason::PEER_EOF), SW_OK);
    for (auto &worker : workers) {
        worker.join();
    }
    EXPECT_EQ(callbacks, 1u);
    EXPECT_EQ(factory->close_commands.load(), 1u);
    EXPECT_LE(factory->notifications, 1u);
    EXPECT_TRUE(conn->active);
    EXPECT_EQ(control(conn, SW_SERVER_EVENT_CLOSE), SW_OK);
    EXPECT_EQ(server->get_connection_verify_no_ssl(id), nullptr);
    EXPECT_EQ(callbacks, 1u);
}

TEST_F(ConnectionState, callback_exception_releases_transport_and_preserves_exception) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    const auto id = conn->session_id;
    server->onClose = [&](Server *, DataHead *) {
        callbacks++;
        throw std::runtime_error("callback failed");
    };
    EXPECT_THROW(server->finish_close(id, Server::CLOSE_ACTIVELY), std::runtime_error);
    EXPECT_EQ(callbacks, 1u);
    EXPECT_EQ(server->get_connection_verify_no_ssl(id), nullptr);
}

TEST_F(ConnectionState, delayed_receive_requires_explicit_resume) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    conn->recv_delayed = 1;
    EXPECT_EQ(server->update_recv_interest(reactor.get(), conn), SW_OK);
    EXPECT_TRUE(conn->socket->removed);
    EXPECT_EQ(server->update_recv_interest(reactor.get(), conn, true), SW_OK);
    EXPECT_TRUE(conn->socket->removed);
    EXPECT_EQ(control(conn, SW_SERVER_EVENT_RESUME_RECV), SW_OK);
    EXPECT_FALSE(conn->recv_delayed);
    EXPECT_TRUE(conn->socket->events & SW_EVENT_READ);
}

TEST_F(ConnectionState, close_without_callback_still_has_terminal_state) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    server->onClose = nullptr;
    factory->defer_close_command = true;
    EXPECT_TRUE(server->finish_close(conn->session_id, Server::CLOSE_ACTIVELY));
    EXPECT_TRUE(conn->is_close_requested());
    EXPECT_FALSE(conn->can_receive());
    EXPECT_FALSE(server->finish_close(conn->session_id, Server::CLOSE_ACTIVELY));
    EXPECT_EQ(control(conn, SW_SERVER_EVENT_RESUME_RECV), SW_ERR);
    EXPECT_EQ(factory->close_commands.load(), 1u);
}

TEST_F(ConnectionState, zero_length_receive_is_not_peer_eof) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    char byte;
    ASSERT_EQ(::shutdown(peers.back()->fd, SHUT_WR), 0);
    ASSERT_EQ(conn->socket->wait_event(1000, SW_EVENT_READ), SW_OK);
    EXPECT_EQ(conn->socket->recv(&byte, 0, 0), 0);
    EXPECT_FALSE(conn->socket->recv_eof);
    EXPECT_EQ(conn->socket->recv(&byte, 1, 0), 0);
    EXPECT_TRUE(conn->socket->recv_eof);
}

TEST_F(ConnectionState, abort_escalation_preserves_first_close_reason) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    factory->defer_close_command = true;
    EXPECT_TRUE(server->finish_close(conn->session_id, Server::CLOSE_ACTIVELY));
    EXPECT_FALSE(conn->is_close_aborting());
    EXPECT_EQ(server->request_close(reactor.get(), conn, ConnectionCloseReason::IO_ERROR, true), SW_OK);
    EXPECT_TRUE(conn->is_close_aborting());
    EXPECT_TRUE(conn->is_close_reset());
    EXPECT_EQ(conn->close_reason, static_cast<sw_atomic_t>(ConnectionCloseReason::APPLICATION));
    EXPECT_EQ(callbacks, 1u);
    EXPECT_EQ(control(conn, SW_SERVER_EVENT_CLOSE), SW_OK);
}

TEST_F(ConnectionState, close_command_retry_cannot_reenable_connect_delivery) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    factory->reject_close_command = true;
    server->onClose = nullptr;
    size_t connects = 0;
    server->onConnect = [&](Server *, DataHead *) { connects++; };
    EXPECT_FALSE(server->finish_close(conn->session_id, Server::CLOSE_ACTIVELY));
    EXPECT_FALSE(conn->is_close_worker_claimed());
    EXPECT_TRUE(conn->is_close_worker_started());
    DataHead event{};
    event.type = SW_SERVER_EVENT_CONNECT;
    event.fd = conn->session_id;
    server->worker_accept_event(&event);
    EXPECT_EQ(connects, 0u);
    factory->reject_close_command = false;
    EXPECT_TRUE(server->finish_close(conn->session_id, Server::CLOSE_ACTIVELY));
}

TEST_F(ConnectionState, reactor_hangup_does_not_impersonate_an_observed_recv_eof) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    char byte;
    // A pending HUP makes the socket helper report closure even if recv itself only returned EAGAIN.
    conn->socket->event_hup = 1;
    EXPECT_EQ(conn->socket->recv(&byte, 1, MSG_DONTWAIT), 0);
    EXPECT_FALSE(conn->socket->recv_eof);
}

TEST_F(ConnectionState, physical_close_keeps_terminal_state_for_a_cached_reader) {
    auto *cached = connect();
    ASSERT_NE(cached, nullptr);
    const auto id = cached->session_id;
    const auto last_recv_time = cached->get_last_recv_time();
    cached->recv_queued_bytes = 17;
    cached->last_dispatch_time = 25;

    // No worker close handling occurred: session retirement must have its own terminal marker.
    EXPECT_EQ(Server::close_connection(reactor.get(), cached->socket), SW_OK);
    EXPECT_FALSE(cached->active);
    EXPECT_TRUE(cached->is_close_requested());
    EXPECT_TRUE(cached->is_session_released());
    EXPECT_FALSE(cached->is_close_worker_started());
    EXPECT_EQ(cached->prepare_receive_event(id, 4, 99), Connection::ReceiveEventStatus::CLOSED);
    EXPECT_EQ(cached->recv_queued_bytes, 17u);
    EXPECT_EQ(cached->last_dispatch_time, 25);
    EXPECT_DOUBLE_EQ(cached->get_last_recv_time(), last_recv_time);
    EXPECT_EQ(callbacks, 0u);
}

TEST_F(ConnectionState, cached_reader_cannot_account_data_to_a_reused_descriptor) {
    auto *cached = connect();
    ASSERT_NE(cached, nullptr);
    const auto old_id = cached->session_id;
    const auto old_fd = cached->fd;
    // Queue the next connection before freeing the accepted descriptor so accept() reuses that exact slot.
    ASSERT_NE(open_peer(), nullptr);
    ASSERT_TRUE(server->finish_close(old_id, Server::CLOSE_ACTIVELY));
    ASSERT_TRUE(cached->is_session_released());
    reactor->execute_end_callbacks();
    auto *replacement = accept_connection();
    ASSERT_NE(replacement, nullptr);
    ASSERT_EQ(replacement->fd, old_fd);
    ASSERT_EQ(replacement, cached);
    ASSERT_NE(replacement->session_id, old_id);
    EXPECT_FALSE(replacement->is_session_released());
    EXPECT_FALSE(replacement->is_close_requested());
    EXPECT_FALSE(replacement->is_close_worker_started());
    EXPECT_DOUBLE_EQ(replacement->get_last_recv_time(), replacement->connect_time);
    replacement->recv_queued_bytes = 100;
    replacement->last_dispatch_time = 123;

    EXPECT_EQ(cached->prepare_receive_event(old_id, 13, 999), Connection::ReceiveEventStatus::STALE);
    EXPECT_EQ(replacement->recv_queued_bytes, 100u);
    EXPECT_EQ(replacement->last_dispatch_time, 123);
    EXPECT_EQ(replacement->prepare_receive_event(replacement->session_id, 10, 124),
              Connection::ReceiveEventStatus::READY);
    EXPECT_EQ(replacement->recv_queued_bytes, 90u);
    EXPECT_EQ(replacement->last_dispatch_time, 124);

    ClientInfoSnapshot snapshot;
    EXPECT_FALSE(server->get_client_info(old_id, snapshot));
    ASSERT_TRUE(server->get_client_info(replacement->session_id, snapshot));
    EXPECT_EQ(snapshot.session_id, replacement->session_id);
    EXPECT_EQ(snapshot.recv_queued_bytes, 90u);
    EXPECT_EQ(snapshot.last_dispatch_time, 124);

    ASSERT_TRUE(server->feedback(replacement->session_id, SW_SERVER_EVENT_PAUSE_RECV));
    EXPECT_TRUE(replacement->recv_paused);
    EXPECT_FALSE(server->feedback(old_id, SW_SERVER_EVENT_RESUME_RECV));
    EXPECT_TRUE(replacement->recv_paused);
    EXPECT_TRUE(replacement->socket->removed);
    EXPECT_TRUE(server->feedback(replacement->session_id, SW_SERVER_EVENT_RESUME_RECV));
}

TEST_F(ConnectionState, passive_close_preserves_data_queued_before_worker_close_processing) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    const auto id = conn->session_id;
    conn->recv_queued_bytes = 12;
    ASSERT_EQ(server->request_close(reactor.get(), conn, ConnectionCloseReason::PEER_EOF), SW_OK);
    ASSERT_TRUE(conn->is_close_requested());
    EXPECT_EQ(conn->prepare_receive_event(id, 4, 10), Connection::ReceiveEventStatus::READY);
    EXPECT_EQ(conn->recv_queued_bytes, 8u);

    factory->defer_close_command = true;
    ASSERT_TRUE(server->finish_close(id, 0));
    EXPECT_EQ(conn->prepare_receive_event(id, 4, 11), Connection::ReceiveEventStatus::CLOSED);
    EXPECT_EQ(conn->recv_queued_bytes, 4u);
    EXPECT_EQ(callbacks, 1u);
}

TEST_F(ConnectionState, owner_receive_accounting_rejects_a_stale_generation_without_taking_the_slot_lock) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    const auto id = conn->session_id;
    conn->recv_queued_bytes = 12;
    // The owning reactor may already hold this lock. Its synchronous accounting must not reacquire it.
    sw_spinlock(&conn->lock);
    EXPECT_EQ(conn->prepare_receive_event_on_reactor(id, 4, 11), Connection::ReceiveEventStatus::READY);
    EXPECT_EQ(conn->prepare_receive_event_on_reactor(id + 1, 4, 99), Connection::ReceiveEventStatus::STALE);
    sw_spinlock_release(&conn->lock);
    EXPECT_EQ(conn->recv_queued_bytes, 8u);
    EXPECT_EQ(conn->last_dispatch_time, 11);
}

TEST_F(ConnectionState, owner_queue_updates_do_not_require_the_slot_lock) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    // BASE/THREAD do not share this queue with another execution context.
    sw_spinlock(&conn->lock);
    conn->add_recv_queued_bytes<Connection::ReceiveQueueMode::OWNER_REACTOR>(12);
    conn->subtract_recv_queued_bytes<Connection::ReceiveQueueMode::OWNER_REACTOR>(4);
    sw_spinlock_release(&conn->lock);
    EXPECT_EQ(conn->get_recv_queued_bytes(), 8u);
}

TEST_F(ConnectionState, process_queue_updates_preserve_concurrent_producer_and_worker_accounting) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    const auto id = conn->session_id;
    constexpr uint32_t iterations = 40000;
    // Keep enough queued bytes that consumption never relies on producer scheduling.
    conn->recv_queued_bytes = iterations;
    std::atomic<size_t> rejected{0};
    std::thread producer([&]() {
        for (uint32_t i = 0; i < iterations; i++) {
            conn->add_recv_queued_bytes<Connection::ReceiveQueueMode::SHARED_PROCESS>(1);
        }
    });
    std::thread consumer([&]() {
        for (uint32_t i = 0; i < iterations; i++) {
            if (conn->prepare_receive_event(id, 1, i) != Connection::ReceiveEventStatus::READY) {
                rejected++;
            }
        }
    });
    producer.join();
    consumer.join();
    EXPECT_EQ(rejected.load(), 0u);
    EXPECT_EQ(conn->get_recv_queued_bytes(), iterations);
}

TEST_F(ConnectionState, base_factory_accounts_receive_data_before_synchronous_consumption) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    conn->recv_queued_bytes = 17;
    server->message_bus.set_buffer_size(SW_IPC_BUFFER_SIZE);
    server->message_bus.alloc_buffer();
    size_t delivered = 0;
    server->onReceive = [&](Server *, RecvData *data) {
        delivered++;
        EXPECT_EQ(std::string(data->data, data->info.len), "data");
        EXPECT_EQ(conn->get_recv_queued_bytes(), 17u);
        return SW_OK;
    };
    server->factory_ = original_factory;
    ON_SCOPE_EXIT {
        server->factory_ = factory.get();
    };
    RecvData data{};
    data.info.len = 4;
    data.data = "data";
    EXPECT_EQ(Server::dispatch_task(&port->protocol, conn->socket, &data), SW_OK);
    EXPECT_EQ(delivered, 1u);
    EXPECT_EQ(conn->get_recv_queued_bytes(), 17u);
    EXPECT_EQ(server->gs->dispatch_count, 1u);
}

TEST_F(ConnectionState, base_factory_rejection_leaves_receive_queue_unchanged) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    conn->recv_queued_bytes = 17;
    conn->begin_close(ConnectionCloseReason::APPLICATION);
    server->factory_ = original_factory;
    ON_SCOPE_EXIT {
        server->factory_ = factory.get();
    };
    RecvData data{};
    data.info.len = 4;
    data.data = "data";
    EXPECT_EQ(Server::dispatch_task(&port->protocol, conn->socket, &data), SW_ERR);
    EXPECT_EQ(conn->get_recv_queued_bytes(), 17u);
    EXPECT_EQ(server->gs->dispatch_count, 0u);
}

TEST_F(ConnectionState, base_factory_does_not_count_control_event_payloads) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    conn->recv_queued_bytes = 17;
    server->message_bus.set_buffer_size(SW_IPC_BUFFER_SIZE);
    server->message_bus.alloc_buffer();
    SendData event{};
    event.info.fd = conn->fd;
    event.info.type = SW_SERVER_EVENT_BUFFER_FULL;
    event.info.len = 4;
    event.data = "data";
    EXPECT_TRUE(original_factory->dispatch(&event));
    EXPECT_EQ(conn->get_recv_queued_bytes(), 17u);
}

TEST_F(ConnectionState, reset_policy_is_applied_when_the_owner_receives_the_close_command) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    factory->defer_close_command = true;
    ASSERT_TRUE(server->finish_close(conn->session_id, Server::CLOSE_ACTIVELY | Server::CLOSE_RESET));
    EXPECT_FALSE(conn->is_close_reset());
    EXPECT_FALSE(conn->is_close_aborting());
    EXPECT_TRUE(factory->close_flags.load() & Server::CLOSE_RESET);
    EXPECT_EQ(control(conn, SW_SERVER_EVENT_CLOSE, factory->close_flags.load()), SW_OK);
    EXPECT_TRUE(conn->is_session_released());
    EXPECT_TRUE(conn->is_close_reset());
    EXPECT_TRUE(conn->is_close_aborting());
    EXPECT_EQ(callbacks, 1u);
}

TEST_F(ConnectionState, abort_command_discards_output_without_requesting_a_reset) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    conn->socket->out_buffer = new Buffer(SW_SEND_BUFFER_SIZE);
    conn->socket->out_buffer->append("pending", 7);
    factory->defer_close_command = true;
    ASSERT_TRUE(server->finish_close(conn->session_id, Server::CLOSE_ACTIVELY | Server::CLOSE_ABORT));
    EXPECT_FALSE(conn->is_close_aborting());
    EXPECT_EQ(control(conn, SW_SERVER_EVENT_CLOSE, factory->close_flags.load()), SW_OK);
    EXPECT_TRUE(conn->is_session_released());
    EXPECT_TRUE(conn->is_close_aborting());
    EXPECT_FALSE(conn->is_close_reset());
    EXPECT_EQ(callbacks, 1u);
}

namespace {
class ConnectionHandoff : public ConnectionState {
  protected:
    uint8_t saved_thread_type = 0;
    uint16_t saved_thread_id = 0;

    Server::Mode server_mode() const override {
        return Server::MODE_PROCESS;
    }

    void SetUp() override {
        ConnectionState::SetUp();
        saved_thread_type = swoole_get_thread_type();
        saved_thread_id = swoole_get_thread_id();
        swoole_set_thread_type(Server::THREAD_MASTER);
        swoole_set_thread_id(0);
        server->get_event_worker_pool()->workers = server->workers;
        server->get_event_worker_pool()->worker_num = server->worker_num;
        ASSERT_TRUE(server->create_worker_pipes());
    }

    bool adopt(IncomingConnection incoming) {
        swoole_set_thread_type(Server::THREAD_REACTOR);
        ON_SCOPE_EXIT {
            swoole_set_thread_type(Server::THREAD_MASTER);
        };
        return server->initialize_connection(reactor.get(), std::move(incoming));
    }

    void prepare_process_dispatch() {
        auto &bus = server->get_thread(0)->message_bus;
        bus.set_buffer_size(SW_IPC_BUFFER_SIZE);
        bus.set_id_generator([sequence = uint64_t{0}]() mutable { return ++sequence; });
        bus.set_always_chunked_transfer();
        bus.alloc_buffer();
        bus.init_pipe_socket(server->get_worker_pipe_master(0));
    }

    void TearDown() override {
        if (server) {
            server->discard_reactor_output(server->message_bus);
            server->discard_incoming_connections();
        }
        ConnectionState::TearDown();
        swoole_set_thread_type(saved_thread_type);
        swoole_set_thread_id(saved_thread_id);
    }
};

void initialize_handoff_bus(MessageBus &bus) {
    bus.set_buffer_size(SW_IPC_BUFFER_SIZE);
    bus.alloc_buffer();
}

IncomingConnection read_handoff(MessageBus &bus, network::Socket *pipe, Server *server) {
    if (bus.read(pipe) <= 0) {
        return IncomingConnection(nullptr, nullptr, 0);
    }
    EXPECT_EQ(bus.get_buffer()->info.flags, 0);
    EXPECT_EQ(bus.get_buffer()->info.msg_id, 0u);
    auto packet = bus.get_packet();
    if (packet.length != sizeof(network::Socket *)) {
        return IncomingConnection(nullptr, nullptr, 0);
    }
    network::Socket *socket;
    memcpy(&socket, packet.data, sizeof(socket));
    const auto server_fd = bus.get_buffer()->info.server_fd;
    bus.pop();
    return IncomingConnection(socket, server->get_port_by_server_fd(server_fd), server_fd);
}
}  // namespace

TEST_F(ConnectionHandoff, heartbeat_pipe_yields_after_a_bounded_batch_and_keeps_the_remaining_request) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    const auto id = conn->session_id;
    port->heartbeat_idle_time = 1;
    server->heartbeat_check_interval = 1;
    server->max_wait_time = 6;
    conn->set_last_recv_time(microtime() - 2);
    const auto started = server->gs->start;
    server->gs->start = 1;
    ON_SCOPE_EXIT {
        server->gs->start = started;
    };
    auto *thread = server->get_thread(0);
    ASSERT_EQ(thread->init(server.get(), reactor.get(), 0), SW_OK);
    ASSERT_NE(thread->heartbeat_pipe, nullptr);
    auto *writer = thread->heartbeat_pipe->get_socket(false);
    auto *reader = thread->heartbeat_pipe->get_socket(true);
    DataHead request{};
    request.fd = id;
    request.type = SW_SERVER_EVENT_CLOSE_FORCE;
    for (size_t i = 0; i < 65; i++) {
        ASSERT_EQ(writer->send_sync(&request, sizeof(request)), static_cast<ssize_t>(sizeof(request)));
    }
    Event event{};
    event.fd = reader->fd;
    event.socket = reader;
    auto handler = reactor->get_handler(SW_FD_PIPE, SW_EVENT_READ);
    ASSERT_NE(handler, nullptr);
    EXPECT_EQ(handler(reactor.get(), &event), SW_OK);
    DataHead pending{};
    EXPECT_EQ(::recv(reader->fd, &pending, sizeof(pending), MSG_PEEK | MSG_DONTWAIT),
              static_cast<ssize_t>(sizeof(pending)));
    EXPECT_EQ(pending.fd, id);
    EXPECT_EQ(factory->notifications, 1u);
    EXPECT_EQ(handler(reactor.get(), &event), SW_OK);
    EXPECT_EQ(::recv(reader->fd, &pending, sizeof(pending), MSG_PEEK | MSG_DONTWAIT), -1);
    EXPECT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);
    EXPECT_EQ(factory->notifications, 1u);
    EXPECT_TRUE(server->finish_close(id, 0));
    EXPECT_EQ(callbacks, 1u);
}

TEST_F(ConnectionHandoff, process_factory_accounts_once_and_worker_consumes_once) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    prepare_process_dispatch();
    size_t delivered = 0;
    server->onReceive = [&](Server *, RecvData *data) {
        delivered++;
        EXPECT_EQ(std::string(data->data, data->info.len), "data");
        EXPECT_EQ(conn->get_recv_queued_bytes(), 0u);
        return SW_OK;
    };
    server->factory_ = original_factory;
    ON_SCOPE_EXIT {
        server->factory_ = factory.get();
    };
    RecvData data{};
    data.info.len = 4;
    data.data = "data";
    EXPECT_EQ(Server::dispatch_task(&port->protocol, conn->socket, &data), SW_OK);
    EXPECT_EQ(conn->get_recv_queued_bytes(), 4u);
    EXPECT_EQ(server->get_thread(0)->dispatch_count, 1u);
    auto &receiver = server->message_bus;
    ASSERT_GT(receiver.read(server->get_worker_pipe_worker(0)), 0);
    server->worker_accept_event(&receiver.get_buffer()->info);
    receiver.pop();
    EXPECT_EQ(delivered, 1u);
    EXPECT_EQ(conn->get_recv_queued_bytes(), 0u);
}

TEST_F(ConnectionHandoff, process_factory_rolls_back_accounting_when_pipe_write_fails) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    prepare_process_dispatch();
    conn->recv_queued_bytes = 17;
    server->get_worker(0)->pipe_object->close(SW_PIPE_CLOSE_WORKER);
    server->get_worker(0)->pipe_worker = nullptr;
    reactor->execute_end_callbacks();
    server->factory_ = original_factory;
    ON_SCOPE_EXIT {
        server->factory_ = factory.get();
    };
    RecvData data{};
    data.info.len = 4;
    data.data = "data";
    EXPECT_EQ(Server::dispatch_task(&port->protocol, conn->socket, &data), SW_ERR);
    EXPECT_EQ(conn->get_recv_queued_bytes(), 17u);
    EXPECT_EQ(server->get_thread(0)->dispatch_count, 0u);
    EXPECT_EQ(server->gs->dispatch_count, 0u);
}

TEST_F(ConnectionHandoff, process_factory_does_not_count_connect_certificate_payloads) {
    auto *conn = connect();
    ASSERT_NE(conn, nullptr);
    prepare_process_dispatch();
    conn->recv_queued_bytes = 17;
    SendData event{};
    event.info.fd = conn->fd;
    event.info.type = SW_SERVER_EVENT_CONNECT;
    event.info.len = 4;
    event.data = "cert";
    ASSERT_TRUE(original_factory->dispatch(&event));
    EXPECT_EQ(conn->get_recv_queued_bytes(), 17u);
    EXPECT_EQ(server->get_thread(0)->dispatch_count, 0u);
    ASSERT_GT(server->message_bus.read(server->get_worker_pipe_worker(0)), 0);
    EXPECT_EQ(server->message_bus.get_buffer()->info.type, SW_SERVER_EVENT_CONNECT);
    server->message_bus.pop();
}

TEST_F(ConnectionHandoff, accept_handoff_is_unpublished_until_the_owner_adopts_it) {
    ASSERT_NE(open_peer(), nullptr);
    auto *socket = port->socket->accept();
    ASSERT_NE(socket, nullptr);
    socket->fd_type = SW_FD_SESSION;
    socket->removed = 1;
    const auto fd = socket->fd;
    MessageBus receiver;
    initialize_handoff_bus(receiver);
    size_t connects = 0;
    server->onConnect = [&](Server *, DataHead *info) {
        connects++;
        EXPECT_EQ(sw_reactor(), reactor.get());
        EXPECT_NE(server->get_connection_verify_no_ssl(info->fd), nullptr);
    };
    ASSERT_TRUE(server->handoff_connection(IncomingConnection(socket, port, port->get_fd())));
    EXPECT_FALSE(server->get_connection(fd)->active);
    EXPECT_EQ(server->gs->accept_count, 0);
    EXPECT_EQ(connects, 0u);
    auto incoming = read_handoff(receiver, server->get_worker_pipe_master(0), server.get());
    ASSERT_NE(incoming.socket, nullptr);
    EXPECT_TRUE(adopt(std::move(incoming)));
    EXPECT_TRUE(server->get_connection(fd)->active);
    EXPECT_EQ(server->gs->accept_count, 1);
    EXPECT_EQ(factory->notifications, 1u);
    DataHead event{};
    event.type = SW_SERVER_EVENT_CONNECT;
    event.fd = server->get_connection(fd)->session_id;
    server->worker_accept_event(&event);
    server->worker_accept_event(&event);
    EXPECT_EQ(connects, 1u);
}

TEST_F(ConnectionHandoff, failed_accept_send_releases_the_unpublished_socket) {
    ASSERT_NE(open_peer(), nullptr);
    auto *socket = port->socket->accept();
    ASSERT_NE(socket, nullptr);
    socket->removed = 1;
    const auto fd = socket->fd;
    server->get_worker(0)->pipe_object->close(SW_PIPE_CLOSE_MASTER);
    server->get_worker(0)->pipe_master = nullptr;
    reactor->execute_end_callbacks();
    EXPECT_FALSE(server->handoff_connection(IncomingConnection(socket, port, port->get_fd())));
    reactor->execute_end_callbacks();
    EXPECT_EQ(::fcntl(fd, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
    EXPECT_EQ(server->gs->accept_count, 0);
    EXPECT_EQ(server->gs->abort_count, 1);
    EXPECT_EQ(port->gs->abort_count, 1);
    EXPECT_EQ(callbacks, 0u);
}

TEST_F(ConnectionHandoff, kernel_queued_handoff_survives_the_sender_scope) {
    ASSERT_NE(open_peer(), nullptr);
    auto *socket = port->socket->accept();
    ASSERT_NE(socket, nullptr);
    socket->fd_type = SW_FD_SESSION;
    socket->removed = 1;
    ASSERT_TRUE(server->handoff_connection(IncomingConnection(socket, port, port->get_fd())));
    // The datagram owns its pointer even when the sender's wrappers are gone.
    server->message_bus.release_pipe_sockets();
    reactor->execute_end_callbacks();
    MessageBus receiver;
    initialize_handoff_bus(receiver);
    auto incoming = read_handoff(receiver, server->get_worker_pipe_master(0), server.get());
    ASSERT_NE(incoming.socket, nullptr);
    EXPECT_NE(::fcntl(incoming.socket->fd, F_GETFD), -1);
    EXPECT_TRUE(adopt(std::move(incoming)));
}

TEST_F(ConnectionHandoff, discarded_unsent_handoff_closes_without_a_close_callback) {
    ASSERT_NE(open_peer(), nullptr);
    auto *socket = port->socket->accept();
    ASSERT_NE(socket, nullptr);
    socket->removed = 1;
    const auto fd = socket->fd;
    auto *pipe = server->get_worker_pipe_worker(0);
    DataHead filler{};
    // Fill the kernel queue, forcing the handoff into the producer's async output buffer.
    size_t sent = 0;
    while (::send(pipe->fd, &filler, sizeof(filler), MSG_DONTWAIT) > 0) {
        ASSERT_LT(++sent, 100000u);
    }
    ASSERT_EQ(errno, EAGAIN);
    ASSERT_TRUE(server->handoff_connection(IncomingConnection(socket, port, port->get_fd())));
    auto *wrapper = server->message_bus.get_pipe_socket(pipe);
    ASSERT_FALSE(Buffer::empty(wrapper->out_buffer));
    server->discard_reactor_output(server->message_bus);
    reactor->execute_end_callbacks();
    EXPECT_EQ(::fcntl(fd, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
    EXPECT_EQ(server->gs->accept_count, 0);
    EXPECT_EQ(server->gs->abort_count, 1);
    EXPECT_EQ(port->gs->abort_count, 1);
    EXPECT_EQ(callbacks, 0u);
}

TEST_F(ConnectionHandoff, unread_kernel_handoff_is_reclaimed_during_shutdown) {
    ASSERT_NE(open_peer(), nullptr);
    auto *socket = port->socket->accept();
    ASSERT_NE(socket, nullptr);
    socket->removed = 1;
    const auto fd = socket->fd;
    ASSERT_TRUE(server->handoff_connection(IncomingConnection(socket, port, port->get_fd())));
    server->discard_incoming_connections();
    reactor->execute_end_callbacks();
    EXPECT_EQ(::fcntl(fd, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
    EXPECT_EQ(server->gs->accept_count, 0);
    EXPECT_EQ(server->gs->close_count, 0);
    EXPECT_EQ(port->gs->close_count, 0);
    EXPECT_EQ(server->gs->abort_count, 1);
    EXPECT_EQ(port->gs->abort_count, 1);
    EXPECT_EQ(callbacks, 0u);
}
