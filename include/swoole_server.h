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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole_string.h"
#include "swoole_socket.h"
#include "swoole_timer.h"
#include "swoole_reactor.h"
#include "swoole_signal.h"
#include "swoole_protocol.h"
#include "swoole_websocket.h"
#include "swoole_process_pool.h"
#include "swoole_pipe.h"
#include "swoole_channel.h"
#include "swoole_message_bus.h"

#ifdef SW_SUPPORT_DTLS
#include "swoole_dtls.h"
#endif

#ifdef __MACH__
#include <sys/syslimits.h>
#endif

#include <string>
#include <queue>
#include <thread>
#include <mutex>
#include <atomic>
#include <unordered_map>
#include <unordered_set>
#include <condition_variable>

//------------------------------------Server-------------------------------------------
namespace swoole {

namespace http_server {
struct Request;
struct RewriteRule;
class StaticHandler;
}  // namespace http_server

class Server;
struct ListenPort;
#ifndef _WIN32
struct Manager;
#endif
class Thread;

typedef std::function<void(void)> WorkerFn;

struct Session {
    SessionId id;
    swSocketFd fd;
    uint32_t reactor_id : 8;
    uint32_t reserve_ : 24;
};

enum class ConnectionCloseReason : uint32_t {
    NONE,
    APPLICATION,
    SOCKET_EVENT,
    PEER_EOF,
    IO_ERROR,
    PROTOCOL_ERROR,
    IDLE_TIMEOUT,
    SERVER_ERROR,
    WORKER_SHUTDOWN,
};

// This tracks the native callback dispatch call, not the lifetime of a yielded PHP coroutine.
enum class CloseCallbackState : uint32_t { NONE, DISPATCHING, DISPATCHED };

// A stable fd-indexed slot, reused by successive session generations. PROCESS shares the slot
// with workers; THREAD shares it between threads; BASE keeps its table private to each worker.
// The owner reactor controls Socket lifetime. Other roles copy/claim metadata under the slot
// lock and validate the expected session. An ordinary predicate never pins the slot or Socket.
// add_connection() resets only [after active, before lock); the tail is initialized explicitly.
struct Connection {
    enum class ReceiveEventStatus { STALE, CLOSED, READY };
    enum class ReceiveQueueMode { OWNER_REACTOR, SHARED_PROCESS };

    /**
     * It must be first. Zero means this slot has no published session, including system/listen fds.
     * The owner publishes/retires it under lock. An optimistic lookup does not pin this generation;
     * worker mutations must revalidate the session under the same lock before using ordinary fields.
     */
    uint8_t active;
    // Immutable within a published session: initialize_connection() created a TLS/DTLS instance.
    uint8_t ssl;
    // Owner reactor sets readiness after the handshake; worker queries also read it. The
    // is_ssl_ready() predicate preserves this ordinary access and adds no publication barrier.
    uint8_t ssl_ready;
    // Owner output feedback consumed by PROCESS send-yield code; this is not a close reason.
    uint8_t overflow;
    SocketType socket_type;
    swSocketFd fd;
    int worker_id;
    // Immutable generation token while active. Retain the caller's token across callbacks/IPC;
    // reading a fresh token from a cached Connection pointer could target a replacement session.
    SessionId session_id;
    //--------------------------------------------------------------
    uint8_t high_watermark;
    uint8_t http_upgrade;
    uint8_t http2_stream;
    uint8_t websocket_compression;
    // Worker, under the slot lock: preserves onClose's reactor_id == -1 convention.
    bool close_actively;
    // Owner reactor: a TYPE_CLOSE marker is already in the output queue.
    uint8_t close_queued;
    // Owner reactor: reset on physical release, independent of output queue policy.
    bool close_reset;
    // Owner reactor: pending output must be discarded.
    bool close_abort;
    // Owner reactor: notification dispatch has begun, even if the socket was already unregistered.
    uint8_t close_notification_started;
    // Owner reactor: notification sent/being sent, but the worker's CLOSE command has not arrived.
    // Keep the session reserved so its late onClose cannot be redirected to a reused descriptor.
    uint8_t close_waiting_worker;
    // Owner reactor: the worker's close command has arrived; duplicate commands are harmless.
    uint8_t close_worker_received;
    // Owner reactor: independent reasons why receiving is disabled.
    uint8_t recv_paused;
    // Owner reactor: configured delayed receive has not been explicitly resumed.
    uint8_t recv_delayed;
    uint8_t recv_throttled;
    uint8_t recv_shutdown;
    // Worker protect(), background heartbeat snapshots and reactor idle checks hold the slot lock.
    uint8_t protect;
    ReactorId reactor_id;
    // Shared protocol state: worker handshake/close code and reactor parsing both access it.
    // Values are ordered protocol states, not flags. HANDSHAKE_FAILED sorts above ACTIVE;
    // an ordinal threshold must not be substituted for an exact ACTIVE check.
    uint8_t websocket_status;
    // Owner transport error snapshot exposed to workers; independent of the first close cause.
    uint16_t close_errno;
    uint16_t waiting_time;
    uint16_t local_port;
    uint16_t local_addr_index;
    // PROCESS has concurrent producer/consumer writes: reactor adds dispatched payload and worker
    // subtracts consumption, so even an approximate flow-control count needs atomic RMW there.
    // BASE/THREAD account synchronously on the owner reactor through the compile-time policy.
    sw_atomic_t recv_queued_bytes;
    uint32_t send_queued_bytes;
    /**
     * bind uid
     */
    uint32_t uid;
    /**
     * Socket lifetime and dereferences belong to its owner reactor (BASE worker / PROCESS reactor /
     * THREAD event worker). A shared Connection pointer does not grant workers ownership of this pointer.
     */
    network::Socket *socket;
    // Owner protocol parser's native HTTP/Redis object. In PROCESS this points into master
    // memory; worker callbacks must use dispatched request data rather than dereference it.
    void *object;
    // Owner-reactor backpressure timer. Cancel it before retiring the Socket so a delayed retry
    // cannot re-register input for a closed session or dereference a freed Socket.
    TimerNode *timer;
    /**
     * connect/send/dispatch time
     */
    double connect_time;
    double last_send_time;
    double last_dispatch_time;
    // Owner WebSocket fragment assembly. Physical close frees it; dispatching a frame never
    // transfers ownership of this native buffer to application callbacks or another process.
    String *websocket_buffer;

    // Certificate objects are worker-private. Pair pointer access with ssl_client_cert_pid and
    // the slot lock; another process must not dereference the pointer even if it is non-null.
    String *ssl_client_cert;
    pid_t ssl_client_cert_pid;
    // Peer address copied before publication. Query snapshots do not need Socket ownership;
    // cross-role callers still validate the session under the slot lock before copying it.
    network::Address info;
    // Preserved across reuse. Serializes worker generation checks/callback claims with owner
    // initialization/retirement. Never hold across PHP, cancellation, destructors or IPC.
    // If the server bounds mutex is also needed, acquire the bounds mutex first.
    sw_atomic_t lock;
    // Shared atomic: workers and the reactor can race to publish the first close cause. Worker
    // writers hold lock, but reactor writers do not all hold it, so the CAS remains necessary.
    sw_atomic_t close_reason;
    // Worker sets DISPATCHING before calling onClose and DISPATCHED after its native dispatch
    // returns. Protected by the slot lock; completion does not wait for a yielded PHP coroutine.
    CloseCallbackState close_callback_state;
    // Outside the reset prefix: heartbeat may sample this even while the slot is inactive.
    // Preserve the old value until the reactor stores the new session's actual receive time.
    double last_recv_time;
    int server_fd;
    // Owner retires under the slot lock before freeing transport resources. Preserve this fact
    // until the next publication so late worker events reject the old generation under that lock.
    bool session_released;
    // Worker callback/command claims, all under the slot lock. A close claim also suppresses a
    // late CONNECT event; releasing a failed command claim never releases either callback claim.
    bool connect_callback_claimed;
    // Worker began close processing; queued receive events must no longer enter application code.
    bool close_worker_started;
    // Worker owns submission of CLOSE to the reactor. Cleared only when submission needs retry.
    bool close_worker_claimed;

    // Reactor writes; heartbeat and worker queries read. A relaxed scalar snapshot avoids torn
    // double accesses without publishing any surrounding fields. Use the slot lock for identity.
    double get_last_recv_time() const {
        return sw_atomic_double_load_relaxed(&last_recv_time);
    }

    void set_last_recv_time(double value) {
        sw_atomic_double_store_relaxed(&last_recv_time, value);
    }

    // Read predicate used by reactor and worker validation. Plain connections require no TLS
    // handshake, even though ssl_ready remains zero. Negation means TLS exists but is not ready.
    // This does not perform a handshake, claim ownership, or synchronize the shared ready flag.
    // Callers still validate the session and close policy separately; readiness is not liveness.
    bool is_ssl_ready() const {
        return !ssl || ssl_ready;
    }

    // Exact protocol-state match. In particular, ACTIVE excludes CLOSING and HANDSHAKE_FAILED.
    bool is_websocket_status(websocket::Status status) const {
        return websocket_status == status;
    }

    // Ordinal comparison for existing protocol-routing/API thresholds. CLOSING and
    // HANDSHAKE_FAILED both sort after ACTIVE, so this must retain the caller's exact boundary.
    // It is not a strict "handshake succeeded" predicate and supplies no synchronization.
    bool is_websocket_status_at_least(websocket::Status status) const {
        return websocket_status >= status;
    }

    bool is_websocket_active() const {
        return is_websocket_status(websocket::STATUS_ACTIVE);
    }

    bool is_close_active() const {
        return close_actively;
    }

    bool is_close_reset() const {
        return close_reset;
    }

    // Owner reactor only; worker close flags reach it through the CLOSE command.
    void request_reset() {
        close_reset = true;
    }

    bool is_close_requested() const {
        return sw_atomic_load_acquire(const_cast<sw_atomic_t *>(&close_reason)) !=
               static_cast<uint32_t>(ConnectionCloseReason::NONE);
    }

    // Caller holds the slot lock or runs on the owning reactor.
    bool is_close_worker_started() const {
        return close_worker_started;
    }

    bool is_close_worker_claimed() const {
        return close_worker_claimed;
    }

    bool is_close_aborting() const {
        return close_abort;
    }

    bool is_session_released() const {
        return session_released;
    }

    // Caller holds the slot lock; a successful lookup alone does not pin the session generation.
    bool is_current_session(SessionId expected_session) const {
        return active && session_id == expected_session && !is_session_released();
    }

    // The existing factory/receive entry point fixes the mode at compile time. C++14 folds
    // this constant condition; no runtime mode argument or extra indirect call is needed.
    template <ReceiveQueueMode Mode>
    void add_recv_queued_bytes(uint32_t length) {
        if (Mode == ReceiveQueueMode::SHARED_PROCESS) {
            sw_atomic_fetch_add(&recv_queued_bytes, length);
        } else {
            recv_queued_bytes += length;
        }
    }

    template <ReceiveQueueMode Mode>
    void subtract_recv_queued_bytes(uint32_t length) {
        if (Mode == ReceiveQueueMode::SHARED_PROCESS) {
            sw_atomic_fetch_sub(&recv_queued_bytes, length);
        } else {
            recv_queued_bytes -= length;
        }
    }

    // Scalar queue snapshot, not a liveness/generation check. PROCESS must atomically read the
    // shared producer/consumer value; cross-role callers separately validate their session.
    uint32_t get_recv_queued_bytes() const {
        return sw_atomic_load_acquire(const_cast<sw_atomic_t *>(&recv_queued_bytes));
    }

    // BASE/THREAD execute receive accounting synchronously on the owning reactor. PROCESS callers
    // use prepare_receive_event() below because a different process may retire/reinitialize this slot.
    ReceiveEventStatus prepare_receive_event_on_reactor(SessionId expected_session,
                                                        uint32_t length,
                                                        double dispatch_time) {
        return prepare_receive_event_impl<ReceiveQueueMode::OWNER_REACTOR>(expected_session, length, dispatch_time);
    }

    ReceiveEventStatus prepare_receive_event(SessionId expected_session, uint32_t length, double dispatch_time) {
        sw_spinlock(&lock);
        const auto status =
            prepare_receive_event_impl<ReceiveQueueMode::SHARED_PROCESS>(expected_session, length, dispatch_time);
        sw_spinlock_release(&lock);
        return status;
    }

  private:
    template <ReceiveQueueMode Mode>
    ReceiveEventStatus prepare_receive_event_impl(SessionId expected_session, uint32_t length, double dispatch_time) {
        if (session_id != expected_session) {
            return ReceiveEventStatus::STALE;
        }
        if (session_released) {
            return ReceiveEventStatus::CLOSED;
        }
        if (!active || !is_ssl_ready()) {
            return ReceiveEventStatus::STALE;
        }
        if (length > 0) {
            subtract_recv_queued_bytes<Mode>(length);
        }
        last_dispatch_time = dispatch_time;
        return close_worker_started ? ReceiveEventStatus::CLOSED : ReceiveEventStatus::READY;
    }

  public:
    // Reactor or worker may report the first close cause concurrently. Preserve the winner;
    // later abort/RST escalation is separate owner policy and must not overwrite this cause.
    void begin_close(ConnectionCloseReason reason) {
        sw_atomic_cmp_set(&close_reason, 0, static_cast<uint32_t>(reason));
    }

    bool is_close_callback_dispatching() const {
        return close_callback_state == CloseCallbackState::DISPATCHING;
    }

    // Worker after native onClose dispatch. The callback may have reentered close or allowed fd
    // reuse; update only the generation that originally claimed this callback.
    void finish_close_callback(SessionId expected_session) {
        sw_spinlock(&lock);
        if (is_current_session(expected_session) && close_callback_state == CloseCallbackState::DISPATCHING) {
            close_callback_state = CloseCallbackState::DISPATCHED;
        }
        sw_spinlock_release(&lock);
    }

    // Worker after failed CLOSE submission. Permit a command retry while retaining the facts
    // that close processing and callback dispatch already started; retries cannot replay onClose.
    void release_close_worker(SessionId expected_session) {
        sw_spinlock(&lock);
        if (is_current_session(expected_session)) {
            close_worker_claimed = false;
        }
        sw_spinlock_release(&lock);
    }

    // Owner-reactor policy only. Socket::removed says whether it is registered, not why READ
    // stopped. Application pause, delayed receive, backpressure and shutdown remain independent.
    bool can_receive() const {
        return !is_close_requested() && !recv_paused && !recv_delayed && !recv_throttled && !recv_shutdown;
    }
};

// Snapshot data consumed by the PHP wrapper without exposing Connection internals.
struct ClientInfoSnapshot {
    SessionId session_id = 0;
    swSocketFd server_fd = 0;
    swSocketFd socket_fd = 0;
    SocketType socket_type = SW_SOCK_TCP;
    ReactorId reactor_id = 0;
    int worker_id = 0;
    uint32_t uid = 0;
    uint8_t websocket_status = 0;
    int close_errno = 0;
    // A copied value owned by the caller, never a shared counter.
    uint32_t recv_queued_bytes = 0;
    uint32_t send_queued_bytes = 0;
    double connect_time = 0;
    double last_recv_time = 0;
    double last_send_time = 0;
    double last_dispatch_time = 0;
    uint16_t remote_port = 0;
    uint16_t server_port = 0;
    std::string remote_ip;
    std::string ssl_client_cert;
    bool has_server_port = false;
    bool has_ssl_client_cert = false;
};

//------------------------------------ReactorThread-------------------------------------------
// Transport data for an unpublished socket. Server owns the accept/handoff/adoption lifecycle;
// all rejected or discarded sockets go through abort_connection(), never a second socket deleter.
struct IncomingConnection {
    // Exclusive unpublished transport: successful handoff relinquishes the producer's access.
    network::Socket *socket;
    // Server-lifetime listener metadata, valid throughout handoff/adoption.
    ListenPort *port;
    // Listener identity serialized in the small IPC header; not the accepted session id.
    int server_fd;

    IncomingConnection(network::Socket *sock, ListenPort *listen_port, int listen_fd)
        : socket(sock), port(listen_port), server_fd(listen_fd) {}
};

struct ReactorThread {
    int id;
    std::thread thread;
    network::Socket *notify_pipe = nullptr;
    uint64_t dispatch_count = 0;
    network::Socket *pipe_command = nullptr;
    TimerNode *heartbeat_timer = nullptr;
    // PROCESS: heartbeat sends per-session force-close requests; only the owner reactor reads them.
    // Keep both endpoints alive until the heartbeat and reactor threads have joined.
    std::unique_ptr<SocketPair> heartbeat_pipe;
    MessageBus message_bus;

    int init(Server *serv, Reactor *reactor, uint16_t reactor_id);
    void shutdown(Reactor *reactor);
    int close_connection(Reactor *reactor,
                         SessionId session_id,
                         ConnectionCloseReason reason = ConnectionCloseReason::SERVER_ERROR);
    void drain_pipe_buffers(Server *serv, int timeout_msec);
    void discard_pipe_buffers(const Server *serv);
    void clean();
};

struct ServerPortGS {
    sw_atomic_t connection_num;
    sw_atomic_t *connection_nums = nullptr;
    sw_atomic_long_t abort_count;
    sw_atomic_long_t accept_count;
    sw_atomic_long_t close_count;
    sw_atomic_long_t dispatch_count;
    sw_atomic_long_t request_count;
    sw_atomic_long_t response_count;
    sw_atomic_long_t total_recv_bytes;
    sw_atomic_long_t total_send_bytes;
};

struct ListenPort {
    uint16_t object_id;
    /**
     * tcp socket listen backlog
     */
    uint16_t backlog = SW_BACKLOG;
    bool listening = false;
    /**
     * open tcp_defer_accept option
     */
    int tcp_defer_accept = 0;
    /**
     * TCP_FASTOPEN
     */
    int tcp_fastopen = 0;
    /**
     * TCP KeepAlive
     */
    int tcp_keepidle = SW_TCP_KEEPIDLE;
    int tcp_keepinterval = SW_TCP_KEEPINTERVAL;
    int tcp_keepcount = SW_TCP_KEEPCOUNT;

    int tcp_user_timeout = 0;

    double max_idle_time = 0;

    int socket_buffer_size = network::Socket::default_buffer_size;
    uint32_t buffer_high_watermark = 0;
    uint32_t buffer_low_watermark = 0;

    SocketType type = SW_SOCK_TCP;
    uint8_t ssl = 0;
    std::string host;
    int port = 0;
    network::Socket *socket = nullptr;
    pthread_t thread_id = 0;

    uint16_t heartbeat_idle_time = 0;

    /**
     * check data eof
     */
    bool open_eof_check = false;
    /**
     * built-in http protocol
     */
    bool open_http_protocol = false;
    /**
     * built-in http2.0 protocol
     */
    bool open_http2_protocol = false;
    /**
     * built-in websocket protocol
     */
    bool open_websocket_protocol = false;
    /**
     * Relevant settings of websocket server
     */
    WebSocketSettings websocket_settings = {};
    /**
     *  one package: length check
     */
    bool open_length_check = false;
    /**
     * for mqtt protocol
     */
    bool open_mqtt_protocol = false;
    /**
     *  redis protocol
     */
    bool open_redis_protocol = false;
    /**
     * open tcp nodelay option
     */
    bool open_tcp_nodelay = false;
    /**
     * open tcp nopush option(for sendfile)
     */
    bool open_tcp_nopush = true;
    /**
     * open tcp keepalive
     */
    bool open_tcp_keepalive = false;
    /**
     * set socket option
     */
    int kernel_socket_recv_buffer_size = 0;
    int kernel_socket_send_buffer_size = 0;

    std::shared_ptr<SSLContext> ssl_context = nullptr;
    std::unordered_map<std::string, std::shared_ptr<SSLContext>> sni_contexts;

#ifdef SW_SUPPORT_DTLS
    std::unordered_map<int, dtls::Session *> *dtls_sessions = nullptr;
    mutable std::mutex dtls_sessions_mutex;
    dtls::Session *create_dtls_session(network::Socket *sock) const;
    dtls::Session *get_dtls_session(int fd) const;
    void remove_dtls_session(int fd) const;
#endif

    bool ssl_is_enable() const {
        return get_ssl_context() != nullptr;
    }

    SSLContext *get_ssl_context() const {
        return ssl_context.get();
    }

    std::shared_ptr<SSLContext> dup_ssl_context() const {
        auto new_ctx = std::make_shared<SSLContext>();
        *new_ctx = *ssl_context;
        // The SNI context creates and owns its own SSL_CTX.
        new_ctx->context = nullptr;
        return new_ctx;
    }

    ServerPortGS *gs = nullptr;

    Protocol protocol = {};
    void *ptr = nullptr;

    int (*onRead)(Reactor *reactor, ListenPort *port, Event *event) = nullptr;

    bool is_dgram() const {
        return network::Socket::is_dgram(type);
    }

    bool is_dtls() const {
#ifdef SW_SUPPORT_DTLS
        return ssl_context && (ssl_context->protocols & SW_SSL_DTLS);
#else
        return false;
#endif
    }

    bool is_stream() const {
        return network::Socket::is_stream(type);
    }

    void set_eof_protocol(const std::string &eof, bool find_from_right = false);
    void set_length_protocol(uint32_t length_offset, char length_type, uint32_t body_offset);
    void set_stream_protocol();

    void set_package_max_length(uint32_t max_length) {
        protocol.package_max_length = max_length;
    }

    explicit ListenPort(Server *server);
    ~ListenPort();
    int listen();
    void close();
    bool import(int sock);
    void init_protocol();
    const char *get_protocols() const;
    int create_socket();
    void close_socket();
    void destroy_http_request(Connection *conn);

    static int readable_callback_raw(Reactor *reactor, ListenPort *lp, Event *event);
    static int readable_callback_length(Reactor *reactor, ListenPort *lp, Event *event);
    static int readable_callback_eof(Reactor *reactor, ListenPort *lp, Event *event);
    static int readable_callback_http(Reactor *reactor, ListenPort *lp, Event *event);
    static int readable_callback_redis(Reactor *reactor, ListenPort *lp, Event *event);

    bool ssl_context_init();
    bool ssl_context_create(SSLContext *context, bool allow_empty_cert) const;
    bool ssl_create(network::Socket *sock);
    bool ssl_add_sni_cert(const std::string &name, const std::shared_ptr<SSLContext> &ctx);
    static bool ssl_matches_wildcard_name(const char *subject_name, const char *cert_name);
    bool ssl_init() const;

    bool set_ssl_key_file(const std::string &file) const {
        return ssl_context->set_key_file(file);
    }

    bool set_ssl_cert_file(const std::string &file) const {
        return ssl_context->set_cert_file(file);
    }

    void set_ssl_cafile(const std::string &file) const {
        ssl_context->cafile = file;
    }

    bool set_ssl_client_cert_file(const std::string &file) const {
        return ssl_context->set_client_cert_file(file);
    }

    void set_ssl_capath(const std::string &path) const {
        ssl_context->capath = path;
    }

    void set_ssl_passphrase(const std::string &str) const {
        ssl_context->passphrase = str;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    void set_tls_host_name(const std::string &str) const {
        ssl_context->tls_host_name = str;
        // if user set empty ssl_host_name, disable it, otherwise the underlying may set it automatically
        ssl_context->disable_tls_host_name = ssl_context->tls_host_name.empty();
    }
#endif

    void set_ssl_dhparam(const std::string &file) const {
        ssl_context->dhparam = file;
    }

    void set_ssl_ecdh_curve(const std::string &str) const {
        ssl_context->ecdh_curve = str;
    }

    void set_ssl_protocols(long protocols) const {
        if (protocols & SW_SSL_DTLS) {
#ifndef SW_SUPPORT_DTLS
            protocols ^= SW_SSL_DTLS;
#else
            if (is_dgram()) {
                protocols ^= SW_SSL_DTLS;
            }
#endif
        }
        ssl_context->protocols = protocols;
    }

    void set_ssl_disable_compress(bool value) const {
        ssl_context->disable_compress = value;
    }

    void set_ssl_verify_peer(bool value) const {
        ssl_context->verify_peer = value;
    }

    void set_ssl_allow_self_signed(bool value) const {
        ssl_context->allow_self_signed = value;
    }

    void set_ssl_verify_depth(uint8_t value) const {
        ssl_context->verify_depth = value;
    }

    void set_ssl_ciphers(const std::string &str) const {
        ssl_context->ciphers = str;
    }

    void set_ssl_prefer_server_ciphers(bool value) const {
        ssl_context->prefer_server_ciphers = value;
    }

#ifdef OPENSSL_IS_BORINGSSL
    void set_ssl_grease(uint8_t value) {
        ssl_context->grease = value;
    }
#endif

    const std::string &get_ssl_cert_file() const {
        return ssl_context->cert_file;
    }

    const std::string &get_ssl_key_file() const {
        return ssl_context->key_file;
    }

    const std::string &get_ssl_client_cert_file() const {
        return ssl_context->client_cert_file;
    }

    const std::string &get_ssl_capath() const {
        return ssl_context->capath;
    }

    const std::string &get_ssl_cafile() const {
        return ssl_context->cafile;
    }

    bool get_ssl_verify_peer() const {
        return ssl_context->verify_peer;
    }

    bool get_ssl_allow_self_signed() const {
        return ssl_context->allow_self_signed;
    }

    uint32_t get_ssl_protocols() const {
        return ssl_context->protocols;
    }

    bool has_sni_contexts() const {
        return !sni_contexts.empty();
    }

    static int ssl_server_sni_callback(SSL *ssl, int *al, void *arg);
    void clear_protocol();

    network::Socket *get_socket() const {
        return socket;
    }

    int get_port() const {
        return port;
    }

    const char *get_host() const {
        return host.c_str();
    }

    SocketType get_type() const {
        return type;
    }

    int get_fd() const {
        return socket ? socket->fd : -1;
    }

    size_t get_connection_num() const;
};

struct ServerGS {
    pid_t master_pid;
    pid_t manager_pid;

    SessionId session_round;
    sw_atomic_t start;
    sw_atomic_t shutdown;

    int max_fd;
    int min_fd;

    bool onstart_called;
    time_t start_time;
    sw_atomic_t connection_num;
    sw_atomic_t *connection_nums = nullptr;
    sw_atomic_t tasking_num;
    uint32_t max_concurrency;
    sw_atomic_t concurrency;
    sw_atomic_long_t abort_count;
    sw_atomic_long_t accept_count;
    sw_atomic_long_t close_count;
    sw_atomic_long_t dispatch_count;
    sw_atomic_long_t request_count;
    sw_atomic_long_t response_count;
    sw_atomic_long_t total_recv_bytes;
    sw_atomic_long_t total_send_bytes;
    sw_atomic_long_t pipe_packet_msg_id;
    sw_atomic_long_t task_count;

    sw_atomic_t spinlock;

    Barrier manager_barrier;

    ProcessPool task_workers;
    ProcessPool event_workers;
};

class Factory {
  protected:
    Server *server_;

  public:
    explicit Factory(Server *_server) {
        server_ = _server;
    }
#ifndef _WIN32
    pid_t spawn_event_worker(Worker *worker) const;
    pid_t spawn_user_worker(Worker *worker) const;
    pid_t spawn_task_worker(Worker *worker) const;
    void kill_user_workers() const;
    void kill_event_workers() const;
    void kill_task_workers() const;
#endif
    void check_worker_exit_status(Worker *worker, const ExitStatus &exit_status) const;
    virtual ~Factory() = default;
    virtual bool start() = 0;
    virtual bool shutdown() = 0;
    virtual bool dispatch(SendData *) = 0;
    virtual bool finish(SendData *) = 0;
    virtual bool notify(DataHead *) = 0;
    virtual bool end(SessionId session_id, int flags) = 0;
};

class BaseFactory : public Factory {
  public:
    explicit BaseFactory(Server *server);
    ~BaseFactory() override;
    bool start() override;
    bool shutdown() override;
    bool dispatch(SendData *) override;
    bool finish(SendData *) override;
    bool notify(DataHead *) override;
    bool end(SessionId session_id, int flags) override;
    bool forward_message(const Session *session, SendData *data) const;
};

#ifndef _WIN32
class ProcessFactory : public Factory {
  public:
    explicit ProcessFactory(Server *server);
    ~ProcessFactory() override;
    bool start() override;
    bool shutdown() override;
    bool dispatch(SendData *) override;
    bool finish(SendData *) override;
    bool notify(DataHead *) override;
    bool end(SessionId session_id, int flags) override;
};
#endif

struct ThreadReloadTask {
    Server *server_;
    uint16_t start_worker_id;
    uint16_t worker_num;
    uint16_t next_worker_id;
    std::unordered_set<WorkerId> completed_workers;

    bool is_completed() const {
        return completed_workers.size() == worker_num;
    }

    bool has_next() const {
        return next_worker_id < start_worker_id + worker_num;
    }

    bool contains(WorkerId worker_id) const {
        return worker_id >= start_worker_id && worker_id < start_worker_id + worker_num;
    }

    bool mark_completed(WorkerId worker_id) {
        return contains(worker_id) && completed_workers.emplace(worker_id).second;
    }

    ThreadReloadTask(Server *_server, bool _reload_all_workers);
    ~ThreadReloadTask() = default;
};

class ThreadFactory : public BaseFactory {
    std::vector<std::shared_ptr<Thread>> threads_;
    std::mutex lock_;
    std::condition_variable cv_;
    std::queue<Worker *> queue_;
    bool reload_all_workers = false;
    sw_atomic_t reloading = 0;
    std::shared_ptr<ThreadReloadTask> reload_task;
    void at_thread_enter(WorkerId id, int process_type);
    void at_thread_exit(Worker *worker);
    void create_message_bus() const;
    void destroy_message_bus();
    void do_reload();
    void finish_reload_worker(Worker *worker);
    void push_to_wait_queue(Worker *worker);

  public:
    explicit ThreadFactory(Server *server);
    ~ThreadFactory() override;
    WorkerId get_manager_thread_id() const;
    WorkerId get_master_thread_id() const;
    void spawn_event_worker(WorkerId i);
    void spawn_task_worker(WorkerId i);
    void spawn_user_worker(WorkerId i);
    void spawn_manager_thread(WorkerId i);
    void terminate_manager_thread();
    void wait();
    bool reload(bool reload_all_workers);
    bool start() override;
    bool shutdown() override;
};

enum ServerEventType {
    // recv data payload
    SW_SERVER_EVENT_RECV_DATA,
    SW_SERVER_EVENT_RECV_DGRAM,
    // send data
    SW_SERVER_EVENT_SEND_DATA,
    SW_SERVER_EVENT_SEND_FILE,
    // connection event
    SW_SERVER_EVENT_CLOSE,
    SW_SERVER_EVENT_CONNECT,
    SW_SERVER_EVENT_CLOSE_FORCE,
    SW_SERVER_EVENT_CLOSE_FORWARD,
    // task
    SW_SERVER_EVENT_TASK,
    SW_SERVER_EVENT_FINISH,
    // pipe
    SW_SERVER_EVENT_PIPE_MESSAGE,
    // event operate
    SW_SERVER_EVENT_PAUSE_RECV,
    SW_SERVER_EVENT_RESUME_RECV,
    // buffer event
    SW_SERVER_EVENT_BUFFER_FULL,
    SW_SERVER_EVENT_BUFFER_EMPTY,
    // process message
    SW_SERVER_EVENT_INCOMING,
    SW_SERVER_EVENT_SHUTDOWN,
    SW_SERVER_EVENT_COMMAND_REQUEST,
    SW_SERVER_EVENT_COMMAND_RESPONSE,
    SW_SERVER_EVENT_SHUTDOWN_SIGNAL,
};

// Carried in DataHead::ext_flags of a SW_SERVER_EVENT_SEND_FILE event: the event owns the file
// and must delete it once the native transfer terminates.
enum ServerSendfileFlag {
    SW_SERVER_SENDFILE_DELETE = 1u << 0,
};

class Server {
  public:
    typedef int (*DispatchFunction)(Server *, Connection *, SendData *);

    struct Command {
        typedef std::function<void(Server *, const std::string &msg)> Callback;
        typedef std::function<std::string(Server *, const std::string &msg)> Handler;
        enum ProcessType {
            MASTER = 1u << 1,
            REACTOR_THREAD = 1u << 2,
            EVENT_WORKER = 1u << 3,
            TASK_WORKER = 1u << 4,
            MANAGER = 1u << 5,
            ALL_PROCESS = MASTER | REACTOR_THREAD | EVENT_WORKER | TASK_WORKER | MANAGER,
        };
        int id;
        int accepted_process_types;
        std::string name;
    };

    struct MultiTask {
        uint16_t count;
        std::unordered_map<TaskId, uint16_t> map;

        std::function<TaskId(uint16_t index, EventData *buf)> pack;
        std::function<void(uint16_t index, EventData *result)> unpack;
        std::function<void(uint16_t index)> fail;

        explicit MultiTask(uint16_t n) : count(n) {
            map.reserve(n);
        }

        int find(TaskId task_id) const;
        bool unpack_results(const char *data, size_t length) const;
    };

    enum Mode {
        MODE_BASE = 1,
#ifndef _WIN32
        MODE_PROCESS = 2,
#endif
        MODE_THREAD = 3,
    };

    enum TaskIpcMode {
#ifndef _WIN32
        TASK_IPC_UNIXSOCK = 1,
        TASK_IPC_MSGQUEUE = 2,
        TASK_IPC_PREEMPTIVE = 3,
#endif
        TASK_IPC_STREAM = 4,
    };

    enum ThreadType {
        THREAD_NORMAL = 0,
        THREAD_MASTER = 1,
        THREAD_REACTOR = 2,
        THREAD_HEARTBEAT = 3,
        THREAD_WORKER = 4,
    };

    enum DispatchMode {
        DISPATCH_ROUND = 1,
        DISPATCH_FDMOD = 2,
        DISPATCH_IDLE_WORKER = 3,
        DISPATCH_IPMOD = 4,
        DISPATCH_UIDMOD = 5,
        DISPATCH_USERFUNC = 6,
        DISPATCH_CO_CONN_LB = 8,
        DISPATCH_CO_REQ_LB = 9,
        DISPATCH_CONCURRENT_LB = 10,
    };

    enum FactoryDispatchResult {
        DISPATCH_RESULT_DISCARD_PACKET = -1,
        DISPATCH_RESULT_CLOSE_CONNECTION = -2,
        DISPATCH_RESULT_USERFUNC_FALLBACK = -3,
    };

    // deprecated, will be removed in the next minor version
    enum HookType {
        HOOK_MASTER_START,
        HOOK_MASTER_TIMER,
        HOOK_REACTOR_START,
        HOOK_WORKER_START,
        HOOK_TASK_WORKER_START,
        HOOK_MASTER_CONNECT,
        HOOK_REACTOR_CONNECT,
        HOOK_WORKER_CONNECT,
        HOOK_REACTOR_RECEIVE,
        HOOK_WORKER_RECEIVE,
        HOOK_REACTOR_CLOSE,
        HOOK_WORKER_CLOSE,
        HOOK_MANAGER_START,
        HOOK_MANAGER_TIMER,
        HOOK_PROCESS_TIMER,
        HOOK_END = SW_MAX_HOOK_TYPE - 1,
    };

    enum CloseFlag {
        CLOSE_RESET = 1u << 1,
        CLOSE_ACTIVELY = 1u << 2,
        // Internal policy: discard pending output without requesting a TCP reset.
        CLOSE_ABORT = 1u << 3,
    };

    // onClose callback context, captured under the slot lock before the transport can retire.
    // These bits belong to callback DataHead only, not CLOSE commands sent to a reactor.
    enum CloseCallbackFlag {
        CLOSE_CALLBACK_WEBSOCKET = 1u << 0,
        CLOSE_CALLBACK_HTTP2 = 1u << 1,
    };

    /**
     * reactor thread/process num
     */
    uint16_t reactor_num = 0;
    /**
     * worker process num
     */
    uint32_t worker_num = 0;

    uint8_t dgram_port_num = 0;

    /**
     * package dispatch mode
     */
    uint8_t dispatch_mode = DISPATCH_FDMOD;

    /**
     * No idle work process is available.
     */
    bool scheduler_warning = false;

    int worker_uid = 0;
    int worker_groupid = 0;

    /**
     * worker process max request
     */
    uint32_t max_request = 0;
    uint32_t max_request_grace = 0;

    network::Socket *udp_socket_ipv4 = nullptr;
    network::Socket *udp_socket_ipv6 = nullptr;
    network::Socket *dgram_socket = nullptr;

    uint32_t max_wait_time = SW_WORKER_MAX_WAIT_TIME;
    uint32_t worker_max_concurrency = UINT_MAX;

    /*----------------------------Reactor schedule--------------------------------*/
    sw_atomic_t worker_round_id = 0;

    /**
     * worker(worker and task_worker) process chroot / user / group
     */
    std::string chroot_;
    std::string user_;
    std::string group_;

    /**
     * run as a daemon process
     */
    bool daemonize = false;
    /**
     * have dgram socket
     */
    bool have_dgram_sock = false;
    /**
     * have stream socket
     */
    bool have_stream_sock = false;
    /**
     * open cpu affinity setting
     */
    bool open_cpu_affinity = false;
    /**
     * disable notice when use SW_DISPATCH_ROUND and SW_DISPATCH_QUEUE
     */
    bool disable_notify = false;
    /**
     * discard the timeout request
     */
    bool discard_timeout_request = false;
    /**
     * parse cookie header
     */
    bool http_parse_cookie = true;
    /**
     * parse x-www-form-urlencoded data
     */
    bool http_parse_post = true;
    /**
     * parse multipart/form-data files to match $_FILES
     */
    bool http_parse_files = false;
    /**
     * http content compression
     */
    bool http_compression = false;
    /**
     * RFC-7692
     */
    bool websocket_compression = false;
    /**
     * handle static files
     */
    bool enable_static_handler = false;
    /**
     * show file list in the current directory
     */
    bool http_autoindex = false;
    /**
     * enable onConnect/onClose event when use dispatch_mode=1/3
     */
    bool enable_unsafe_event = false;
    /**
     * waiting for worker onConnect callback function to return
     */
    bool enable_delay_receive = false;
    /**
     * reuse port
     */
    bool enable_reuse_port = false;
    /**
     * asynchronous reloading
     */
    bool reload_async = true;
    /**
     * use event object
     */
    bool event_object = false;
    /**
     * use task object
     */
    bool task_object = false;
    /**
     * enable coroutine in task worker
     */
    bool task_enable_coroutine = false;
    /**
     * yield coroutine when the output buffer is full
     */
    bool send_yield = true;
    /**
     * enable coroutine
     */
    bool enable_coroutine = true;
    /**
     * disable multi-threads
     */
    bool single_thread = false;
    /**
     * server status
     */
    bool running = true;

    int *cpu_affinity_available = nullptr;
    int cpu_affinity_available_num = 0;

#ifndef _WIN32
    UnixSocket *pipe_command = nullptr;
#endif
    MessageBus message_bus;

    double send_timeout = 0;

    uint16_t heartbeat_check_interval = 0;

    time_t reload_time = 0;
    time_t warning_time = 0;
    long timezone_ = 0;
    TimerNode *master_timer = nullptr;
    TimerNode *heartbeat_timer = nullptr;

    /* buffer output/input setting*/
    uint32_t output_buffer_size = UINT_MAX;
    uint32_t input_buffer_size = SW_INPUT_BUFFER_SIZE;
    uint32_t max_queued_bytes = 0;

    /**
     * the master process and worker process communicate using unix socket dgram.
     * ipc_max_size represents the maximum size of each datagram,
     * which is obtained from the kernel send buffer of unix socket in swServer_set_ipc_max_size function.
     */
    uint32_t ipc_max_size = SW_IPC_MAX_SIZE;

    void *private_data_1 = nullptr;
    void *private_data_2 = nullptr;
    void *private_data_3 = nullptr;
    void *private_data_4 = nullptr;

    Factory *factory_ = nullptr;
#ifndef _WIN32
    Manager *manager_ = nullptr;
#endif

    std::vector<ListenPort *> ports;
#ifndef _WIN32
    std::vector<std::shared_ptr<UnixSocket>> worker_pipes;
#endif

    ListenPort *get_primary_port() const {
        return ports.front();
    }

    Mode get_mode() const {
        return mode_;
    };

    /**
     * This method can only be used for INET ports and cannot obtain Unix socket ports.
     */
    ListenPort *get_port(int _port) const {
        for (auto port : ports) {
            if (port->port == _port || _port == 0) {
                return port;
            }
        }
        return nullptr;
    }

    ListenPort *get_port(SocketType type, const char *host, int _port) const {
        for (auto port : ports) {
            if (port->port == _port && port->type == type && strcmp(host, port->host.c_str()) == 0) {
                return port;
            }
        }
        return nullptr;
    }

    ListenPort *get_port_by_server_fd(const int server_fd) const {
        return static_cast<ListenPort *>(connection_list[server_fd].object);
    }

    ListenPort *get_port_by_fd(int fd) const {
        return get_port_by_server_fd(connection_list[fd].server_fd);
    }

    ListenPort *get_port_by_session_id(SessionId session_id) const {
        const Connection *conn = get_connection_by_session_id(session_id);
        if (!conn) {
            return nullptr;
        }
        return get_port_by_fd(conn->fd);
    }

    uint32_t get_package_max_length(Connection *conn) {
        return get_port_by_fd(conn->fd)->protocol.package_max_length;
    }

    network::Socket *get_server_socket(int fd) const {
        Connection *conn = get_connection(fd);
        if (sw_unlikely(!conn || conn->fd != fd || !conn->socket)) {
            return nullptr;
        }
        if (sw_unlikely(conn->socket->fd_type != SW_FD_STREAM_SERVER && conn->socket->fd_type != SW_FD_DGRAM_SERVER)) {
            return nullptr;
        }
        return conn->socket;
    }

    network::Socket *get_server_socket(int fd, SocketType expected_type) const {
        network::Socket *socket = get_server_socket(fd);
        if (sw_unlikely(!socket || socket->socket_type != expected_type)) {
            return nullptr;
        }
        return socket;
    }

    network::Socket *get_command_reply_socket() const {
#ifdef _WIN32
        return get_worker(0)->pipe_master;
#else
        return is_base_mode() ? get_worker(0)->pipe_master : pipe_command->get_socket(false);
#endif
    }

    network::Socket *get_worker_pipe_master(WorkerId id) const {
        return get_worker(id)->pipe_master;
    }

    network::Socket *get_worker_pipe_worker(WorkerId id) const {
        return get_worker(id)->pipe_worker;
    }

    network::Socket *get_pipe_socket_in_message_bus(network::Socket *_socket) {
        if (is_thread_mode()) {
            return get_worker_message_bus()->get_pipe_socket(_socket);
        } else {
            return _socket;
        }
    }

    network::Socket *get_worker_pipe_master_in_message_bus(const Worker *worker) {
        return get_pipe_socket_in_message_bus(worker->pipe_master);
    }

    network::Socket *get_worker_pipe_worker_in_message_bus(const Worker *worker) {
        return get_pipe_socket_in_message_bus(worker->pipe_worker);
    }

    network::Socket *get_worker_pipe_master_in_message_bus(WorkerId id) {
        return get_worker_pipe_master_in_message_bus(get_worker(id));
    }

    network::Socket *get_worker_pipe_worker_in_message_bus(WorkerId id) {
        return get_worker_pipe_worker_in_message_bus(get_worker(id));
    }

    /**
     * [Worker|Master]
     */
    network::Socket *get_reactor_pipe_socket(const SessionId session_id, int reactor_id) const {
        const int pipe_index = session_id % reactor_pipe_num;
        /**
         * pipe_worker_id: The pipe in which worker.
         */
        int pipe_worker_id = reactor_id + (pipe_index * reactor_num);
        Worker *worker = get_worker(pipe_worker_id);
        return worker->pipe_worker;
    }

    /**
     *  task process
     */
    uint32_t task_worker_num = 0;
    uint8_t task_ipc_mode =
#ifdef _WIN32
        SW_IPC_SOCKET
#else
        TASK_IPC_UNIXSOCK
#endif
        ;
    uint32_t task_max_request = 0;
    uint32_t task_max_request_grace = 0;
    std::vector<std::shared_ptr<Pipe>> task_notify_pipes;
    EventData *task_results = nullptr;

    /**
     * Used for process management, saving the mapping relationship between PID and worker pointers
     */
    std::unordered_map<pid_t, Worker *> user_worker_map;
    /**
     * When asynchronous restart is enabled, the old worker process will be detached first, and a new worker process
     * will be created immediately. The old process will live and die by itself
     */
    std::unordered_set<pid_t> detached_processes;
    /**
     * Shared memory, sharing state between processes
     */
    Worker *user_workers = nullptr;

    std::unordered_map<std::string, Command> commands;
    std::unordered_map<int, Command::Handler> command_handlers;
    std::unordered_map<int64_t, Command::Callback> command_callbacks;
    int command_current_id = 1;
    int64_t command_current_request_id = 1;

    Worker *workers = nullptr;
    ServerGS *gs = nullptr;

    std::shared_ptr<std::unordered_set<std::string>> locations = nullptr;
    std::shared_ptr<std::vector<std::string>> http_index_files = nullptr;
    std::shared_ptr<std::unordered_set<std::string>> http_compression_types = nullptr;

    Barrier reactor_thread_barrier = {};

    /**
     * temporary directory for HTTP uploaded file.
     */
    std::string upload_tmp_dir = "/tmp";
    /**
     * Write the uploaded file in form-data to disk file
     */
    size_t upload_max_filesize = 0;
    /**
     * http compression level for gzip/br
     */
    uint8_t http_compression_level = 0;
    uint32_t compression_min_length;
    /**
     * master process pid
     */
    std::string pid_file;

    std::queue<String *> *buffer_pool = nullptr;

    const Allocator *recv_buffer_allocator = &SwooleG.std_allocator;
    size_t recv_buffer_size = SW_BUFFER_SIZE_BIG;

    int manager_alarm = 0;

    /**
     * message queue key
     */
    uint64_t message_queue_key = 0;

    void *hooks[SW_MAX_HOOK_TYPE] = {};

    /*----------------------------Event Callback--------------------------------*/
    /**
     * Master Process
     */
    std::function<void(Server *)> onStart;
    std::function<void(Server *)> onBeforeShutdown;
    std::function<void(Server *)> onShutdown;
    /**
     * Manager Process
     */
    std::function<void(Server *)> onManagerStart;
    std::function<void(Server *)> onManagerStop;
    std::function<void(Server *, Worker *, const ExitStatus &)> onWorkerError;
    std::function<void(Server *)> onBeforeReload;
    std::function<void(Server *)> onAfterReload;
    /**
     * Worker Process
     */
    std::function<void(Server *, EventData *)> onPipeMessage;
    std::function<void(Server *, Worker *)> onWorkerStart;
    std::function<void(Server *, Worker *)> onWorkerStop;
    std::function<void(Server *, Worker *)> onWorkerExit;
    std::function<void(Server *, Worker *)> onUserWorkerStart;
    /**
     * Connection
     */
    std::function<int(Server *, RecvData *)> onReceive;
    std::function<int(Server *, RecvData *)> onPacket;
    std::function<void(Server *, DataHead *)> onClose;
    std::function<void(Server *, DataHead *)> onConnect;
    std::function<void(Server *, DataHead *)> onBufferFull;
    std::function<void(Server *, DataHead *)> onBufferEmpty;
    /**
     * Task Worker
     */
    std::function<int(Server *, EventData *)> onTask;
    std::function<int(Server *, EventData *)> onFinish;
    /**
     * Internal callbacks
     */
    // Generate packet IDs for MessageBus.
    std::function<uint64_t(void)> msg_id_generator;
    int (*dispatch_func)(Server *, Connection *, SendData *) = nullptr;
    // Worker-side resource cleanup for CLOSE events received after session retirement.
    // Cleanup is idempotent by session ID.
    std::function<void(Server *, SessionId)> cleanup_connection;

    explicit Server(Mode _mode = MODE_BASE);
    ~Server();

    bool set_document_root(const std::string &path);
    void add_static_handler_location(const std::string &);
    void add_static_handler_index_files(const std::string &);
    bool select_static_handler(const http_server::Request *request, const Connection *conn);
    bool apply_rewrite_rules(http_server::StaticHandler *handler);
    void add_http_compression_type(const std::string &type);
    void add_rewrite_rule(const std::string &pattern, const std::string &replacement);

    int create();
    bool create_worker_pipes();

    int start();
    void destroy();
    bool reload(bool reload_all_workers) const;
    bool shutdown();

    int add_worker(Worker *worker);
    ListenPort *add_port(SocketType type, const char *host, int port);
    int add_systemd_socket();
    void add_hook(enum HookType type, const Callback &func, int push_back);
    bool add_command(const std::string &command, int accepted_process_types, const Command::Handler &func);
    Connection *add_connection(const ListenPort *ls, network::Socket *_socket, int server_fd);
    bool dispatch_connection(Reactor *reactor, network::Socket *socket, ListenPort *port, int server_fd);
    bool initialize_connection(Reactor *reactor, IncomingConnection incoming);
    bool handoff_connection(IncomingConnection incoming);
    void discard_reactor_event(EventData *event) const;
    void discard_reactor_output(MessageBus &bus) const;
    void discard_incoming_connections() const;
    const char *get_local_addr(Connection *conn);
    const char *get_remote_addr(Connection *conn);
    void abort_connection(Reactor *reactor, const ListenPort *ls, network::Socket *_socket) const;
    void abort_worker(Worker *worker) const;
    void reset_worker_counter(Worker *worker) const;
    int connection_incoming(Reactor *reactor, Connection *conn) const;

    uint32_t get_idle_worker_num() const;
    int get_idle_task_worker_num() const;
    int get_tasking_num() const;

    TaskId get_task_id(const EventData *task) const {
        return get_task_worker_pool()->get_task_id(task);
    }

    static uint16_t get_command_id(const EventData *cmd) {
        return cmd->info.server_fd;
    }

    EventData *get_task_result() const {
        return &(task_results[swoole_get_worker_id()]);
    }

    WorkerId get_task_src_worker_id(const EventData *task) const {
        return get_task_worker_pool()->get_task_src_worker_id(task);
    }

    int get_minfd() const {
        return is_base_mode() ? min_fd_ : gs->min_fd;
    }

    int get_maxfd() const {
        return is_base_mode() ? max_fd_ : gs->max_fd;
    }

    void set_maxfd(int maxfd) const {
        if (is_base_mode()) {
            max_fd_ = maxfd;
        } else {
            gs->max_fd = maxfd;
        }
    }

    void set_minfd(int minfd) const {
        if (is_base_mode()) {
            min_fd_ = minfd;
        } else {
            gs->min_fd = minfd;
        }
    }

    pid_t get_master_pid() const {
        return gs->master_pid;
    }

    pid_t get_manager_pid() const {
        return gs->manager_pid;
    }

    pid_t get_worker_pid(WorkerId worker_id) const {
        return get_worker(worker_id)->pid;
    }

    const std::string &get_document_root() {
        return document_root;
    }

    String *get_recv_buffer(network::Socket *_socket) const {
        String *buffer = _socket->recv_buffer;
        if (buffer == nullptr) {
            buffer = new String(SW_BUFFER_SIZE_BIG, recv_buffer_allocator);
            _socket->recv_buffer = buffer;
        }

        return buffer;
    }

    MessageBus *get_worker_message_bus() {
#ifdef SW_THREAD
        return sw_likely(is_thread_mode()) ? SwooleTG.message_bus : &message_bus;
#else
        return &message_bus;
#endif
    }

    uint32_t get_worker_buffer_num() const {
        return is_base_mode() ? 1 : reactor_num + dgram_port_num;
    }

    ProcessPool *get_task_worker_pool() const {
        return &gs->task_workers;
    }

    ProcessPool *get_event_worker_pool() const {
        return &gs->event_workers;
    }

    bool is_support_unsafe_events() const {
        if (is_hash_dispatch_mode()) {
            return true;
        } else {
            return enable_unsafe_event;
        }
    }

    bool is_process_mode() const {
#ifdef _WIN32
        return false;
#else
        return mode_ == MODE_PROCESS;
#endif
    }

    bool is_base_mode() const {
        return mode_ == MODE_BASE;
    }

    bool is_thread_mode() const {
        return mode_ == MODE_THREAD;
    }

    bool is_enable_coroutine() const {
        if (is_task_worker()) {
            return task_enable_coroutine;
        } else if (is_manager()) {
            return false;
        } else {
            return enable_coroutine;
        }
    }

    bool is_master_thread() const {
        return swoole_get_thread_type() == THREAD_MASTER;
    }

    bool is_hash_dispatch_mode() const {
        return dispatch_mode == DISPATCH_FDMOD || dispatch_mode == DISPATCH_IPMOD ||
               dispatch_mode == DISPATCH_CO_CONN_LB;
    }

    bool is_support_send_yield() const {
        return is_hash_dispatch_mode();
    }

    bool if_require_packet_callback(const ListenPort *port, bool isset) const {
        return (port->is_dgram() && !port->ssl && !isset);
    }

    bool if_require_receive_callback(const ListenPort *port, bool isset) const {
        return (((port->is_dgram() && port->ssl) || port->is_stream()) && !isset);
    }

    bool if_forward_message(const Session *session) const {
        return session->reactor_id != swoole_get_worker_id();
    }

    // Caller holds the slot lock and has verified the session generation.
    bool claim_close_callback(Connection *conn) const {
        if (!onClose || conn->close_callback_state != CloseCallbackState::NONE) {
            return false;
        }
        conn->close_callback_state = CloseCallbackState::DISPATCHING;
        return true;
    }

    Worker *get_worker(uint16_t worker_id) const;
    Worker *get_worker_by_pid(pid_t worker_pid) const;
    bool kill_worker(int worker_id);
    void stop_async_worker(Worker *worker);

    Pipe *get_pipe_object(int pipe_fd) const {
        return static_cast<Pipe *>(connection_list[pipe_fd].object);
    }

    size_t get_all_worker_num() const {
        return get_core_worker_num() + get_user_worker_num();
    }

    size_t get_user_worker_num() const {
        return user_worker_list.size();
    }

    size_t get_core_worker_num() const {
        return worker_num + task_worker_num;
    }

    ReactorThread *get_thread(int reactor_id) const {
        return &reactor_threads[reactor_id];
    }

    bool is_started() const {
        return gs->start;
    }

    bool is_created() const {
        return factory_ != nullptr;
    }

    bool is_running() const {
        return running;
    }

    bool is_master() const {
        return swoole_get_worker_type() == SW_MASTER;
    }

    bool is_worker() const {
        return swoole_get_worker_type() == SW_EVENT_WORKER;
    }

    bool is_event_worker() const {
        return is_worker();
    }

    bool is_task_worker() const {
        return swoole_get_worker_type() == SW_TASK_WORKER;
    }

    bool is_manager() const {
        return swoole_get_worker_type() == SW_MANAGER;
    }

    bool is_user_worker() const {
        return swoole_get_worker_type() == SW_USER_WORKER;
    }

    bool is_worker_thread() const {
        return is_thread_mode() && swoole_get_thread_type() == THREAD_WORKER;
    }

    bool is_worker_process() const {
        return !is_thread_mode() && (is_worker() || is_task_worker());
    }

    bool is_reactor_thread() {
        return swoole_get_thread_type() == THREAD_REACTOR;
    }

    bool is_single_worker() const {
        return (worker_num == 1 && task_worker_num == 0 && max_request == 0 && get_user_worker_num() == 0);
    }

    bool isset_hook(HookType type) const {
        assert(type <= HOOK_END);
        return hooks[type];
    }

    bool is_sync_process() const {
        if (is_manager()) {
            return true;
        }
        if (is_task_worker() && !task_enable_coroutine) {
            return true;
        }
        return false;
    }

    bool is_shutdown() const {
        return gs->shutdown;
    }

    // Only accepted sessions publish active. A scan must not dereference another reactor's
    // Socket: its lifetime belongs to that reactor and can end immediately after this check.
    static bool is_valid_connection(const Connection *conn) {
        return conn && conn->active;
    }

    bool is_healthy_connection(double now, const Connection *conn) const;
    std::vector<SessionId> heartbeat(bool close_connection) const;
    bool get_client_info(SessionId session_id, ClientInfoSnapshot &snapshot) const;
    bool get_client_list(SessionId start_session_id, int find_count, std::vector<SessionId> &sessions) const;

    static bool is_dgram_event(uint8_t type) {
        return type == SW_SERVER_EVENT_RECV_DGRAM;
    }

    static bool is_stream_event(uint8_t type) {
        switch (type) {
        case SW_SERVER_EVENT_RECV_DATA:
        case SW_SERVER_EVENT_SEND_DATA:
        case SW_SERVER_EVENT_SEND_FILE:
        case SW_SERVER_EVENT_CONNECT:
        case SW_SERVER_EVENT_CLOSE:
        case SW_SERVER_EVENT_PAUSE_RECV:
        case SW_SERVER_EVENT_RESUME_RECV:
        case SW_SERVER_EVENT_BUFFER_FULL:
        case SW_SERVER_EVENT_BUFFER_EMPTY:
            return true;
        default:
            return false;
        }
    }

    int get_connection_fd(SessionId session_id) const {
        return session_list[session_id % SW_SESSION_LIST_SIZE].fd;
    }

    // Lookup available to master/worker processes and reactor/worker threads. This is only an
    // instantaneous identity check, not a lifetime pin. Worker mutations or multi-field snapshots
    // must take conn->lock and revalidate; only the owner reactor may dereference conn->socket.
    Connection *get_connection_verify_no_ssl(SessionId session_id) const {
        Session *session = get_session(session_id);
        int fd = session->fd;
        Connection *conn = get_connection(fd);
        if (!conn || conn->active == 0) {
            return nullptr;
        }
        if (session->id != session_id || conn->session_id != session_id) {
            return nullptr;
        }
        return conn;
    }

    Connection *get_connection_verify(SessionId session_id) const {
        Connection *conn = get_connection_verify_no_ssl(session_id);
        if (conn && !conn->is_ssl_ready()) {
            return nullptr;
        }
        return conn;
    }

    Connection *get_connection(const int fd) const {
        if (sw_unlikely(static_cast<uint32_t>(fd) >= max_connection)) {
            return nullptr;
        }
        return &connection_list[fd];
    }

    Connection *get_connection_for_iterator(int fd) const {
        Connection *conn = get_connection(fd);
        if (conn && conn->active && !conn->is_close_requested()) {
            if (!conn->is_ssl_ready()) {
                return nullptr;
            }
            return conn;
        }
        return nullptr;
    }

    Connection *get_connection_by_session_id(SessionId session_id) const {
        return get_connection(get_connection_fd(session_id));
    }

    Session *get_session(SessionId session_id) const {
        return &session_list[session_id % SW_SESSION_LIST_SIZE];
    }

    void clear_timer();
    static void timer_callback(Timer *timer, TimerNode *tnode);

    bool create_event_workers();
    bool create_task_workers();
    bool create_user_workers();
#ifndef _WIN32
    int start_manager_process();
#endif

    void call_hook(enum HookType type, void *arg);
    void call_worker_start_callback(Worker *worker);
    void call_worker_stop_callback(Worker *worker);
    void call_worker_error_callback(Worker *worker, const ExitStatus &status);
    void call_command_handler(MessageBus &mb, uint16_t worker_id, network::Socket *sock);
    std::string call_command_handler_in_master(int command_id, const std::string &msg);
    void call_command_callback(int64_t request_id, const std::string &result);
    void foreach_connection(const std::function<void(Connection *)> &callback) const;
    // Owner-reactor traversal. Select fd ownership before accessing mutable Connection/Socket state.
    void foreach_connection_on_reactor(Reactor *reactor, const std::function<void(Connection *)> &callback) const;
    // Background heartbeat traversal. Snapshot candidates under the slot lock, release it before IPC.
    void foreach_idle_connection(double now, const std::function<bool(SessionId, ReactorId)> &callback) const;
    void check_idle_connections(Reactor *reactor) const;
    void close_idle_connection(Reactor *reactor, SessionId session_id) const;
    static int accept_connection(Reactor *reactor, Event *event);
#ifdef SW_SUPPORT_DTLS
    network::Socket *accept_dtls_socket(const ListenPort *ls,
                                        const network::Address *sa,
                                        const char *packet,
                                        size_t length);
#endif
    static int accept_command_result(Reactor *reactor, Event *event);
    static int close_connection(Reactor *reactor, network::Socket *_socket);
    static int dispatch_task(const Protocol *proto, network::Socket *_socket, const RecvData *rdata);
    static void discard_sendfile(DataHead *info, const char *data);

    int send_to_connection(SendData *) const;
    int request_close(Reactor *reactor, Connection *conn, ConnectionCloseReason reason, bool reset = false) const;
    int request_force_close(Reactor *reactor, Connection *conn, ConnectionCloseReason reason) const;
    bool finish_close(SessionId session_id, int flags) const;
    int update_recv_interest(Reactor *reactor, Connection *conn, bool clear_write = false) const;
    ssize_t send_to_worker_from_worker(const Worker *dst_worker, const void *buf, size_t len, int flags);
    bool has_kernel_nobufs_error(SessionId session_id) const;

    ssize_t send_to_worker_from_worker(WorkerId id, const EventData *data, int flags) {
        return send_to_worker_from_worker(get_worker(id), data, data->size(), flags);
    }

    ssize_t send_to_reactor_thread(const EventData *ev_data, size_t sendn, SessionId session_id);

    /**
     * Send data to session.
     * This function is used for sending data to the client in the server.
     * @return true on success, false on failure.
     */
    bool send(SessionId session_id, const void *data, uint32_t length) const;
    /**
     * Send file to session.
     * This function is used for sending files in the HTTP server.
     * It will read the file from disk and send it to the client.
     */
    bool sendfile(SessionId session_id, const char *file, uint32_t l_file, off_t offset, size_t length) const;
    bool sendfile(
        SessionId session_id, const char *file, uint32_t l_file, off_t offset, size_t length, bool &delete_file) const;
    bool sendwait(SessionId session_id, const void *data, uint32_t length) const;
    bool close(SessionId session_id, bool reset = false) const;

    bool notify(Connection *conn, ServerEventType event) const;
    bool feedback(SessionId session_id, ServerEventType event);
    bool command(WorkerId process_id,
                 Command::ProcessType process_type,
                 const std::string &name,
                 const std::string &msg,
                 const Command::Callback &fn);

    bool task(EventData *_task, int *dst_worker_id, bool blocking = false);
    bool finish(const char *data, size_t data_len, int flags = 0, const EventData *current_task = nullptr);
    bool task_sync(EventData *task, int *dst_worker_id, double timeout = -1);
    bool task_sync(MultiTask &mtask, double timeout = -1);
    bool send_pipe_message(WorkerId worker_id, EventData *msg);
    bool send_pipe_message(WorkerId worker_id, const char *data, size_t len);

    void init_reactor(Reactor *reactor);
    void init_event_worker(Worker *worker) const;
    bool init_task_workers();
    void init_signal_handler() const;
    void init_ipc_max_size();
    void init_pipe_sockets(MessageBus *mb) const;

    void set_max_connection(uint32_t _max_connection);

    void set_max_concurrency(uint32_t _max_concurrency) const {
        if (_max_concurrency == 0) {
            _max_concurrency = UINT_MAX;
        }
        gs->max_concurrency = _max_concurrency;
    }

    void set_worker_max_concurrency(uint32_t _max_concurrency) {
        if (_max_concurrency == 0) {
            _max_concurrency = UINT_MAX;
        }
        worker_max_concurrency = _max_concurrency;
    }

    uint32_t get_max_connection() const {
        return max_connection;
    }

    uint32_t get_max_concurrency() const {
        return gs->max_concurrency;
    }

    uint32_t get_concurrency() const {
        return gs->concurrency;
    }

    bool is_unavailable() const {
        return get_concurrency() >= get_max_concurrency();
    }

    uint32_t get_worker_max_concurrency() const {
        return worker_max_concurrency;
    }

    void set_start_session_id(SessionId value) const {
        if (value > UINT_MAX) {
            value = UINT_MAX;
        }
        gs->session_round = value;
    }

    void disable_accept();
    int schedule_worker(int fd, SendData *data);
#ifndef _WIN32
    pid_t restart_worker_process(const ExitStatus &exit_status);
#endif

    size_t get_connection_num() const {
        if (gs->connection_nums) {
            size_t num = 0;
            for (uint32_t i = 0; i < worker_num; i++) {
                num += gs->connection_nums[i];
            }
            return num;
        } else {
            return gs->connection_num;
        }
    }

    static void read_worker_message(ProcessPool *pool, EventData *msg);

    void drain_worker_pipe();
    // Remaining milliseconds in the original shutdown budget, shared by all cleanup phases.
    int get_worker_exit_timeout_msec() const;
    void clean_worker_connections(Worker *worker);

    /**
     * [Worker]
     */
    void worker_start_callback(Worker *worker);
    void worker_stop_callback(Worker *worker);
    void worker_accept_event(DataHead *info);
    void worker_signal_init() const;

    std::function<void(std::shared_ptr<Thread>, const WorkerFn &fn)> worker_thread_start;

    /**
     * [Master]
     */
    bool signal_handler_shutdown();
    bool signal_handler_child_exit() const;
    bool signal_handler_reload(bool reload_all_workers) const;
    bool signal_handler_read_message() const;
    bool signal_handler_reopen_logger() const;

    static void worker_signal_handler(int signo);
    static int reactor_process_main_loop(ProcessPool *pool, Worker *worker);
    static void reactor_thread_main_loop(Server *serv, int reactor_id);
    static bool task_pack(EventData *task, const void *data, size_t data_len);
    static void task_dump(EventData *task);
    static bool task_unpack(EventData *task, String *buffer, PacketPtr *packet);
    static void master_signal_handler(int signo);
    static void heartbeat_check(Timer *timer, TimerNode *tnode);

    int start_event_worker(Worker *worker);

    const char *get_startup_error_message() const;

  private:
    enum Mode mode_;
    Connection *connection_list = nullptr;
    // BASE workers have private connection tables, so their scan bounds must also stay private after fork.
    mutable int min_fd_ = 0;
    mutable int max_fd_ = 0;
    Session *session_list = nullptr;
    ServerPortGS *port_gs_list = nullptr;
    /**
     * http static file directory
     */
    std::string document_root;

    std::shared_ptr<std::vector<http_server::RewriteRule>> rewrite_rules;
    // Coordinates active/bounds publication between reactors in this process. This mutex is not
    // process-shared; worker generation access uses Connection::lock. Lock order: bounds, then slot.
    mutable std::mutex lock_;
    uint32_t max_connection = 0;
    TimerNode *enable_accept_timer = nullptr;
    std::thread heartbeat_thread;
    // The heartbeat producer and master joiner protect the stop flag with this mutex. It never
    // protects Connection state or participates in recv/send paths. The condition variable wakes
    // the interval wait during shutdown; it cannot cancel an in-flight synchronous pipe send.
    std::mutex heartbeat_mutex_;
    std::condition_variable heartbeat_cv_;
    bool heartbeat_stop_requested_ = true;
    /**
     * The number of pipe per reactor maintenance
     */
    uint16_t reactor_pipe_num = 0;
    ReactorThread *reactor_threads = nullptr;
    /**
     * Only used for temporarily saving pointers in add_worker()
     */
    std::vector<Worker *> user_worker_list;
    std::unordered_map<uint16_t, network::Address> local_addr_v4_map;
    std::unordered_map<uint16_t, network::Address> local_addr_v6_map;

    void create_pipe_buffers();
    void release_pipe_buffers();
    void create_worker(Worker *worker);
    Factory *create_base_factory();
    Factory *create_thread_factory();
#ifndef _WIN32
    Factory *create_process_factory();
#endif
    int start_check();
    void check_port_type(const ListenPort *ls);
    void store_listen_socket();
#ifndef _WIN32
    void store_pipe_fd(UnixSocket *p);
#endif
    void destroy_base_factory();
    void destroy_thread_factory() const;
#ifndef _WIN32
    void destroy_process_factory();
#endif
    void destroy_worker(Worker *worker);
    void destroy_task_workers();
    int start_reactor_threads();
#ifndef _WIN32
    int start_reactor_processes();
#endif
    int start_worker_threads();
    int start_master_thread(Reactor *reactor);
    void start_heartbeat_thread();
    void stop_worker_threads();
    bool reload_worker_threads(bool reload_all_workers) const;
    void join_reactor_thread();
    void stop_master_thread();
    void join_heartbeat_thread();
    TimerCallback get_timeout_callback(ListenPort *port, Reactor *reactor, Connection *conn) const;
    bool init_network_interface_addr_map();
    uint16_t get_local_addr_index(network::Address *addr);

    int get_lowest_load_worker_id() const {
        uint32_t lowest_load_worker_id = 0;
        size_t min_coroutine = workers[0].coroutine_num;
        for (uint32_t i = 1; i < worker_num; i++) {
            if (workers[i].coroutine_num < min_coroutine) {
                min_coroutine = workers[i].coroutine_num;
                lowest_load_worker_id = i;
            }
        }
        return lowest_load_worker_id;
    }

    int get_lowest_concurrent_worker_id() const {
        uint32_t lowest_concurrent_worker_id = 0;
        size_t min_concurrency = workers[0].concurrency;
        for (uint32_t i = 1; i < worker_num; i++) {
            if (workers[i].concurrency < min_concurrency) {
                min_concurrency = workers[i].concurrency;
                lowest_concurrent_worker_id = i;
            }
        }
        return lowest_concurrent_worker_id;
    }

    int get_idle_worker_id() {
        bool found = false;
        uint32_t key = 0;
        SW_LOOP_N(worker_num + 1) {
            key = sw_atomic_fetch_add(&worker_round_id, 1) % worker_num;
            if (workers[key].is_idle()) {
                found = true;
                break;
            }
        }
        if (sw_unlikely(!found)) {
            scheduler_warning = true;
        }
        swoole_trace_log(SW_TRACE_SERVER, "schedule=%d, round=%d", key, worker_round_id);
        return key;
    }

    void lock() {
        lock_.lock();
    }

    void unlock() {
        lock_.unlock();
    }
};

}  // namespace swoole

typedef swoole::Server swServer;

static inline swoole::Server *sw_server() {
    return SwooleG.server;
}
