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
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <rango@swoole.com>                             |
 +----------------------------------------------------------------------+
 */

#include "swoole_server.h"
#include "swoole_memory.h"

namespace swoole {
using network::Socket;

static int ReactorProcess_loop(ProcessPool *pool, Worker *worker);
static int ReactorProcess_onPipeRead(Reactor *reactor, Event *event);
static int ReactorProcess_onClose(Reactor *reactor, Event *event);
static void ReactorProcess_onTimeout(Timer *timer, TimerNode *tnode);

#ifdef HAVE_REUSEPORT
static int ReactorProcess_reuse_port(ListenPort *ls);
#endif

static bool Server_is_single(Server *serv) {
    return serv->worker_num == 1 && serv->task_worker_num == 0 && serv->max_request == 0 &&
           serv->user_worker_list.empty();
}

int Server::create_reactor_processes() {
    reactor_num = worker_num;
    connection_list = (Connection *) sw_calloc(max_connection, sizeof(Connection));
    if (connection_list == nullptr) {
        swoole_sys_warning("calloc[2](%d) failed", (int) (max_connection * sizeof(Connection)));
        return SW_ERR;
    }
    return SW_OK;
}

void Server::destroy_reactor_processes() {
    sw_free(connection_list);
}

int Server::start_reactor_processes() {
    single_thread = 1;

    // listen TCP
    if (have_stream_sock == 1) {
        for (auto ls : ports) {
            if (ls->is_dgram()) {
                continue;
            }
#ifdef HAVE_REUSEPORT
            if (enable_reuse_port) {
                if (::close(ls->socket->fd) < 0) {
                    swoole_sys_warning("close(%d) failed", ls->socket->fd);
                }
                delete ls->socket;
                ls->socket = nullptr;
                continue;
            } else
#endif
            {
                // listen server socket
                if (ls->listen() < 0) {
                    return SW_ERR;
                }
            }
        }
    }

    ProcessPool *pool = &gs->event_workers;
    *pool = {};
    if (pool->create(worker_num, 0, SW_IPC_UNIXSOCK) < 0) {
        return SW_ERR;
    }
    pool->set_max_request(max_request, max_request_grace);

    /**
     * store to ProcessPool object
     */
    gs->event_workers.ptr = this;
    gs->event_workers.max_wait_time = max_wait_time;
    gs->event_workers.use_msgqueue = 0;
    gs->event_workers.main_loop = ReactorProcess_loop;
    gs->event_workers.onWorkerNotFound = Server::wait_other_worker;
    memcpy(workers, gs->event_workers.workers, sizeof(*workers) * worker_num);
    gs->event_workers.workers = workers;

    SW_LOOP_N(worker_num) {
        gs->event_workers.workers[i].pool = &gs->event_workers;
        gs->event_workers.workers[i].id = i;
        gs->event_workers.workers[i].type = SW_PROCESS_WORKER;
    }

    init_ipc_max_size();
    if (create_pipe_buffers() < 0) {
        return SW_ERR;
    }

    // single worker
    if (Server_is_single(this)) {
        int retval = ReactorProcess_loop(&gs->event_workers, &gs->event_workers.workers[0]);
        if (retval == SW_OK) {
            gs->event_workers.destroy();
        }
        return retval;
    }

    SW_LOOP_N(worker_num) {
        create_worker(&gs->event_workers.workers[i]);
    }

    // task workers
    if (task_worker_num > 0) {
        if (create_task_workers() < 0) {
            return SW_ERR;
        }
        if (gs->task_workers.start() < 0) {
            return SW_ERR;
        }
    }

    // create user worker process
    if (!user_worker_list.empty()) {
        user_workers = (Worker *) sw_shm_calloc(get_user_worker_num(), sizeof(Worker));
        if (user_workers == nullptr) {
            swoole_sys_warning("gmalloc[server->user_workers] failed");
            return SW_ERR;
        }
        for (auto worker : user_worker_list) {
            /**
             * store the pipe object
             */
            if (worker->pipe_object) {
                store_pipe_fd(worker->pipe_object);
            }
            spawn_user_worker(worker);
        }
    }

    /**
     * manager process is the same as the master process
     */
    SwooleG.pid = gs->manager_pid = getpid();
    SwooleG.process_type = SW_PROCESS_MANAGER;

    /**
     * manager process can not use signalfd
     */
    SwooleG.use_signalfd = 0;

    gs->event_workers.onWorkerMessage = read_worker_message;
    gs->event_workers.start();

    init_signal_handler();

    if (onManagerStart) {
        onManagerStart(this);
    }

    gs->event_workers.wait();
    gs->event_workers.shutdown();

    kill_user_workers();

    if (onManagerStop) {
        onManagerStop(this);
    }

    SW_LOOP_N(worker_num) {
        destroy_worker(&gs->event_workers.workers[i]);
    }

    return SW_OK;
}

static int ReactorProcess_onPipeRead(Reactor *reactor, Event *event) {
    SendData _send;
    Server *serv = (Server *) reactor->ptr;
    Factory *factory = serv->factory;
    PipeBuffer *pipe_buffer = serv->message_bus.get_buffer();

    ssize_t retval = serv->message_bus.read(event->socket);
    if (retval <= 0) {
        return SW_OK;
    }

    switch (pipe_buffer->info.type) {
    case SW_SERVER_EVENT_PIPE_MESSAGE: {
        serv->onPipeMessage(serv, (EventData *) pipe_buffer);
        break;
    }
    case SW_SERVER_EVENT_FINISH: {
        serv->onFinish(serv, (EventData *) pipe_buffer);
        break;
    }
    case SW_SERVER_EVENT_SEND_FILE: {
        _send.info = pipe_buffer->info;
        _send.data = pipe_buffer->data;
        factory->finish(&_send);
        break;
    }
    case SW_SERVER_EVENT_SEND_DATA: {
        if (pipe_buffer->info.reactor_id < 0 || pipe_buffer->info.reactor_id >= (int16_t) serv->get_all_worker_num()) {
            swoole_warning("invalid worker_id=%d", pipe_buffer->info.reactor_id);
            return SW_OK;
        }
        auto packet = serv->message_bus.get_packet();
        memcpy(&_send.info, &pipe_buffer->info, sizeof(_send.info));
        _send.info.type = SW_SERVER_EVENT_RECV_DATA;
        _send.data = packet.data;
        _send.info.len = packet.length;
        factory->finish(&_send);
        break;
    }
    case SW_SERVER_EVENT_CLOSE: {
        factory->end(pipe_buffer->info.fd, Server::CLOSE_ACTIVELY);
        break;
    }
    case SW_SERVER_EVENT_COMMAND_REQUEST: {
        serv->call_command_handler(serv->message_bus, SwooleWG.worker->id, serv->get_worker(0)->pipe_master);
        break;
    }
    case SW_SERVER_EVENT_COMMAND_RESPONSE: {
        int64_t request_id = pipe_buffer->info.fd;
        auto packet = serv->message_bus.get_packet();
        serv->call_command_callback(request_id, std::string(packet.data, packet.length));
        break;
    }
    default:
        break;
    }

    serv->message_bus.pop();

    return SW_OK;
}

static int ReactorProcess_loop(ProcessPool *pool, Worker *worker) {
    Server *serv = (Server *) pool->ptr;

    SwooleG.process_type = SW_PROCESS_WORKER;
    SwooleG.pid = getpid();

    SwooleG.process_id = worker->id;
    if (serv->max_request > 0) {
        SwooleWG.run_always = false;
    }
    SwooleWG.max_request = serv->max_request;
    SwooleWG.worker = worker;
    SwooleTG.id = 0;

    serv->init_worker(worker);

    if (!SwooleTG.reactor) {
        if (swoole_event_init(0) < 0) {
            return SW_ERR;
        }
    }

    Reactor *reactor = SwooleTG.reactor;

    if (SwooleTG.timer && SwooleTG.timer->get_reactor() == nullptr) {
        SwooleTG.timer->reinit(reactor);
    }

    for (auto ls : serv->ports) {
#ifdef HAVE_REUSEPORT
        if (ls->is_stream() && serv->enable_reuse_port) {
            if (ReactorProcess_reuse_port(ls) < 0) {
                swoole_event_free();
                return SW_ERR;
            }
        }
#endif
        if (reactor->add(ls->socket, SW_EVENT_READ) < 0) {
            return SW_ERR;
        }
    }

    reactor->id = worker->id;
    reactor->ptr = serv;

#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd) {
        swoole_signalfd_setup(SwooleTG.reactor);
    }
#endif

    reactor->max_socket = serv->get_max_connection();

    reactor->close = Server::close_connection;

    // set event handler
    // connect
    reactor->set_handler(SW_FD_STREAM_SERVER, Server::accept_connection);
    // close
    reactor->default_error_handler = ReactorProcess_onClose;
    // pipe
    reactor->set_handler(SW_FD_PIPE | SW_EVENT_READ, ReactorProcess_onPipeRead);

    serv->store_listen_socket();

    if (worker->pipe_worker) {
        worker->pipe_worker->set_nonblock();
        worker->pipe_master->set_nonblock();
        if (reactor->add(worker->pipe_worker, SW_EVENT_READ) < 0) {
            return SW_ERR;
        }
        if (reactor->add(worker->pipe_master, SW_EVENT_READ) < 0) {
            return SW_ERR;
        }
    }

    // task workers
    if (serv->task_worker_num > 0) {
        if (serv->task_ipc_mode == Server::TASK_IPC_UNIXSOCK) {
            SW_LOOP_N(serv->gs->task_workers.worker_num) {
                serv->gs->task_workers.workers[i].pipe_master->set_nonblock();
            }
        }
    }

    serv->init_reactor(reactor);

    if (worker->id == 0) {
        if (serv->onStart) {
            serv->onStart(serv);
        }
    }

    if ((serv->master_timer = swoole_timer_add(1000L, true, Server::timer_callback, serv)) == nullptr) {
    _fail:
        swoole_event_free();
        return SW_ERR;
    }

    serv->worker_start_callback();

    /**
     * for heartbeat check
     */
    if (serv->heartbeat_check_interval > 0) {
        serv->heartbeat_timer =
            swoole_timer_add((long) (serv->heartbeat_check_interval * 1000), true, ReactorProcess_onTimeout, reactor);
        if (serv->heartbeat_timer == nullptr) {
            goto _fail;
        }
    }

    int retval = reactor->wait(nullptr);

    /**
     * Close all connections
     */
    serv->foreach_connection([serv](Connection *conn) { serv->close(conn->session_id, true); });

    /**
     * call internal serv hooks
     */
    if (serv->isset_hook(Server::HOOK_WORKER_CLOSE)) {
        void *hook_args[2];
        hook_args[0] = serv;
        hook_args[1] = (void *) (uintptr_t) SwooleG.process_id;
        serv->call_hook(Server::HOOK_WORKER_CLOSE, hook_args);
    }

    swoole_event_free();
    serv->worker_stop_callback();

    return retval;
}

static int ReactorProcess_onClose(Reactor *reactor, Event *event) {
    int fd = event->fd;
    Server *serv = (Server *) reactor->ptr;
    Connection *conn = serv->get_connection(fd);
    if (conn == nullptr || conn->active == 0) {
        return SW_ERR;
    }
    if (event->socket->removed) {
        return Server::close_connection(reactor, event->socket);
    }
    if (reactor->del(event->socket) == 0) {
        if (conn->close_queued) {
            return Server::close_connection(reactor, event->socket);
        } else {
            return serv->notify(conn, SW_SERVER_EVENT_CLOSE) ? SW_OK : SW_ERR;
        }
    } else {
        return SW_ERR;
    }
}

static void ReactorProcess_onTimeout(Timer *timer, TimerNode *tnode) {
    Reactor *reactor = (Reactor *) tnode->data;
    Server *serv = (Server *) reactor->ptr;
    Event notify_ev{};
    double now = microtime();

    notify_ev.type = SW_FD_SESSION;

    serv->foreach_connection([serv, reactor, now, &notify_ev](Connection *conn) {
        if (serv->is_healthy_connection(now, conn)) {
            return;
        }
#ifdef SW_USE_OPENSSL
        if (conn->socket->ssl && conn->socket->ssl_state != SW_SSL_STATE_READY) {
            Server::close_connection(reactor, conn->socket);
            return;
        }
#endif
        if (serv->disable_notify || conn->close_force) {
            Server::close_connection(reactor, conn->socket);
            return;
        }
        conn->close_force = 1;
        notify_ev.fd = conn->fd;
        notify_ev.socket = conn->socket;
        notify_ev.reactor_id = conn->reactor_id;
        ReactorProcess_onClose(reactor, &notify_ev);
    });
}

#ifdef HAVE_REUSEPORT
static int ReactorProcess_reuse_port(ListenPort *ls) {
    ls->socket = swoole::make_socket(
        ls->type, ls->is_dgram() ? SW_FD_DGRAM_SERVER : SW_FD_STREAM_SERVER, SW_SOCK_CLOEXEC | SW_SOCK_NONBLOCK);
    if (ls->socket->set_reuse_port() < 0) {
        ls->socket->free();
        return SW_ERR;
    }
    if (ls->socket->bind(ls->host, &ls->port) < 0) {
        ls->socket->free();
        return SW_ERR;
    }
    return ls->listen();
}
#endif

}  // namespace swoole
