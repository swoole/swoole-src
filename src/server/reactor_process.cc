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

namespace swoole {
using network::Socket;

static int ReactorProcess_onPipeRead(Reactor *reactor, Event *event);
static int ReactorProcess_onClose(Reactor *reactor, Event *event);
static void ReactorProcess_onTimeout(Timer *timer, TimerNode *tnode);

int Server::start_reactor_processes() {
    single_thread = true;

    // listen TCP
    if (have_stream_sock == 1) {
        for (auto ls : ports) {
            if (ls->is_stream()) {
#if defined(__linux__) && defined(HAVE_REUSEPORT)
                if (!enable_reuse_port) {
#endif
                    // listen server socket
                    if (ls->listen() < 0) {
                        return SW_ERR;
                    }
#if defined(__linux__) && defined(HAVE_REUSEPORT)
                } else {
                    ls->close_socket();
                }
#endif
            }
        }
    }

    ProcessPool *pool = get_event_worker_pool();
    *pool = {};
    if (pool->create(worker_num, 0, SW_IPC_UNIXSOCK) < 0) {
        return SW_ERR;
    }
    pool->set_max_request(max_request, max_request_grace);

    /**
     * store to ProcessPool object
     */
    pool->ptr = this;
    pool->max_wait_time = max_wait_time;
    pool->use_msgqueue = 0;
    pool->main_loop = reactor_process_main_loop;
    pool->onWorkerNotFound = wait_other_worker;
    memcpy(workers, pool->workers, sizeof(*workers) * worker_num);
    pool->workers = workers;

    SW_LOOP_N(worker_num) {
        pool->workers[i].pool = pool;
        pool->workers[i].id = i;
        pool->workers[i].type = SW_WORKER;
    }

    init_ipc_max_size();
    if (create_pipe_buffers() < 0) {
        return SW_ERR;
    }

    if (is_single_worker()) {
        Worker *worker = &pool->workers[0];
        SwooleWG.worker = worker;
        int retval = reactor_process_main_loop(pool, worker);
        if (retval == SW_OK) {
            pool->destroy();
        }
        return retval;
    }

    return start_manager_process();
}

static int ReactorProcess_onPipeRead(Reactor *reactor, Event *event) {
    SendData _send;
    auto *serv = static_cast<Server *>(reactor->ptr);
    auto *factory = serv->factory;
    auto *pipe_buffer = serv->message_bus.get_buffer();
    auto *worker = serv->get_worker(reactor->id);

    ssize_t retval = serv->message_bus.read(event->socket);
    if (retval <= 0) {
        return SW_OK;
    }

    switch (pipe_buffer->info.type) {
    case SW_SERVER_EVENT_PIPE_MESSAGE: {
        serv->onPipeMessage(serv, reinterpret_cast<EventData *>(pipe_buffer));
        break;
    }
    case SW_SERVER_EVENT_FINISH: {
        serv->onFinish(serv, reinterpret_cast<EventData *>(pipe_buffer));
        break;
    }
    case SW_SERVER_EVENT_SHUTDOWN: {
        serv->stop_async_worker(worker);
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
    case SW_SERVER_EVENT_CLOSE:
    case SW_SERVER_EVENT_CLOSE_FORWARD: {
        factory->end(pipe_buffer->info.fd, Server::CLOSE_ACTIVELY);
        break;
    }
    case SW_SERVER_EVENT_COMMAND_REQUEST: {
        serv->call_command_handler(serv->message_bus, sw_worker()->id, serv->get_worker(0)->pipe_master);
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

int Server::reactor_process_main_loop(ProcessPool *pool, Worker *worker) {
    auto *serv = static_cast<Server *>(pool->ptr);
    swoole_set_worker_type(SW_EVENT_WORKER);
    swoole_set_worker_id(worker->id);
    swoole_set_worker_pid(getpid());

    serv->init_event_worker(worker);

    if (!SwooleTG.reactor) {
        if (swoole_event_init(0) < 0) {
            return SW_ERR;
        }
    }

    Reactor *reactor = SwooleTG.reactor;

    if (SwooleTG.timer && SwooleTG.timer->get_reactor() == nullptr) {
        SwooleTG.timer->reinit();
    }

    serv->worker_signal_init();

    serv->gs->connection_nums[worker->id] = 0;

    for (auto ls : serv->ports) {
#if defined(__linux__) and defined(HAVE_REUSEPORT)
        if (ls->is_stream() && serv->enable_reuse_port) {
            if (ls->create_socket() < 0) {
                swoole_event_free();
                return SW_ERR;
            }

            if (ls->listen() < 0) {
                return SW_ERR;
            }
        }
#endif
        ls->gs->connection_nums[worker->id] = 0;
        if (reactor->add(ls->socket, SW_EVENT_READ) < 0) {
            return SW_ERR;
        }
    }

    reactor->id = worker->id;
    reactor->ptr = serv;
    reactor->max_socket = serv->get_max_connection();

    reactor->close = close_connection;

    // set event handler
    // connect
    reactor->set_handler(SW_FD_STREAM_SERVER, SW_EVENT_READ, accept_connection);
    // close
    reactor->default_error_handler = ReactorProcess_onClose;
    // pipe
    reactor->set_handler(SW_FD_PIPE, SW_EVENT_READ, ReactorProcess_onPipeRead);

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
            SW_LOOP_N(serv->get_task_worker_pool()->worker_num) {
                serv->get_task_worker_pool()->workers[i].pipe_master->set_nonblock();
            }
        }
    }

    serv->init_reactor(reactor);

    if (worker->id == 0) {
        serv->gs->master_pid = getpid();
        if (serv->onStart && !serv->gs->onstart_called) {
            serv->gs->onstart_called = true;
            serv->onStart(serv);
        }
    }

    if ((serv->master_timer = swoole_timer_add(1000L, true, timer_callback, serv)) == nullptr) {
    _fail:
        swoole_event_free();
        return SW_ERR;
    }

    serv->worker_start_callback(worker);

    /**
     * for heartbeat check
     */
    if (serv->heartbeat_check_interval > 0) {
        serv->heartbeat_timer =
            swoole_timer_add(sec2msec(serv->heartbeat_check_interval), true, ReactorProcess_onTimeout, reactor);
        if (serv->heartbeat_timer == nullptr) {
            goto _fail;
        }
    }

    int retval = reactor->wait();

    /**
     * Close all connections
     */
    serv->foreach_connection([serv](Connection *conn) { serv->close(conn->session_id, true); });

    /**
     * call internal serv hooks
     */
    if (serv->isset_hook(HOOK_WORKER_CLOSE)) {
        void *hook_args[2];
        hook_args[0] = serv;
        hook_args[1] = (void *) (uintptr_t) worker->id;
        serv->call_hook(HOOK_WORKER_CLOSE, hook_args);
    }

    swoole_event_free();
    serv->worker_stop_callback(worker);

    return retval;
}

static int ReactorProcess_onClose(Reactor *reactor, Event *event) {
    int fd = event->fd;
    auto *serv = (Server *) reactor->ptr;
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
            /**
             * peer_closed indicates that the client has closed the connection
             * and the connection is no longer available.
             */
            conn->peer_closed = 1;
            return serv->notify(conn, SW_SERVER_EVENT_CLOSE) ? SW_OK : SW_ERR;
        }
    } else {
        return SW_ERR;
    }
}

static void ReactorProcess_onTimeout(Timer *timer, TimerNode *tnode) {
    auto *reactor = static_cast<Reactor *>(tnode->data);
    auto *serv = static_cast<Server *>(reactor->ptr);
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
}  // namespace swoole
