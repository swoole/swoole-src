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
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#include "swoole_server.h"
#include "swoole_memory.h"

using namespace swoole;
using network::Socket;

int swFactory_create(Factory *factory);

static int ReactorProcess_loop(ProcessPool *pool, Worker *worker);
static int ReactorProcess_onPipeRead(Reactor *reactor, Event *event);
static int ReactorProcess_onClose(Reactor *reactor, Event *event);
static bool ReactorProcess_send2client(Factory *, SendData *data);
static int ReactorProcess_send2worker(Socket *socket, const void *data, size_t length);
static void ReactorProcess_onTimeout(Timer *timer, TimerNode *tnode);

#ifdef HAVE_REUSEPORT
static int ReactorProcess_reuse_port(ListenPort *ls);
#endif

static bool Server_is_single(Server *serv) {
    return serv->worker_num == 1 && serv->task_worker_num == 0 && serv->max_request == 0 &&
           serv->user_worker_list == nullptr;
}

int Server::create_reactor_processes() {
    reactor_num = worker_num;
    connection_list = (Connection *) sw_calloc(max_connection, sizeof(Connection));
    if (connection_list == nullptr) {
        swSysWarn("calloc[2](%d) failed", (int ) (max_connection * sizeof(Connection)));
        return SW_ERR;
    }
    // create factry object
    if (swFactory_create(&(factory)) < 0) {
        swError("create factory failed");
        return SW_ERR;
    }
    factory.finish = ReactorProcess_send2client;
    return SW_OK;
}

void Server::destroy_reactor_processes() {
    factory.free(&factory);
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
                    swSysWarn("close(%d) failed", ls->socket->fd);
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
    if (ProcessPool::create(pool, worker_num, 0, SW_IPC_UNIXSOCK) < 0) {
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

    uint32_t i;
    for (i = 0; i < worker_num; i++) {
        gs->event_workers.workers[i].pool = &gs->event_workers;
        gs->event_workers.workers[i].id = i;
        gs->event_workers.workers[i].type = SW_PROCESS_WORKER;
    }

    // single worker
    if (Server_is_single(this)) {
        int retval = ReactorProcess_loop(&gs->event_workers, &gs->event_workers.workers[0]);
        if (retval == SW_OK) {
            gs->event_workers.destroy();
        }
        return retval;
    }

    for (i = 0; i < worker_num; i++) {
        if (create_worker(&gs->event_workers.workers[i]) < 0) {
            return SW_ERR;
        }
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

    /**
     * create user worker process
     */
    if (user_worker_list) {
        user_workers = (Worker *) sw_shm_calloc(user_worker_num, sizeof(Worker));
        if (user_workers == nullptr) {
            swSysWarn("gmalloc[server->user_workers] failed");
            return SW_ERR;
        }
        for (auto worker : *user_worker_list) {
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

    gs->event_workers.start();

    init_signal_handler();

    if (onStart) {
        swWarn("The onStart event with SWOOLE_BASE is deprecated");
        onStart(this);
    }

    if (onManagerStart) {
        onManagerStart(this);
    }

    gs->event_workers.wait();
    gs->event_workers.shutdown();

    kill_user_workers();

    if (onManagerStop) {
        onManagerStop(this);
    }

    return SW_OK;
}

static int ReactorProcess_onPipeRead(Reactor *reactor, Event *event) {
    EventData task;
    SendData _send;
    Server *serv = (Server *) reactor->ptr;
    Factory *factory = &serv->factory;
    String *output_buffer;

    if (read(event->fd, &task, sizeof(task)) <= 0) {
        return SW_ERR;
    }

    switch (task.info.type) {
    case SW_SERVER_EVENT_PIPE_MESSAGE:
        serv->onPipeMessage(serv, &task);
        break;
    case SW_SERVER_EVENT_FINISH:
        serv->onFinish(serv, &task);
        break;
    case SW_SERVER_EVENT_SEND_FILE:
        memcpy(&_send.info, &task.info, sizeof(_send.info));
        _send.data = task.data;
        factory->finish(factory, &_send);
        break;
    case SW_SERVER_EVENT_PROXY_START:
    case SW_SERVER_EVENT_PROXY_END:
        output_buffer = SwooleWG.output_buffer[task.info.reactor_id];
        output_buffer->append(task.data, task.info.len);
        if (task.info.type == SW_SERVER_EVENT_PROXY_END) {
            memcpy(&_send.info, &task.info, sizeof(_send.info));
            _send.info.type = SW_SERVER_EVENT_RECV_DATA;
            _send.data = output_buffer->str;
            _send.info.len = output_buffer->length;
            factory->finish(factory, &_send);
            swString_clear(output_buffer);
        }
        break;
    default:
        break;
    }
    return SW_OK;
}

static int ReactorProcess_alloc_output_buffer(int n_buffer) {
    SwooleWG.output_buffer = (String **) sw_malloc(sizeof(String *) * n_buffer);
    if (SwooleWG.output_buffer == nullptr) {
        swError("malloc for SwooleWG.output_buffer failed");
        return SW_ERR;
    }

    int i;
    for (i = 0; i < n_buffer; i++) {
        SwooleWG.output_buffer[i] = swString_new(SW_BUFFER_SIZE_BIG);
        if (SwooleWG.output_buffer[i] == nullptr) {
            swError("output_buffer init failed");
            return SW_ERR;
        }
    }
    return SW_OK;
}

static void ReactorProcess_free_output_buffer(int n_buffer) {
    int i;
    for (i = 0; i < n_buffer; i++) {
        swString_free(SwooleWG.output_buffer[i]);
    }
    sw_free(SwooleWG.output_buffer);
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
    if (worker->id == 0) {
        SwooleTG.update_time = 1;
    }

    serv->init_worker(worker);

    // create reactor
    if (!SwooleTG.reactor) {
        if (swoole_event_init(0) < 0) {
            return SW_ERR;
        }
    }

    Reactor *reactor = SwooleTG.reactor;

    if (SwooleTG.timer && SwooleTG.timer->get_reactor() == nullptr) {
        SwooleTG.timer->reinit(reactor);
    }

    int n_buffer = serv->worker_num + serv->task_worker_num + serv->user_worker_num;
    if (ReactorProcess_alloc_output_buffer(n_buffer)) {
        return SW_ERR;
    }

    for (auto ls : serv->ports) {
#ifdef HAVE_REUSEPORT
        if (ls->is_stream() && serv->enable_reuse_port) {
            if (ReactorProcess_reuse_port(ls) < 0) {
                ReactorProcess_free_output_buffer(n_buffer);
                swoole_event_free();
                return SW_ERR;
            }
        }
#endif
        if (reactor->add(reactor, ls->socket, SW_EVENT_READ) < 0) {
            return SW_ERR;
        }
    }

    reactor->id = worker->id;
    reactor->ptr = serv;

#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd) {
        swSignalfd_setup(SwooleTG.reactor);
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
        if (reactor->add(reactor, worker->pipe_worker, SW_EVENT_READ) < 0) {
            return SW_ERR;
        }
        if (reactor->add(reactor, worker->pipe_master, SW_EVENT_READ) < 0) {
            return SW_ERR;
        }
    }

    // task workers
    if (serv->task_worker_num > 0) {
        if (serv->task_ipc_mode == SW_TASK_IPC_UNIXSOCK) {
            for (uint32_t i = 0; i < serv->gs->task_workers.worker_num; i++) {
                serv->gs->task_workers.workers[i].pipe_master->set_nonblock();
            }
        }
    }

    serv->init_reactor(reactor);

    // single server trigger onStart event
    if (Server_is_single(serv)) {
        if (serv->onStart) {
            serv->onStart(serv);
        }
    }

    /**
     * 1 second timer
     */
    if ((serv->master_timer = swoole_timer_add(1000, true, Server::timer_callback, serv)) == nullptr) {
    _fail:
        ReactorProcess_free_output_buffer(n_buffer);
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

    int retval = reactor->wait(reactor, nullptr);

    /**
     * Close all connections
     */
    serv->foreach_connection([serv](Connection *conn) { serv->close(conn->session_id, true); });

    /**
     * call internal serv hooks
     */
    if (serv->hooks[Server::HOOK_WORKER_CLOSE]) {
        void *hook_args[2];
        hook_args[0] = serv;
        hook_args[1] = (void *) (uintptr_t) SwooleG.process_id;
        serv->call_hook(Server::HOOK_WORKER_CLOSE, hook_args);
    }

    swoole_event_free();
    serv->worker_stop_callback();
    ReactorProcess_free_output_buffer(n_buffer);

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
    if (reactor->del(reactor, event->socket) == 0) {
        if (conn->close_queued) {
            return Server::close_connection(reactor, event->socket);
        } else {
            return serv->notify(conn, SW_SERVER_EVENT_CLOSE) ? SW_OK : SW_ERR;
        }
    } else {
        return SW_ERR;
    }
}

static int ReactorProcess_send2worker(Socket *socket, const void *data, size_t length) {
    if (!swoole_event_is_available()) {
        return socket->send_blocking(data, length);
    } else {
        return swoole_event_write(socket, data, length);
    }
}

static bool ReactorProcess_send2client(Factory *factory, SendData *data) {
    Server *serv = (Server *) factory->ptr;
    int session_id = data->info.fd;

    Session *session = serv->get_session(session_id);
    if (session->reactor_id != SwooleG.process_id) {
        swTrace("session->reactor_id=%d, SwooleG.process_id=%d", session->reactor_id, SwooleG.process_id);
        Worker *worker = serv->gs->event_workers.get_worker(session->reactor_id);
        EventData proxy_msg {};

        if (data->info.type == SW_SERVER_EVENT_RECV_DATA) {
            proxy_msg.info.fd = session_id;
            proxy_msg.info.reactor_id = SwooleG.process_id;
            proxy_msg.info.type = SW_SERVER_EVENT_PROXY_START;

            size_t send_n = data->info.len;
            size_t offset = 0;

            while (send_n > 0) {
                if (send_n > SW_IPC_BUFFER_SIZE) {
                    proxy_msg.info.len = SW_IPC_BUFFER_SIZE;
                } else {
                    proxy_msg.info.type = SW_SERVER_EVENT_PROXY_END;
                    proxy_msg.info.len = send_n;
                }
                memcpy(proxy_msg.data, data->data + offset, proxy_msg.info.len);
                send_n -= proxy_msg.info.len;
                offset += proxy_msg.info.len;
                ReactorProcess_send2worker(
                    worker->pipe_master, (const char *) &proxy_msg, sizeof(proxy_msg.info) + proxy_msg.info.len);
            }

            swTrace("proxy message, fd=%d, len=%ld", worker->pipe_master, sizeof(proxy_msg.info) + proxy_msg.info.len);
        } else if (data->info.type == SW_SERVER_EVENT_SEND_FILE) {
            memcpy(&proxy_msg.info, &data->info, sizeof(proxy_msg.info));
            memcpy(proxy_msg.data, data->data, data->info.len);
            return ReactorProcess_send2worker(
                worker->pipe_master, (const char *) &proxy_msg, sizeof(proxy_msg.info) + proxy_msg.info.len);
        } else {
            swWarn("unkown event type[%d]", data->info.type);
            return false;
        }
        return true;
    } else {
        return swFactory_finish(factory, data);
    }
}

static void ReactorProcess_onTimeout(Timer *timer, TimerNode *tnode) {
    Reactor *reactor = (Reactor *) tnode->data;
    Server *serv = (Server *) reactor->ptr;
    Event notify_ev;
    time_t now = swoole_microtime();

    if (now < serv->heartbeat_check_lasttime + 10) {
        return;
    }

    sw_memset_zero(&notify_ev, sizeof(notify_ev));
    notify_ev.type = SW_FD_SESSION;

    int checktime = now - serv->heartbeat_idle_time;

    serv->foreach_connection([serv, checktime, reactor, &notify_ev](Connection *conn) {
        if (conn->protect || conn->last_recv_time > checktime) {
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
    int option = 1;
    if (setsockopt(ls->socket->fd, SOL_SOCKET, SO_REUSEPORT, &option, sizeof(int)) != 0) {
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
