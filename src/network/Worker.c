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

#include "swoole.h"
#include "Server.h"
#include "Client.h"
#include "async.h"

#include <pwd.h>
#include <grp.h>

static int swWorker_onPipeReceive(swReactor *reactor, swEvent *event);
static void swWorker_onTimeout(swTimer *timer, swTimer_node *tnode);
static void swWorker_stop();

int swWorker_create(swWorker *worker)
{
    /**
     * Create shared memory storage
     */
    worker->send_shm = sw_shm_malloc(SwooleG.serv->buffer_output_size);
    if (worker->send_shm == NULL)
    {
        swWarn("malloc for worker->store failed.");
        return SW_ERR;
    }
    swMutex_create(&worker->lock, 1);

    return SW_OK;
}

void swWorker_free(swWorker *worker)
{
    if (worker->send_shm)
    {
        sw_shm_free(worker->send_shm);
    }
}

void swWorker_signal_init(void)
{
    swSignal_clear();
    /**
     * use user settings
     */
    SwooleG.use_signalfd = SwooleG.enable_signalfd;

    swSignal_add(SIGHUP, NULL);
    swSignal_add(SIGPIPE, NULL);
    swSignal_add(SIGUSR1, NULL);
    swSignal_add(SIGUSR2, NULL);
    //swSignal_add(SIGINT, swWorker_signal_handler);
    swSignal_add(SIGTERM, swWorker_signal_handler);
    swSignal_add(SIGALRM, swSystemTimer_signal_handler);
    //for test
    swSignal_add(SIGVTALRM, swWorker_signal_handler);
#ifdef SIGRTMIN
    swSignal_add(SIGRTMIN, swWorker_signal_handler);
#endif
}

void swWorker_signal_handler(int signo)
{
    switch (signo)
    {
    case SIGTERM:
        /**
         * Event worker
         */
        if (SwooleG.main_reactor)
        {
            swWorker_stop();
        }
        /**
         * Task worker
         */
        else
        {
            SwooleG.running = 0;
        }
        break;
    case SIGALRM:
        swSystemTimer_signal_handler(SIGALRM);
        break;
    /**
     * for test
     */
    case SIGVTALRM:
        swWarn("SIGVTALRM coming");
        break;
    case SIGUSR1:
        break;
    case SIGUSR2:
        break;
    default:
#ifdef SIGRTMIN
        if (signo == SIGRTMIN)
        {
            swServer_reopen_log_file(SwooleG.serv);
        }
#endif
        break;
    }
}

static sw_inline int swWorker_discard_data(swServer *serv, swEventData *task)
{
    int fd = task->info.fd;
    //check connection
    swConnection *conn = swServer_connection_verify(serv, task->info.fd);
    if (conn == NULL)
    {
        if (serv->disable_notify && !serv->discard_timeout_request)
        {
            return SW_FALSE;
        }
        goto discard_data;
    }
    else
    {
        if (conn->closed)
        {
            goto discard_data;
        }
        else
        {
            return SW_FALSE;
        }
    }
    discard_data:
#ifdef SW_USE_RINGBUFFER
    if (task->info.type == SW_EVENT_PACKAGE)
    {
        swPackage package;
        memcpy(&package, task->data, sizeof(package));
        swReactorThread *thread = swServer_get_thread(SwooleG.serv, task->info.from_id);
        thread->buffer_input->free(thread->buffer_input, package.data);
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SESSION_DISCARD_TIMEOUT_DATA, "[1]received the wrong data[%d bytes] from socket#%d", package.length, fd);
    }
    else
#endif
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SESSION_DISCARD_TIMEOUT_DATA, "[1]received the wrong data[%d bytes] from socket#%d", task->info.len, fd);
    }
    return SW_TRUE;
}

int swWorker_onTask(swFactory *factory, swEventData *task)
{
    swServer *serv = factory->ptr;
    swString *package = NULL;
    swDgramPacket *header;

#ifdef SW_USE_OPENSSL
    swConnection *conn;
#endif

    factory->last_from_id = task->info.from_id;
    //worker busy
    serv->workers[SwooleWG.id].status = SW_WORKER_BUSY;

    switch (task->info.type)
    {
    //no buffer
    case SW_EVENT_TCP:
    //ringbuffer shm package
    case SW_EVENT_PACKAGE:
        //discard data
        if (swWorker_discard_data(serv, task) == SW_TRUE)
        {
            break;
        }
        do_task:
        {
            serv->onReceive(serv, task);
            SwooleWG.request_count++;
            sw_atomic_fetch_add(&SwooleStats->request_count, 1);
        }
        if (task->info.type == SW_EVENT_PACKAGE_END)
        {
            package->length = 0;
        }
        break;

    //chunk package
    case SW_EVENT_PACKAGE_START:
    case SW_EVENT_PACKAGE_END:
        //discard data
        if (swWorker_discard_data(serv, task) == SW_TRUE)
        {
            break;
        }
        package = swWorker_get_buffer(serv, task->info.from_id);
        //merge data to package buffer
        memcpy(package->str + package->length, task->data, task->info.len);
        package->length += task->info.len;

        //package end
        if (task->info.type == SW_EVENT_PACKAGE_END)
        {
            goto do_task;
        }
        break;

    case SW_EVENT_UDP:
    case SW_EVENT_UDP6:
    case SW_EVENT_UNIX_DGRAM:
        package = swWorker_get_buffer(serv, task->info.from_id);
        swString_append_ptr(package, task->data, task->info.len);

        if (package->offset == 0)
        {
            header = (swDgramPacket *) package->str;
            package->offset = header->length;
        }

        //one packet
        if (package->offset == package->length - sizeof(swDgramPacket))
        {
            SwooleWG.request_count++;
            sw_atomic_fetch_add(&SwooleStats->request_count, 1);
            serv->onPacket(serv, task);
            swString_clear(package);
        }
        break;

    case SW_EVENT_CLOSE:
#ifdef SW_USE_OPENSSL
        conn = swServer_connection_verify_no_ssl(serv, task->info.fd);
        if (conn && conn->ssl_client_cert.length > 0)
        {
            free(conn->ssl_client_cert.str);
            bzero(&conn->ssl_client_cert, sizeof(conn->ssl_client_cert.str));
        }
#endif
        factory->end(factory, task->info.fd);
        break;

    case SW_EVENT_CONNECT:
#ifdef SW_USE_OPENSSL
        //SSL client certificate
        if (task->info.len > 0)
        {
            conn = swServer_connection_verify_no_ssl(serv, task->info.fd);
            conn->ssl_client_cert.str = sw_strndup(task->data, task->info.len);
            conn->ssl_client_cert.size = conn->ssl_client_cert.length = task->info.len;
        }
#endif
        if (serv->onConnect)
        {
            serv->onConnect(serv, &task->info);
        }
        break;

    case SW_EVENT_BUFFER_FULL:
        if (serv->onBufferFull)
        {
            serv->onBufferFull(serv, &task->info);
        }
        break;

    case SW_EVENT_BUFFER_EMPTY:
        if (serv->onBufferEmpty)
        {
            serv->onBufferEmpty(serv, &task->info);
        }
        break;

    case SW_EVENT_FINISH:
        serv->onFinish(serv, task);
        break;

    case SW_EVENT_PIPE_MESSAGE:
        serv->onPipeMessage(serv, task);
        break;

    default:
        swWarn("[Worker] error event[type=%d]", (int )task->info.type);
        break;
    }

    //worker idle
    serv->workers[SwooleWG.id].status = SW_WORKER_IDLE;

    //maximum number of requests, process will exit.
    if (!SwooleWG.run_always && SwooleWG.request_count >= SwooleWG.max_request)
    {
        swWorker_stop();
    }
    return SW_OK;
}

void swWorker_onStart(swServer *serv)
{
    /**
     * Release other worker process
     */
    swWorker *worker;

    if (SwooleWG.id >= serv->worker_num)
    {
        SwooleG.process_type = SW_PROCESS_TASKWORKER;
    }
    else
    {
        SwooleG.process_type = SW_PROCESS_WORKER;
    }

    int is_root = !geteuid();
    struct passwd *passwd = NULL;
    struct group *group = NULL;

    if (is_root)
    {
        //get group info
        if (SwooleG.group)
        {
            group = getgrnam(SwooleG.group);
            if (!group)
            {
                swWarn("get group [%s] info failed.", SwooleG.group);
            }
        }
        //get user info
        if (SwooleG.user)
        {
            passwd = getpwnam(SwooleG.user);
            if (!passwd)
            {
                swWarn("get user [%s] info failed.", SwooleG.user);
            }
        }
        //chroot
        if (SwooleG.chroot)
        {
            if (0 > chroot(SwooleG.chroot))
            {
                swSysError("chroot to [%s] failed.", SwooleG.chroot);
            }
        }
        //set process group
        if (SwooleG.group && group)
        {
            if (setgid(group->gr_gid) < 0)
            {
                swSysError("setgid to [%s] failed.", SwooleG.group);
            }
        }
        //set process user
        if (SwooleG.user && passwd)
        {
            if (setuid(passwd->pw_uid) < 0)
            {
                swSysError("setuid to [%s] failed.", SwooleG.user);
            }
        }
    }

    SwooleWG.worker = swServer_get_worker(serv, SwooleWG.id);

    int i;
    for (i = 0; i < serv->worker_num + SwooleG.task_worker_num; i++)
    {
        worker = swServer_get_worker(serv, i);
        if (SwooleWG.id == i)
        {
            continue;
        }
        else
        {
            swWorker_free(worker);
        }
        if (swIsWorker())
        {
            swSetNonBlock(worker->pipe_master);
        }
    }

    sw_shm_protect(serv->session_list, PROT_READ);

    if (serv->onWorkerStart)
    {
        serv->onWorkerStart(serv, SwooleWG.id);
    }
}

void swWorker_onStop(swServer *serv)
{
    if (serv->onWorkerStop)
    {
        serv->onWorkerStop(serv, SwooleWG.id);
    }
}

static void swWorker_stop()
{
    swWorker *worker = SwooleWG.worker;
    swServer *serv = SwooleG.serv;

    /**
     * force to end
     */
    if (serv->reload_async == 0)
    {
        SwooleG.running = 0;
        SwooleG.main_reactor->running = 0;
        return;
    }

    //The worker process is shutting down now.
    if (SwooleWG.wait_exit)
    {
        return;
    }

    //remove read event
    if (worker->pipe_worker)
    {
        swReactor_remove_read_event(SwooleG.main_reactor, worker->pipe_worker);
    }

    if (serv->onWorkerStop)
    {
        serv->onWorkerStop(serv, SwooleWG.id);
        serv->onWorkerStop = NULL;
    }

    if (serv->factory_mode == SW_MODE_SINGLE)
    {
        swListenPort *port;
        LL_FOREACH(serv->listen_list, port)
        {
            SwooleG.main_reactor->del(SwooleG.main_reactor, port->sock);
            swPort_free(port);
        }

        if (worker->pipe_worker)
        {
            SwooleG.main_reactor->del(SwooleG.main_reactor, worker->pipe_worker);
            SwooleG.main_reactor->del(SwooleG.main_reactor, worker->pipe_master);
        }

        goto try_to_exit;
    }

    swWorkerStopMessage msg;
    msg.pid = SwooleG.pid;
    msg.worker_id = SwooleWG.id;

    //send message to manager
    if (swChannel_push(SwooleG.serv->message_box, &msg, sizeof(msg)) < 0)
    {
        SwooleG.running = 0;
    }
    else
    {
        kill(SwooleGS->manager_pid, SIGIO);
    }

    try_to_exit: SwooleWG.wait_exit = 1;
    if (SwooleG.timer.fd == 0)
    {
        swTimer_init(serv->max_wait_time * 1000);
    }
    SwooleG.timer.add(&SwooleG.timer, serv->max_wait_time * 1000, 0, NULL, swWorker_onTimeout);

    swWorker_try_to_exit();
}

static void swWorker_onTimeout(swTimer *timer, swTimer_node *tnode)
{
    SwooleG.running = 0;
    SwooleG.main_reactor->running = 0;
    swoole_error_log(SW_LOG_WARNING, SW_ERROR_SERVER_WORKER_EXIT_TIMEOUT, "worker exit timeout, forced to terminate.");
}

void swWorker_try_to_exit()
{
    swServer *serv = SwooleG.serv;
    int expect_event_num = SwooleG.use_signalfd ? 1 : 0;

    if (SwooleAIO.init && SwooleAIO.task_num == 0)
    {
        swAio_free();
    }

    swDNSResolver_free();

    //close all client connections
    if (serv->factory_mode == SW_MODE_SINGLE)
    {
        int find_fd = swServer_get_minfd(serv);
        int max_fd = swServer_get_maxfd(serv);
        swConnection *conn;
        for (; find_fd <= max_fd; find_fd++)
        {
            conn = &serv->connection_list[find_fd];
            if (conn->active == 1 && swSocket_is_stream(conn->socket_type) && !(conn->events & SW_EVENT_WRITE))
            {
                serv->close(serv, conn->session_id, 0);
            }
        }
    }

    uint8_t call_worker_exit_func = 0;

    while (1)
    {
        if (SwooleG.main_reactor->event_num == expect_event_num)
        {
            SwooleG.main_reactor->running = 0;
            SwooleG.running = 0;
        }
        else
        {
            if (serv->onWorkerExit && call_worker_exit_func == 0)
            {
                serv->onWorkerExit(serv, SwooleWG.id);
                call_worker_exit_func = 1;
                continue;
            }
        }
        break;
    }
}

void swWorker_clean(void)
{
    int i;
    swServer *serv = SwooleG.serv;
    swWorker *worker;

    for (i = 0; i < serv->worker_num + SwooleG.task_worker_num; i++)
    {
        worker = swServer_get_worker(serv, i);
        if (SwooleG.main_reactor)
        {
            if (worker->pipe_worker)
            {
                swReactor_wait_write_buffer(SwooleG.main_reactor, worker->pipe_worker);
            }
            if (worker->pipe_master)
            {
                swReactor_wait_write_buffer(SwooleG.main_reactor, worker->pipe_master);
            }
        }
    }
}

/**
 * worker main loop
 */
int swWorker_loop(swFactory *factory, int worker_id)
{
    swServer *serv = factory->ptr;

#ifndef SW_WORKER_USE_SIGNALFD
    SwooleG.use_signalfd = 0;
#elif defined(HAVE_SIGNALFD)
    SwooleG.use_signalfd = 1;
#endif
    //timerfd
#ifdef HAVE_TIMERFD
    SwooleG.use_timerfd = 1;
#endif

    //worker_id
    SwooleWG.id = worker_id;
    SwooleWG.request_count = 0;
    SwooleG.pid = getpid();

    swWorker *worker = swServer_get_worker(serv, worker_id);
    swServer_worker_init(serv, worker);

    SwooleG.main_reactor = sw_malloc(sizeof(swReactor));
    if (SwooleG.main_reactor == NULL)
    {
        swError("[Worker] malloc for reactor failed.");
        return SW_ERR;
    }

    if (swReactor_create(SwooleG.main_reactor, SW_REACTOR_MAXEVENTS) < 0)
    {
        swError("[Worker] create worker_reactor failed.");
        return SW_ERR;
    }
    
    worker->status = SW_WORKER_IDLE;

    int pipe_worker = worker->pipe_worker;

    swSetNonBlock(pipe_worker);
    SwooleG.main_reactor->ptr = serv;
    SwooleG.main_reactor->add(SwooleG.main_reactor, pipe_worker, SW_FD_PIPE | SW_EVENT_READ);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_PIPE, swWorker_onPipeReceive);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_WRITE, swReactor_onWrite);

    /**
     * set pipe buffer size
     */
    int i;
    swConnection *pipe_socket;
    for (i = 0; i < serv->worker_num + SwooleG.task_worker_num; i++)
    {
        worker = swServer_get_worker(serv, i);
        pipe_socket = swReactor_get(SwooleG.main_reactor, worker->pipe_master);
        pipe_socket->buffer_size = SW_MAX_INT;
        pipe_socket = swReactor_get(SwooleG.main_reactor, worker->pipe_worker);
        pipe_socket->buffer_size = SW_MAX_INT;
    }

    swWorker_onStart(serv);

#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd)
    {
        swSignalfd_setup(SwooleG.main_reactor);
    }
#endif
    //main loop
    SwooleG.main_reactor->wait(SwooleG.main_reactor, NULL);
    //clear pipe buffer
    swWorker_clean();
    //worker shutdown
    swWorker_onStop(serv);
    return SW_OK;
}

/**
 * Send data to ReactorThread
 */
int swWorker_send2reactor(swEventData *ev_data, size_t sendn, int session_id)
{
    int ret;
    swServer *serv = SwooleG.serv;
    int _pipe_fd = swWorker_get_send_pipe(serv, session_id, ev_data->info.from_id);

    if (SwooleG.main_reactor)
    {
        ret = SwooleG.main_reactor->write(SwooleG.main_reactor, _pipe_fd, ev_data, sendn);
    }
    else
    {
        ret = swSocket_write_blocking(_pipe_fd, ev_data, sendn);
    }
    return ret;
}

/**
 * receive data from reactor
 */
static int swWorker_onPipeReceive(swReactor *reactor, swEvent *event)
{
    swEventData task;
    swServer *serv = reactor->ptr;
    swFactory *factory = &serv->factory;
    int ret;

    read_from_pipe:

    if (read(event->fd, &task, sizeof(task)) > 0)
    {
        ret = swWorker_onTask(factory, &task);
#ifndef SW_WORKER_RECV_AGAIN
        /**
         * Big package
         */
        if (task.info.type == SW_EVENT_PACKAGE_START)
#endif
        {
            //no data
            if (ret < 0 && errno == EAGAIN)
            {
                return SW_OK;
            }
            else if (ret > 0)
            {
                goto read_from_pipe;
            }
        }
        return ret;
    }
    return SW_ERR;
}

int swWorker_send2worker(swWorker *dst_worker, void *buf, int n, int flag)
{
    int pipefd, ret;

    if (flag & SW_PIPE_MASTER)
    {
        pipefd = dst_worker->pipe_master;
    }
    else
    {
        pipefd = dst_worker->pipe_worker;
    }

    //message-queue
    if (dst_worker->pool->use_msgqueue)
    {
        struct
        {
            long mtype;
            swEventData buf;
        } msg;

        msg.mtype = dst_worker->id + 1;
        memcpy(&msg.buf, buf, n);

        return swMsgQueue_push(dst_worker->pool->queue, (swQueue_data *) &msg, n);
    }

    if ((flag & SW_PIPE_NONBLOCK) && SwooleG.main_reactor)
    {
        return SwooleG.main_reactor->write(SwooleG.main_reactor, pipefd, buf, n);
    }
    else
    {
        ret = swSocket_write_blocking(pipefd, buf, n);
    }

    return ret;
}
