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
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "swoole.h"
#include "Server.h"

static int worker_task_num;

static int swWorker_onPipeReceive(swReactor *reactor, swEvent *event);
static int swRandom(int worker_pti);

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

    if (worker->lock.free)
    {
        worker->lock.free(&worker->lock);
    }
}

void swWorker_signal_init(void)
{
    swSignal_add(SIGHUP, NULL);
    swSignal_add(SIGPIPE, NULL);
    swSignal_add(SIGUSR1, NULL);
    swSignal_add(SIGUSR2, NULL);
    //swSignal_add(SIGINT, swWorker_signal_handler);
    swSignal_add(SIGTERM, swWorker_signal_handler);
    swSignal_add(SIGALRM, swTimer_signal_handler);
    //for test
    swSignal_add(SIGVTALRM, swWorker_signal_handler);
}

void swWorker_signal_handler(int signo)
{
    switch (signo)
    {
    case SIGTERM:
        SwooleG.running = 0;
        break;
    case SIGALRM:
        swTimer_signal_handler(SIGALRM);
        break;
        /**
         * for test
         */
    case SIGVTALRM:
        swWarn("SIGVTALRM coming");
        break;
    case SIGUSR1:
    case SIGUSR2:
        break;
    default:
        break;
    }
}

static int swRandom(int worker_pti)
{
    srand((int) time(0));
    return rand() % 10 * worker_pti;
}

static sw_inline int swWorker_excute(swFactory *factory, swEventData *task)
{
    swServer *serv = factory->ptr;
    swString *package = NULL;
    swConnection *conn = NULL;

    factory->last_from_id = task->info.from_id;
    //worker busy
    serv->workers[SwooleWG.id].status = SW_WORKER_BUSY;

    switch (task->info.type)
    {
    //no buffer
    case SW_EVENT_TCP:
    case SW_EVENT_UDP:
    case SW_EVENT_UNIX_DGRAM:
    //ringbuffer shm package
    case SW_EVENT_PACKAGE:
        do_task:
        conn = swWorker_get_connection(serv, task->info.fd);
        //socket is closed, discard package.
        if (!conn || conn->closed)
        {
            swWarn("received the wrong data from socket#%d", task->info.fd);
            break;
        }

        factory->onTask(factory, task);

        if (!SwooleWG.run_always)
        {
            //only onTask increase the count
            worker_task_num--;
        }
        if (task->info.type == SW_EVENT_PACKAGE_END)
        {
            package->length = 0;
        }
        break;

    //package trunk
    case SW_EVENT_PACKAGE_START:
    case SW_EVENT_PACKAGE_END:
        //input buffer
        package = SwooleWG.buffer_input[task->info.from_id];
        //merge data to package buffer
        memcpy(package->str + package->length, task->data, task->info.len);
        package->length += task->info.len;
        //printf("package[%d]. from_id=%d|data_len=%d|total_length=%d\n", task->info.type, task->info.from_id, task->info.len, package->length);
        //package end
        if (task->info.type == SW_EVENT_PACKAGE_END)
        {
            goto do_task;
        }
        break;

    case SW_EVENT_CLOSE:
        factory->end(factory, task->info.fd);
        break;

    case SW_EVENT_CONNECT:
        serv->onConnect(serv, task->info.fd, task->info.from_id);
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

    //stop
    if (worker_task_num < 0)
    {
        SwooleG.running = 0;
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

    if (serv->onWorkerStart)
    {
        serv->onWorkerStart(serv, SwooleWG.id);
    }
}

void swWorker_onStop(swServer *serv)
{
    swWorker *worker = swServer_get_worker(serv, SwooleWG.id);

    if (serv->onWorkerStop)
    {
        serv->onWorkerStop(serv, SwooleWG.id);
    }
    swWorker_free(worker);
}

/**
 * worker main loop
 */
int swWorker_loop(swFactory *factory, int worker_id)
{
    swServer *serv = factory->ptr;

#ifndef SW_WORKER_USE_SIGNALFD
    SwooleG.use_signalfd = 0;
#endif

    //worker_id
    SwooleWG.id = worker_id;
    SwooleG.pid = getpid();

    //signal init
    swWorker_signal_init();
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

    int pipe_worker = serv->workers[worker_id].pipe_worker;

    swSetNonBlock(pipe_worker);
    SwooleG.main_reactor->ptr = serv;
    SwooleG.main_reactor->add(SwooleG.main_reactor, pipe_worker, SW_FD_PIPE | SW_EVENT_READ);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_PIPE, swWorker_onPipeReceive);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_PIPE | SW_FD_WRITE, swReactor_onWrite);

    if (serv->max_request < 1)
    {
        SwooleWG.run_always = 1;
    }
    else
    {
        worker_task_num = serv->max_request;
        if (worker_task_num > 10)
        {
            worker_task_num += swRandom(worker_id);
        }
    }

    swWorker_onStart(serv);

#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd)
    {
        swSignalfd_setup(SwooleG.main_reactor);
    }
#endif
    SwooleG.main_reactor->wait(SwooleG.main_reactor, NULL);

    swWorker_onStop(serv);
    return SW_OK;
}

/**
 * Send data to ReactorThread
 */
int swWorker_send2reactor(swEventData *ev_data, size_t sendn, int fd)
{
    int ret;
    swServer *serv = SwooleG.serv;
    /**
     * reactor_id: The fd in which the reactor.
     */
    int reactor_id = fd % serv->reactor_num;
    int round_i = (SwooleWG.pipe_round++) % serv->reactor_pipe_num;
    /**
     * pipe_worker_id: The pipe in which worker.
     */
    int pipe_worker_id = reactor_id + (round_i * serv->reactor_num);
    swWorker *worker = swServer_get_worker(serv, pipe_worker_id);

    if (SwooleG.main_reactor)
    {
        ret = SwooleG.main_reactor->write(SwooleG.main_reactor, worker->pipe_worker, ev_data, sendn);
    }
    else
    {
        ret = swSocket_write_blocking(worker->pipe_worker, ev_data, sendn);
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
        ret = swWorker_excute(factory, &task);
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

int swWorker_send2worker(swWorker *dst_worker, uint16_t is_master, void *buf, int n)
{
    int pipefd, ret;
    pipefd = is_master ? dst_worker->pipe_master : dst_worker->pipe_worker;

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

        ret = dst_worker->pool->queue->in(dst_worker->pool->queue, (swQueue_data *) &msg, n);
    }
    //event worker
    else if (SwooleG.main_reactor)
    {
        ret = SwooleG.main_reactor->write(SwooleG.main_reactor, pipefd, buf, n);
    }
    //task worker
    else
    {
        ret = swSocket_write_blocking(pipefd, buf, n);
    }

    return ret;
}
