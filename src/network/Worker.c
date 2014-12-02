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
    sw_shm_free(worker->send_shm);
    worker->lock.free(&worker->lock);
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
        swWarn("SIGVTALRM coming")
        ;
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
        onTask: factory->onTask(factory, task);

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
            goto onTask;
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
    int i;
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

    if (swIsWorker())
    {
        int maxfd;
        if (SwooleG.task_worker_num > 0)
        {
            maxfd = SwooleG.task_workers.workers[SwooleG.task_worker_num - 1].pipe_master + 1;
        }
        else
        {
            maxfd = serv->workers[serv->worker_num - 1].pipe_master + 1;
        }
        SwooleWG.fd_map = swArray_new(maxfd, sizeof(swPipe *), 0);
    }

    if (serv->ipc_mode != SW_IPC_MSGQUEUE)
    {
        for (i = 0; i < serv->worker_num + SwooleG.task_worker_num; i++)
        {
            worker = swServer_get_worker(serv, i);
            if (SwooleWG.id == i)
            {
                worker->pipe_object->pipe_used = worker->pipe_worker;
                continue;
            }
            else
            {
                swWorker_free(worker);
            }

            if (SwooleWG.id < serv->worker_num && i < serv->worker_num)
            {
                close(worker->pipe_worker);
            }

            if (swIsWorker())
            {
                swSetNonBlock(worker->pipe_master);
                swArray_store(SwooleWG.fd_map, worker->pipe_master, &worker->pipe_object);
                worker->pipe_object->pipe_used = worker->pipe_master;
            }
        }
    }

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
    swWorker_free(swServer_get_worker(serv, SwooleWG.id));
}

/**
 * worker main loop
 */
int swWorker_loop(swFactory *factory, int worker_id)
{
    swServer *serv = factory->ptr;

    struct
    {
        long pti;
        swEventData req;
    } rdata;
    int n;

#ifdef HAVE_CPU_AFFINITY
    if (serv->open_cpu_affinity == 1)
    {
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);
        CPU_SET(worker_id % SW_CPU_NUM, &cpu_set);
        if (0 != sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set))
        {
            swWarn("pthread_setaffinity_np set failed");
        }
    }
#endif

#ifndef SW_WORKER_USE_SIGNALFD
    SwooleG.use_signalfd = 0;
#endif

    //signal init
    swWorker_signal_init();

    //worker_id
    SwooleWG.id = worker_id;

    int i;

    SwooleWG.buffer_input = sw_malloc(sizeof(swString*) * serv->reactor_num);

    if (SwooleWG.buffer_input == NULL)
    {
        swError("malloc for SwooleWG.buffer_input failed.");
        return SW_ERR;
    }

#ifndef SW_USE_RINGBUFFER
    int buffer_input_size;
    if (serv->open_eof_check || serv->open_length_check || serv->open_http_protocol)
    {
        buffer_input_size = serv->package_max_length;
    }
    else
    {
        buffer_input_size = SW_BUFFER_SIZE_BIG;
    }

    for (i = 0; i < serv->reactor_num; i++)
    {
        SwooleWG.buffer_input[i] = swString_new(buffer_input_size);
        if (SwooleWG.buffer_input[i] == NULL)
        {
            swError("buffer_input init failed.");
            return SW_ERR;
        }
    }
#endif

    if (serv->ipc_mode == SW_IPC_MSGQUEUE)
    {
        //抢占式,使用相同的队列type
        if (serv->dispatch_mode == SW_DISPATCH_QUEUE)
        {
            //这里必须加1
            rdata.pti = serv->worker_num + 1;
        }
        else
        {
            //必须加1
            rdata.pti = worker_id + 1;
        }
    }
    else
    {
        SwooleG.main_reactor = sw_malloc(sizeof(swReactor));
        if (SwooleG.main_reactor == NULL)
        {
            swError("[Worker] malloc for reactor failed.");
            return SW_ERR;
        }
        if (swReactor_auto(SwooleG.main_reactor, SW_REACTOR_MAXEVENTS) < 0)
        {
            swError("[Worker] create worker_reactor failed.");
            return SW_ERR;
        }

        int pipe_worker = serv->workers[worker_id].pipe_worker;

        swSetNonBlock(pipe_worker);
        SwooleG.main_reactor->ptr = serv;
        SwooleG.main_reactor->add(SwooleG.main_reactor, pipe_worker, SW_FD_PIPE);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_PIPE, swWorker_onPipeReceive);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_PIPE | SW_EVENT_WRITE, swPipeUnsock_onWrite);
    }

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

    if (serv->ipc_mode == SW_IPC_MSGQUEUE)
    {
        while (SwooleG.running > 0)
        {
            n = serv->read_queue.out(&serv->read_queue, (swQueue_data *) &rdata, sizeof(rdata.req));
            if (n < 0)
            {
                if (errno == EINTR)
                {
                    if (SwooleG.signal_alarm)
                    {
                        SwooleG.timer.select(&SwooleG.timer);
                    }
                }
                else
                {
                    swWarn("[Worker%ld] read_queue->out() failed. Error: %s [%d]", rdata.pti, strerror(errno), errno);
                }
                continue;
            }
            swWorker_excute(factory, &rdata.req);
        }
    }
    else
    {
#ifdef HAVE_SIGNALFD
        if (SwooleG.use_signalfd)
        {
            swSignalfd_setup(SwooleG.main_reactor);
        }
#endif
        SwooleG.main_reactor->wait(SwooleG.main_reactor, NULL);
    }

    swWorker_onStop(serv);
    return SW_OK;
}

/**
 * Send data to ReactorThread
 */
int swWorker_send2reactor(swEventData_overflow *sdata, size_t sendn, int fd)
{
    int ret, count;
    swServer *serv = SwooleG.serv;

    if (serv->ipc_mode == SW_IPC_MSGQUEUE)
    {
        for (count = 0; count < SW_WORKER_SENDTO_COUNT; count++)
        {
            ret = serv->write_queue.in(&serv->write_queue, (swQueue_data *) sdata, sendn);
            if (ret < 0)
            {
                continue;
            }
            else
            {
                break;
            }
        }
    }
    else
    {
        /**
         * reactor_id: The fd in which the reactor.
         */
        int reactor_id = fd % serv->reactor_num;
        int round_i = (SwooleWG.pipe_round++) % serv->reactor_pipe_num;
        /**
         * pipe_worker_id: The pipe in which worker.
         */
        int pipe_worker_id = reactor_id + (round_i * serv->reactor_num);
        swWorker *dst_worker = &serv->workers[pipe_worker_id];
        ret = dst_worker->pipe_object->write(dst_worker->pipe_object, &sdata->_send, sendn);
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
        /**
         * Big package
         */
        ret = swWorker_excute(factory, &task);
        if (task.info.type == SW_EVENT_PACKAGE_START)
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
