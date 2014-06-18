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
#include <signal.h>
#include <sys/wait.h>

static int swFactoryProcess_manager_loop(swFactory *factory);
static int swFactoryProcess_manager_start(swFactory *factory);

static int swFactoryProcess_worker_loop(swFactory *factory, int worker_pti);
static int swFactoryProcess_worker_spawn(swFactory *factory, int worker_pti);
static void swFactoryProcess_worker_signal_init(void);
static void swFactoryProcess_worker_signal_handler(int signo);

static int swFactoryProcess_writer_start(swFactory *factory);
static int swFactoryProcess_writer_loop_queue(swThreadParam *param);

#if SW_USE_WRITER_THREAD
static int swFactoryProcess_writer_loop_unsock(swThreadParam *param);
#endif

static int swFactoryProcess_worker_onPipeReceive(swReactor *reactor, swEvent *event);
static int swFactoryProcess_notify(swFactory *factory, swEvent *event);
static int swFactoryProcess_dispatch(swFactory *factory, swEventData *buf);
static int swFactoryProcess_finish(swFactory *factory, swSendData *data);

SWINLINE static int swFactoryProcess_schedule(swFactoryProcess *object, swEventData *data);

static int worker_task_num = 0;
static int manager_worker_reloading = 0;
static int manager_reload_flag = 0;

int swFactoryProcess_create(swFactory *factory, int writer_num, int worker_num)
{
	swFactoryProcess *object;
	swServer *serv = SwooleG.serv;
	object = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swFactoryProcess));
	if (object == NULL)
	{
		swWarn("[Master] malloc[object] failed");
		return SW_ERR;
	}
	serv->writer_threads = SwooleG.memory_pool->alloc(SwooleG.memory_pool, serv->reactor_num * sizeof(swWriterThread));
	if (serv->writer_threads == NULL)
	{
		swWarn("[Master] malloc[object->writers] failed");
		return SW_ERR;
	}
	object->writer_pti = 0;

	object->workers = SwooleG.memory_pool->alloc(SwooleG.memory_pool, serv->worker_num * sizeof(swWorker));
	if (object->workers == NULL)
	{
		swWarn("[Master] malloc[object->workers] failed");
		return SW_ERR;
	}

	factory->object = object;
	factory->dispatch = swFactoryProcess_dispatch;
	factory->finish = swFactoryProcess_finish;
	factory->start = swFactoryProcess_start;
	factory->notify = swFactoryProcess_notify;
	factory->shutdown = swFactoryProcess_shutdown;
	factory->end = swFactoryProcess_end;
	factory->onTask = NULL;
	factory->onFinish = NULL;

	return SW_OK;
}

int swFactoryProcess_shutdown(swFactory *factory)
{
	swFactoryProcess *object = factory->object;
	swServer *serv = SwooleG.serv;
	int i;
	//kill manager process
	kill(SwooleGS->manager_pid, SIGTERM);
	//kill all child process
	for (i = 0; i < serv->worker_num; i++)
	{
		swTrace("[Main]kill worker processor");
		kill(object->workers[i].pid, SIGTERM);
	}
	if (serv->ipc_mode == SW_IPC_MSGQUEUE)
	{
		object->rd_queue.free(&object->rd_queue);
		object->wt_queue.free(&object->wt_queue);
	}
	//close pipes
	return SW_OK;
}

int swFactoryProcess_start(swFactory *factory)
{
	if (swFactory_check_callback(factory) < 0)
	{
		swWarn("swFactory_check_callback fail");
		return SW_ERR;
	}

	swServer *serv = factory->ptr;
	swFactoryProcess *object = factory->object;
	object->workers_status = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(char)*serv->worker_num);

	//worler idle or busy
	if (object->workers_status == NULL)
	{
		swWarn("alloc for worker_status fail");
		return SW_ERR;
	}

	//保存下指针，需要和reactor做绑定
	serv->workers = object->workers;

	swWorker *worker;
	int i;

	void *worker_shm = sw_shm_calloc(serv->worker_num, serv->response_max_length);
	if (worker_shm == NULL)
	{
		swWarn("malloc for worker->shm failed.");
		return SW_ERR;
	}

	swPipe *worker_notify = sw_calloc(serv->worker_num, sizeof(swPipe));
	if (worker_shm == NULL)
	{
		swWarn("malloc for worker->notify failed.");
		return SW_ERR;
	}

	for (i = 0; i < serv->worker_num; i++)
	{
		worker = swServer_get_worker(serv, i);
		worker->notify = &(worker_notify[i]);
		worker->store.ptr = worker_shm + (i * serv->response_max_length);
		worker->store.lock = 0;

		if (swPipeNotify_auto(worker->notify, 1, 0))
		{
			return SW_ERR;
		}
	}

	//必须先启动manager进程组，否则会带线程fork
	if (swFactoryProcess_manager_start(factory) < 0)
	{
		swWarn("swFactoryProcess_manager_start fail");
		return SW_ERR;
	}

	if (serv->ipc_mode == SW_IPC_MSGQUEUE)
	{
		//tcp & message queue require writer pthread
		if (serv->have_tcp_sock == 1)
		{
			int ret = swFactoryProcess_writer_start(factory);
			if (ret < 0)
			{
				return SW_ERR;
			}
		}
	}

	//主进程需要设置为直写模式
	factory->finish = swFactory_finish;
	return SW_OK;
}

int swFactoryProcess_worker_excute(swFactory *factory, swEventData *task)
{
	swServer *serv = factory->ptr;
	swFactoryProcess *object = factory->object;
	swString *package;

	factory->last_from_id = task->info.from_id;

	//worker busy
	object->workers_status[SwooleWG.id] = SW_WORKER_BUSY;

	switch(task->info.type)
	{
	//no buffer
	case SW_EVENT_TCP:
	case SW_EVENT_UDP:
	case SW_EVENT_UNIX_DGRAM:

	//ringbuffer shm package
	case SW_EVENT_PACKAGE:
		onTask:
		factory->onTask(factory, task);

		if (!SwooleWG.run_always)
		{
			//only onTask increase the count
			worker_task_num --;
		}

		if (task->info.type == SW_EVENT_PACKAGE_END)
		{
			package->length = 0;
		}
		break;

	//package trunk
	case SW_EVENT_PACKAGE_START:
	case SW_EVENT_PACKAGE_END:

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
		serv->onClose(serv, task->info.fd, task->info.from_id);
		break;
	case SW_EVENT_CONNECT:
		serv->onConnect(serv, task->info.fd, task->info.from_id);
		break;
	case SW_EVENT_FINISH:
		serv->onFinish(serv, task);
		break;
	default:
		swWarn("[Worker] error event[type=%d]", (int)task->info.type);
		break;
	}

	//worker idle
	object->workers_status[SwooleWG.id] = SW_WORKER_IDLE;

	//stop
	if (worker_task_num < 0)
	{
		SwooleG.running = 0;
	}
	return SW_OK;
}

//create worker child proccess
static int swFactoryProcess_manager_start(swFactory *factory)
{
	swFactoryProcess *object = factory->object;
	int i, pid, ret;
	int reactor_pti;
	swServer *serv = factory->ptr;

	if (serv->ipc_mode == SW_IPC_MSGQUEUE)
	{
		//读数据队列
		if (swQueueMsg_create(&object->rd_queue, 1, serv->message_queue_key, 1) < 0)
		{
			swError("[Master] swPipeMsg_create[In] fail. Error: %s [%d]", strerror(errno), errno);
			return SW_ERR;
		}
		//为TCP创建写队列
		if (serv->have_tcp_sock == 1)
		{
			//写数据队列
			if (swQueueMsg_create(&object->wt_queue, 1, serv->message_queue_key + 1, 1) < 0)
			{
				swError("[Master] swPipeMsg_create[out] fail. Error: %s [%d]", strerror(errno), errno);
				return SW_ERR;
			}
		}
	}
	else
	{
		object->pipes = sw_calloc(serv->worker_num, sizeof(swPipe));
		if (object->pipes == NULL)
		{
			swError("malloc[worker_pipes] fail. Error: %s [%d]", strerror(errno), errno);
			return SW_ERR;
		}
		//worker进程的pipes
		for (i = 0; i < serv->worker_num; i++)
		{
			if (swPipeUnsock_create(&object->pipes[i], 1, SOCK_DGRAM) < 0)
			{
				swError("create unix socket[1] fail");
				return SW_ERR;
			}
			object->workers[i].pipe_master = object->pipes[i].getFd(&object->pipes[i], 1);
			object->workers[i].pipe_worker = object->pipes[i].getFd(&object->pipes[i], 0);
		}
	}

	if (SwooleG.task_worker_num > 0)
	{
		key_t msgqueue_key = 0;
		if (SwooleG.task_ipc_mode > 0)
		{
			msgqueue_key =  serv->message_queue_key + 2;
		}
		if (swProcessPool_create(&SwooleG.task_workers, SwooleG.task_worker_num, serv->max_request, msgqueue_key)< 0)
		{
			swWarn("[Master] create task_workers fail");
			return SW_ERR;
		}
		//设置指针和回调函数
		SwooleG.task_workers.ptr = serv;
		SwooleG.task_workers.onTask = swTaskWorker_onTask;
		if (serv->onWorkerStart != NULL)
		{
			SwooleG.task_workers.onWorkerStart = swTaskWorker_onWorkerStart;
		}
	}
	pid = fork();
	switch (pid)
	{
	//创建manager进程
	case 0:
		//创建子进程
		for (i = 0; i < serv->worker_num; i++)
		{
			//close(worker_pipes[i].pipes[0]);
			reactor_pti = (i % serv->writer_num);
			object->workers[i].reactor_id = reactor_pti;
			pid = swFactoryProcess_worker_spawn(factory, i);
			if (pid < 0)
			{
				swError("Fork worker process fail");
				return SW_ERR;
			}
			else
			{
				object->workers[i].pid = pid;
			}
		}
		/**
		 * create task worker pool
		 */
		if (SwooleG.task_worker_num > 0)
		{
			swProcessPool_start(&SwooleG.task_workers);
		}
		//标识为管理进程
		SwooleG.process_type = SW_PROCESS_MANAGER;
		ret = swFactoryProcess_manager_loop(factory);
		exit(ret);
		break;
		//主进程
	default:
		SwooleGS->manager_pid = pid;
		break;
	case -1:
		swError("[swFactoryProcess_worker_start]fork manager process fail");
		return SW_ERR;
	}
	return SW_OK;
}

static void swManagerSignalHanlde(int sig)
{
	switch (sig)
	{
	case SIGUSR1:
		if (manager_worker_reloading == 0)
		{
			manager_worker_reloading = 1;
			manager_reload_flag = 0;
		}
		break;
	default:
		break;
	}
}

static int swFactoryProcess_manager_loop(swFactory *factory)
{
	int pid, new_pid;
	int i;
	int reload_worker_i = 0;
	int ret;
	int worker_exit_code;

	SwooleG.use_signalfd = 0;
	SwooleG.use_timerfd = 0;

	swFactoryProcess *object = factory->object;
	swServer *serv = factory->ptr;
	swWorker *reload_workers;

	if (serv->onManagerStart)
	{
		serv->onManagerStart(serv);
	}

	reload_workers = sw_calloc(serv->worker_num, sizeof(swWorker));
	if (reload_workers == NULL)
	{
		swError("[manager] malloc[reload_workers] failed");
		return SW_ERR;
	}

	//for reload
	swSignal_add(SIGUSR1, swManagerSignalHanlde);

	while (SwooleG.running > 0)
	{
		pid = wait(&worker_exit_code);
		swTrace("[manager] worker stop.pid=%d\n", pid);
		if (pid < 0)
		{
			if (manager_worker_reloading == 0)
			{
				swTrace("[Manager] wait failed. Error: %s [%d]", strerror(errno), errno);
			}
			else if (manager_reload_flag == 0)
			{
				memcpy(reload_workers, object->workers, sizeof(swWorker) * serv->worker_num);
				manager_reload_flag = 1;
				goto kill_worker;
			}
		}
		if (SwooleG.running == 1)
		{
			for (i = 0; i < serv->worker_num; i++)
			{
				//对比pid
				if (pid != object->workers[i].pid)
				{
					continue;
				}
				else
				{
					if (serv->onWorkerError!=NULL && WEXITSTATUS(worker_exit_code) > 0)
					{
						serv->onWorkerError(serv, i, pid, WEXITSTATUS(worker_exit_code));
					}
					pid = 0;
					new_pid = swFactoryProcess_worker_spawn(factory, i);
					if (new_pid < 0)
					{
						swWarn("Fork worker process failed. Error: %s [%d]", strerror(errno), errno);
						return SW_ERR;
					}
					else
					{
						object->workers[i].pid = new_pid;
					}
				}
			}

			//task worker
			if(pid > 0)
			{
				swWorker *exit_worker = swHashMap_find_int(&SwooleG.task_workers.map, pid);
				if (exit_worker != NULL)
				{
					swProcessPool_spawn(exit_worker);
				}
			}
		}
		//reload worker
		kill_worker: if (manager_worker_reloading == 1)
		{
			//reload finish
			if (reload_worker_i >= serv->worker_num)
			{
				manager_worker_reloading = 0;
				reload_worker_i = 0;
				continue;
			}
			ret = kill(reload_workers[reload_worker_i].pid, SIGTERM);
			if (ret < 0)
			{
				swWarn("[Manager]kill failed, pid=%d. Error: %s [%d]", reload_workers[reload_worker_i].pid, strerror(errno), errno);
				continue;
			}
			reload_worker_i++;
		}
	}
	sw_free(reload_workers);
	if (serv->onManagerStop)
	{
		serv->onManagerStop(serv);
	}
	return SW_OK;
}

static int swFactoryProcess_worker_spawn(swFactory *factory, int worker_pti)
{
	int pid, ret;

	pid = fork();
	if (pid < 0)
	{
		swWarn("Fork Worker failed. Error: %s [%d]", strerror(errno), errno);
		return SW_ERR;
	}
	//worker child processor
	else if (pid == 0)
	{
		//标识为worker进程
		SwooleG.process_type = SW_PROCESS_WORKER;
		ret = swFactoryProcess_worker_loop(factory, worker_pti);
		exit(ret);
	}
	//parent,add to writer
	else
	{
		return pid;
	}
}

int swFactoryProcess_end(swFactory *factory, swDataHead *event)
{
	swServer *serv = factory->ptr;
	swSendData _send;

	bzero(&_send, sizeof(_send));

	_send.info.fd = event->fd;
	/**
	 * length == 0, close the connection
	 */
	_send.info.len = 0;

	/**
	 * passive or initiative
	 */
	_send.info.type = event->type;

	swConnection *conn = swServer_get_connection(serv, _send.info.fd);
	if (conn == NULL || conn->active == 0)
	{
		swWarn("can not close. Connection[%d] not found.", _send.info.fd);
		return SW_ERR;
	}
	event->from_id = conn->from_id;
	return swFactoryProcess_finish(factory, &_send);
}
/**
 * worker: send to client
 */
int swFactoryProcess_finish(swFactory *factory, swSendData *resp)
{
	int ret, sendn, count;
	swFactoryProcess *object = factory->object;
	swServer *serv = factory->ptr;
	int fd = resp->info.fd;

	//unix dgram
	if (resp->info.type == SW_EVENT_UNIX_DGRAM)
	{
		socklen_t len;
		struct sockaddr_un addr_un;
		int from_sock = resp->info.from_fd;

		addr_un.sun_family = AF_UNIX;
		memcpy(addr_un.sun_path, resp->sun_path, resp->sun_path_len);
		len = sizeof(addr_un);
		ret = swSendto(from_sock, resp->data, resp->info.len, 0, (struct sockaddr *) &addr_un, len);
		goto finish;
	}
	//UDP pacakge
	else if (resp->info.type == SW_EVENT_UDP || resp->info.type == SW_EVENT_UDP6)
	{
		ret = swServer_udp_send(serv, resp);
		goto finish;
	}

	//swQueue_data for msg queue
	struct
	{
		long pti;
		swEventData _send;
	} sdata;

	//for message queue
	sdata.pti = (SwooleWG.id % serv->writer_num) + 1;

	swConnection *conn = swServer_get_connection(serv, fd);
	if (conn == NULL || conn->active == 0)
	{
		swWarn("connection[%d] not found.", fd);
		return SW_ERR;
	}

	sdata._send.info.fd = fd;
	sdata._send.info.type = resp->info.type;
	swWorker *worker = swServer_get_worker(serv, SwooleWG.id);

	/**
	 * Big response, use shared memory
	 */
	if (resp->length > 0)
	{
		int64_t wait_reactor;

		/**
		 * Storage is in use right now, wait notify.
		 */
		if (worker->store.lock == 1)
		{
			worker->notify->read(worker->notify, &wait_reactor, sizeof(wait_reactor));
		}
		swPackage_response response;

		response.length = resp->length;
		response.worker_id = SwooleWG.id;

		sdata._send.info.from_fd = SW_RESPONSE_BIG;
		sdata._send.info.len = sizeof(response);

		memcpy(sdata._send.data, &response, sizeof(response));

		/**
		 * Lock the worker storage
		 */
		worker->store.lock = 1;
		memcpy(worker->store.ptr, resp->data, resp->length);
	}
	else
	{
		//copy data
		memcpy(sdata._send.data, resp->data, resp->info.len);

		sdata._send.info.len = resp->info.len;
		sdata._send.info.from_fd = SW_RESPONSE_SMALL;
	}

#if SW_REACTOR_SCHEDULE == 2
	sdata._send.info.from_id = fd % serv->reactor_num;
#else
	sdata._send.info.from_id = conn->from_id;
#endif

	sendn = sdata._send.info.len + sizeof(resp->info);

	//swWarn("send: sendn=%d|type=%d|content=%s", sendn, resp->info.type, resp->data);
	swTrace("[Worker]wt_queue[%ld]->in| fd=%d", sdata.pti, fd);

	for (count = 0; count < SW_WORKER_SENDTO_COUNT; count++)
	{
		if (serv->ipc_mode == SW_IPC_MSGQUEUE)
		{
			ret = object->wt_queue.in(&object->wt_queue, (swQueue_data *)&sdata, sendn);
		}
		else
		{
			int pipe_i;
			swReactor *reactor = &(serv->reactor_threads[sdata._send.info.from_id].reactor);
			if (serv->reactor_pipe_num > 1)
			{
				pipe_i = fd % serv->reactor_pipe_num + reactor->id;
			}
			else
			{
				pipe_i = reactor->id;
			}
			//swWarn("send to reactor. fd=%d|pipe_i=%d|reactor_id=%d|reactor_pipe_num=%d", fd, pipe_i, conn->from_id, serv->reactor_pipe_num);
			ret = write(object->workers[pipe_i].pipe_worker, &sdata._send, sendn);
		}
		//printf("wt_queue->in: fd=%d|from_id=%d|data=%s|ret=%d|errno=%d\n", sdata._send.info.fd, sdata._send.info.from_id, sdata._send.data, ret, errno);
		if (ret >= 0)
		{
			break;
		}
		else if (errno == EINTR)
		{
			continue;
		}
		else if (errno == EAGAIN)
		{
			swYield();
		}
		else
		{
			break;
		}
	}
	finish:
	if (ret < 0)
	{
		swWarn("sendto to reactor failed. Error: %s [%d]", strerror(errno), errno);
	}
	return ret;
}

static int swRandom(int worker_pti)
{
	srand((int)time(0));
	return rand()%10 * worker_pti;
}

static void swFactoryProcess_worker_signal_init(void)
{
	swSignal_add(SIGHUP, NULL);
	swSignal_add(SIGPIPE, NULL);
	swSignal_add(SIGUSR1, NULL);
	swSignal_add(SIGUSR2, NULL);
	swSignal_add(SIGTERM, swFactoryProcess_worker_signal_handler);
	swSignal_add(SIGALRM, swTimer_signal_handler);
	//for test
	swSignal_add(SIGVTALRM, swFactoryProcess_worker_signal_handler);
}

static void swFactoryProcess_worker_signal_handler(int signo)
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

/**
 * worker main loop
 */
static int swFactoryProcess_worker_loop(swFactory *factory, int worker_pti)
{
	swFactoryProcess *object = factory->object;
	swServer *serv = factory->ptr;

	struct
	{
		long pti;
		swEventData req;
	} rdata;
	int n;

	int pipe_rd = object->workers[worker_pti].pipe_worker;

#ifdef HAVE_CPU_AFFINITY
	if (serv->open_cpu_affinity == 1)
	{
		cpu_set_t cpu_set;
		CPU_ZERO(&cpu_set);
		CPU_SET(worker_pti % SW_CPU_NUM, &cpu_set);
		if (0 != sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set))
		{
			swWarn("pthread_setaffinity_np set failed");
		}
	}
#endif

	//signal init
	swFactoryProcess_worker_signal_init();

	//worker_id
	SwooleWG.id = worker_pti;

#ifndef SW_USE_RINGBUFFER
	int i;
	//for open_check_eof and  open_check_length
	if (serv->open_eof_check || serv->open_length_check)
	{
		SwooleWG.buffer_input = sw_malloc(sizeof(swString*) * serv->reactor_num);
		if (SwooleWG.buffer_input == NULL)
		{
			swError("malloc for SwooleWG.buffer_input failed.");
			return SW_ERR;
		}
		for (i = 0; i < serv->reactor_num; i++)
		{
			SwooleWG.buffer_input[i] = swString_new(serv->buffer_input_size);
			if (SwooleWG.buffer_input[i] == NULL)
			{
				swError("buffer_input init failed.");
				return SW_ERR;
			}
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
			rdata.pti = worker_pti + 1;
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
		swSetNonBlock(pipe_rd);
		SwooleG.main_reactor->ptr = serv;
		SwooleG.main_reactor->add(SwooleG.main_reactor, pipe_rd, SW_FD_PIPE);
		SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_PIPE, swFactoryProcess_worker_onPipeReceive);

#ifdef HAVE_SIGNALFD
		if (SwooleG.use_signalfd)
		{
			swSignalfd_setup(SwooleG.main_reactor);
		}
#endif

	}

	if (factory->max_request < 1)
	{
		SwooleWG.run_always = 1;
	}
	else
	{
		worker_task_num = factory->max_request;
		worker_task_num += swRandom(worker_pti);
	}

	//worker start
	if (serv->onWorkerStart != NULL)
	{
		serv->onWorkerStart(serv, worker_pti);
	}

	if (serv->ipc_mode == SW_IPC_MSGQUEUE)
	{
		while (SwooleG.running > 0)
		{
			n = object->rd_queue.out(&object->rd_queue, (swQueue_data *)&rdata, sizeof(rdata.req));
			if (n < 0)
			{
				if (errno == EINTR)
				{
					if (SwooleG.signal_alarm && serv->onTimer)
					{
						swTimer_select(&SwooleG.timer);
						SwooleG.signal_alarm = 0;
					}
				}
				else
				{
					swWarn("[Worker]rd_queue[%ld]->out wait failed. Error: %s [%d]", rdata.pti, strerror(errno), errno);
				}
				continue;
			}
			swFactoryProcess_worker_excute(factory, &rdata.req);
		}
	}
	else
	{
		struct timeval timeo;
		timeo.tv_sec = SW_REACTOR_TIMEO_SEC;
		timeo.tv_usec = SW_REACTOR_TIMEO_USEC;
		SwooleG.main_reactor->wait(SwooleG.main_reactor, &timeo);
	}

	if (serv->onWorkerStop != NULL)
	{
		//worker shutdown
		serv->onWorkerStop(serv, worker_pti);
	}
	swTrace("[Worker]max request");
	return SW_OK;
}

/**
 * for msg queue
 * 头部放一个long让msg queue可以直接插入到消息队列中
 */
static __thread struct
{
	long pti;
	swDataHead _send;
} sw_notify_data;

/**
 * 主进程通知worker进程
 */
int swFactoryProcess_notify(swFactory *factory, swDataHead *ev)
{
	memcpy(&sw_notify_data._send, ev, sizeof(swDataHead));
	sw_notify_data._send.len = 0;
	return swFactoryProcess_send2worker(factory, (swEventData *) &sw_notify_data._send, -1);
}

SWINLINE static int swFactoryProcess_schedule(swFactoryProcess *object, swEventData *data)
{
	swServer *serv = SwooleG.serv;
	int target_worker_id = 0;

	//轮询
	if (serv->dispatch_mode == SW_DISPATCH_ROUND)
	{
		target_worker_id = (object->worker_pti++) % serv->worker_num;
	}
	//使用fd取摸来散列
	else if (serv->dispatch_mode == SW_DISPATCH_FDMOD)
	{
		//Fixed #48. 替换一下顺序
		//udp use remote port
		if (data->info.type == SW_EVENT_UDP || data->info.type == SW_EVENT_UDP6 || data->info.type == SW_EVENT_UNIX_DGRAM)
		{
			target_worker_id = ((uint16_t) data->info.from_id) % serv->worker_num;
		}
		else
		{
			target_worker_id = data->info.fd % serv->worker_num;
		}
	}
	//使用抢占式队列(IPC消息队列)分配
	else
	{
		if (serv->ipc_mode == SW_IPC_MSGQUEUE)
		{
			//msgsnd参数必须>0
			//worker进程中正确的mtype应该是pti + 1
			target_worker_id = serv->worker_num;
		}
		else
		{
			int i;
			atomic_t *round = &SwooleTG.worker_round_i;
			for (i = 0; i < serv->worker_num; i++)
			{
				sw_atomic_fetch_add(round, 1);
				target_worker_id = (*round) % serv->worker_num;

				if (object->workers_status[target_worker_id] == SW_WORKER_IDLE)
				{
					break;
				}
			}
			swTrace("schedule=%d|round=%d\n", target_worker_id, *round);
		}
	}
	return target_worker_id;
}

/**
 * 主进程向worker进程发送数据
 * @param worker_id 发到指定的worker进程
 */
int swFactoryProcess_send2worker(swFactory *factory, swEventData *data, int worker_id)
{
	swFactoryProcess *object = factory->object;
	swServer *serv = factory->ptr;
	int pti = 0;
	int ret;
	int send_len = sizeof(data->info) + data->info.len;

	if (worker_id < 0)
	{
		if (SwooleTG.factory_lock_target)
		{
			if (SwooleTG.factory_target_worker < 0)
			{
				pti = swFactoryProcess_schedule(object, data);
				SwooleTG.factory_target_worker = pti;
			}
			else
			{
				pti = SwooleTG.factory_target_worker;
			}
		}
		else
		{
			pti = swFactoryProcess_schedule(object, data);
		}
	}
	//指定了worker_id
	else
	{
		pti = worker_id;
	}

	if (serv->ipc_mode == SW_IPC_MSGQUEUE)
	{
		//insert to msg queue
		swQueue_data *in_data = (swQueue_data *) ((void *) data - sizeof(long));

		//加1防止id为0的worker进程出错
		in_data->mtype = pti + 1;
		ret = object->rd_queue.in(&object->rd_queue, in_data, send_len);
		//swTrace("[Master]rd_queue[%ld]->in: fd=%d|type=%d|len=%d", in_data->mtype, info->fd, info->type, info->len);
	}
	else
	{
		//send to unix sock
		//swWarn("pti=%d|from_id=%d|data_len=%d|swDataHead_size=%ld", pti, data->info.from_id, send_len, sizeof(swDataHead));
		ret = swWrite(object->workers[pti].pipe_master, (void *) data, send_len);
	}
	return ret;
}

int swFactoryProcess_dispatch(swFactory *factory, swEventData *data)
{
	swFactory *_factory = factory;
	return swFactoryProcess_send2worker(_factory, data, -1);
}

static int swFactoryProcess_writer_start(swFactory *factory)
{
	swServer *serv = SwooleG.serv;
	swThreadParam *param;
	int i;
	pthread_t pidt;
	swThreadStartFunc thread_main;

	if (serv->ipc_mode == SW_IPC_MSGQUEUE)
	{
		thread_main = (swThreadStartFunc) swFactoryProcess_writer_loop_queue;
	}
	else
	{
#if SW_USE_WRITER_THREAD
		thread_main = (swThreadStartFunc) swFactoryProcess_writer_loop_unsock;
#else
		swError("never get here");
#endif
	}

	for (i = 0; i < serv->writer_num; i++)
	{
		param = sw_malloc(sizeof(swPipe));
		if (param == NULL)
		{
			swError("malloc fail\n");
			return SW_ERR;
		}
		param->object = factory;
		param->pti = i;
		if (pthread_create(&pidt, NULL, thread_main, (void *) param) < 0)
		{
			swTrace("pthread_create fail\n");
			return SW_ERR;
		}
		pthread_detach(pidt);
		serv->writer_threads[i].ptid = pidt;
		SW_START_SLEEP;
	}
	return SW_OK;
}

/**
 * Use message queue ipc
 */
int swFactoryProcess_writer_loop_queue(swThreadParam *param)
{
	swFactory *factory = param->object;
	swFactoryProcess *object = factory->object;
	swEventData *resp;

	int pti = param->pti;
	swQueue_data sdata;
	//必须加1,msg_type必须不能为0
	sdata.mtype = pti + 1;

	swSignal_none();
	while (SwooleG.running > 0)
	{
		swTrace("[Writer]wt_queue[%ld]->out wait", sdata.mtype);
		if (object->wt_queue.out(&object->wt_queue, &sdata, sizeof(sdata.mdata)) < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}
			swWarn("[writer]wt_queue->out fail.Error: %s [%d]", strerror(errno), errno);
		}
		else
		{
			int ret;
			resp = (swEventData *) sdata.mdata;

			//Close
			//TODO: thread safe, should close in reactor thread.
			if (resp->info.len == 0)
			{
				close_fd:
				swConnection_close(SwooleG.serv, resp->info.fd, 0);
				continue;
			}
			else
			{
				if (resp->info.type == SW_EVENT_SENDFILE)
				{
					ret = swConnection_sendfile_blocking(resp->info.fd, resp->data, 1000 * SW_WRITER_TIMEOUT);
				}
				else
				{
					ret = swConnection_send_blocking(resp->info.fd, resp->data, resp->info.len, 1000 * SW_WRITER_TIMEOUT);
				}

				if (ret < 0)
				{
					switch (swConnection_error(resp->info.fd, errno))
					{
					case SW_ERROR:
						swWarn("send to fd[%d] failed. Error: %s[%d]", resp->info.fd, strerror(errno), errno);
						break;
					case SW_CLOSE:
						goto close_fd;
					default:
						break;
					}
				}
			}
		}
	}
	pthread_exit((void *) param);
	return SW_OK;
}

/**
 * receive data from reactor
 */
static int swFactoryProcess_worker_onPipeReceive(swReactor *reactor, swEvent *event)
{
	swEventData task;
	swServer *serv = reactor->ptr;
	swFactory *factory = &serv->factory;

	if (read(event->fd, &task, sizeof(task)) > 0)
	{
		return swFactoryProcess_worker_excute(factory, &task);
	}
	return SW_ERR;
}

#if SW_USE_WRITER_THREAD
/**
 * 使用Unix Socket通信
 */
int swFactoryProcess_writer_loop_unsock(swThreadParam *param)
{
	swFactory *factory = param->object;
	swFactoryProcess *object = factory->object;
	int pti = param->pti;
	swReactor *reactor = &(object->writers[pti].reactor);

	struct timeval tmo;
	tmo.tv_sec = 3;
	tmo.tv_usec = 0;

	reactor->factory = factory;
	reactor->id = pti;
	if (swReactorSelect_create(reactor) < 0)
	{
		swWarn("swReactorSelect_create fail");
		pthread_exit((void *) param);
	}
	swSingalNone();
	reactor->setHandle(reactor, SW_FD_PIPE, swReactorThread_onPipeReceive);
	reactor->wait(reactor, &tmo);
	reactor->free(reactor);
	pthread_exit((void *) param);
	return SW_OK;
}
#endif

