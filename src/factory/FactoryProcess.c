#include "swoole.h"
#include "Server.h"
#include <signal.h>
#include <sys/wait.h>

typedef struct _swPipes
{
	int pipes[2];
} swPipes;

typedef struct _swController
{
	struct _swController *next, *prev;
	int id;
	int pid;
	int pipe_fd;
	int (*onEvent)(swFactory *serv, swEventData *event);
} swController;

static int swFactoryProcess_manager_loop(swFactory *factory);
static int swFactoryProcess_worker_start(swFactory *factory);
static int swFactoryProcess_worker_loop(swFactory *factory, int c_pipe, int worker_pti);
static int swFactoryProcess_worker_spawn(swFactory *factory, int writer_pti, int worker_pti);
static int swFactoryProcess_writer_start(swFactory *factory);

static int swFactoryProcess_writer_loop(swThreadParam *param);
static int swFactoryProcess_writer_loop_ex(swThreadParam *param);
static int swFactoryProcess_writer_receive(swReactor *, swEvent *);
static int swFactoryProcess_send2worker(swFactory *factory, swEventData *data, int send_len);

static int swFactoryProcess_controller(swFactory *factory, swEventCallback cb);
static int swFactoryProcess_controller_start(swFactory *factory);
static int swFactoryProcess_controller_spawn(swFactory *factory, swController *controller);
static int swFactoryProcess_controller_receive(swReactor *reactor, swDataHead *ev);
static int swFactoryProcess_controller_loop(swFactory *factory, swController *controller);

static int swFactoryProcess_notify(swFactory *factory, swEvent *event);
static int swFactoryProcess_dispatch(swFactory *factory, swEventData *buf);
static int swFactoryProcess_finish(swFactory *factory, swSendData *data);
static int swFactoryProcess_event(swFactory *factory, int controller_id, swEventData *data);//向某个worker进程或controller发送数据

static int c_worker_pipe = 0; //Current Proccess Worker's pipe
static int c_worker_pti = 0; //Current Proccess Worker's id
static int c_writer_pti = 0; //Current Proccess writer's id

static int manager_worker_reloading = 0;
static int manager_reload_flag = 0;
static swController *manager_controller_list;
static swPipes *manager_controller_pipes;
static int manager_controller_count = 0;

int swFactoryProcess_create(swFactory *factory, int writer_num, int worker_num)
{
	swFactoryProcess *object;
	object = sw_malloc(sizeof(swFactoryProcess));
	if (object == NULL)
	{
		swWarn("[swFactoryProcess_create] malloc[0] fail");
		return SW_ERR;
	}
	object->writers = sw_calloc(writer_num, sizeof(swThreadWriter));
	if (object->writers == NULL)
	{
		swWarn("[Main] malloc[object->writers] fail");
		return SW_ERR;
	}
	object->writer_num = writer_num;
	object->writer_pti = 0;

	object->workers = sw_calloc(worker_num, sizeof(swWorkerChild));
	if (object->workers == NULL)
	{
		swWarn("[Main] malloc[object->workers] fail");
		return SW_ERR;
	}
	object->worker_num = worker_num;

	factory->running = 1;
	factory->object = object;
	factory->dispatch = swFactoryProcess_dispatch;
	factory->finish = swFactoryProcess_finish;
	factory->start = swFactoryProcess_start;
	factory->notify = swFactoryProcess_notify;
	factory->controller = swFactoryProcess_controller;
	factory->event = swFactoryProcess_event;
	factory->shutdown = swFactoryProcess_shutdown;
	factory->end = swFactoryProcess_end;

	factory->onTask = NULL;
	factory->onFinish = NULL;
	return SW_OK;
}

/**
 * 返回controller的ID
 */
int swFactoryProcess_controller(swFactory *factory, swEventCallback cb)
{
	swFactoryProcess *object = factory->object;
	swServer *serv = factory->ptr;
	swController *controller = sw_malloc(sizeof(swController));
	if (controller == NULL)
	{
		swWarn("malloc fail\n");
		return SW_ERR;
	}
	controller->onEvent = cb;
	LL_APPEND(manager_controller_list, controller);
	controller->id = manager_controller_count;
	manager_controller_count ++;
	return controller->id;
}

int swFactoryProcess_event(swFactory *factory, int controller_id, swEventData *data)
{
	swFactoryProcess *object = factory->object;
	int pipe_fd, ret;
	int send_len = sizeof(data->info) + data->info.len;

	//这是一个controller
	if(controller_id > manager_controller_count)
	{
		swWarn("controller_id > manager_controller_count");
		return SW_ERR;
	}
	pipe_fd = manager_controller_pipes[controller_id].pipes[0];
	ret = swWrite(pipe_fd, (char *)data, send_len);
	return (ret < 0) ? SW_ERR : SW_OK;
}

int swFactoryProcess_controller_start(swFactory *factory)
{
	int i, pid;
	swController *controller;

	//循环fork
	LL_FOREACH(manager_controller_list, controller)
	{
		controller->pipe_fd = manager_controller_pipes[controller->id].pipes[1];
		pid = swFactoryProcess_controller_spawn(factory, controller);
		if(pid < 0)
		{
			swError("Fork controller process fail.Errno=%d", errno);
			return SW_ERR;
		}
		else
		{
			controller->pid = pid;
		}
	}
	return SW_OK;
}

int swFactoryProcess_controller_spawn(swFactory *factory, swController *controller)
{
	int pid = fork();
	int ret = 0;

	if(pid < 0)
	{
		swWarn("fork() fail. errno=%d", errno);
		return SW_ERR;
	}
	else if(pid == 0)
	{
		//关闭不需要的pipe, 0是给父进程使用的
		close(manager_controller_pipes[controller->id].pipes[0]);
		ret = swFactoryProcess_controller_loop(factory, controller);
		exit(ret);
	}
	else
	{
		return pid;
	}
}

int swFactoryProcess_controller_loop(swFactory *factory, swController *controller)
{
	swFactoryProcess *object = factory->object;
	swReactor reactor;

	struct timeval tmo;
	tmo.tv_sec = SW_REACTOR_WRITER_TIMEO;
	tmo.tv_usec = 0;

	if (swReactorSelect_create(&reactor) < 0)
	{
		swWarn("reactor create fail\n");
		return SW_ERR;
	}
	reactor.ptr = controller;
	reactor.factory = factory;
	reactor.add(&reactor, controller->pipe_fd, SW_FD_PIPE);
	reactor.setHandle(&reactor, SW_FD_PIPE, swFactoryProcess_controller_receive);
	reactor.wait(&reactor, &tmo);
	reactor.free(&reactor);
	return SW_OK;
}

int swFactoryProcess_controller_receive(swReactor *reactor, swDataHead *ev)
{
	int n, ret;
	swFactory *factory = reactor->factory;
	swController *controller = reactor->ptr;
	swEventData event;

	n = read(ev->fd, &event, sizeof(event));
	if (n > 0)
	{
		//处理事件
		return controller->onEvent(factory, &event);
	}
	else
	{
		swWarn("[controller]sento fail.errno=%d\n", errno);
		return SW_ERR;
	}
}

int swFactoryProcess_shutdown(swFactory *factory)
{
	swFactoryProcess *object = factory->object;
	swServer *serv = factory->ptr;
	int i;
	//kill manager process
	kill(object->manager_pid, SIGTERM);
	//kill all child process
	for (i = 0; i < object->worker_num; i++)
	{
		swTrace("[Main]kill worker processor\n");
		kill(object->workers[i].pid, SIGTERM);
	}
#ifdef SW_USE_SHM_CHAN
	//kill all child process
	for (i = 0; i < object->writer_num; i++)
	{
#if defined(SW_CHAN_USE_MMAP) || SW_CHAN_USE_MMAP==1
		swShareMemory_mmap_free(&object->writers[i].shm);
#else
		swShareMemory_sysv_free(&object->writers[i].shm, 1);
#endif
	}
#endif

	if(serv->dispatch_mode == SW_DISPATCH_QUEUE)
	{
		object->msg_queue.close(&object->msg_queue);
	}

	free(object->workers);
	free(object->writers);
	free(object);
	return SW_OK;
}

int swFactoryProcess_start(swFactory *factory)
{
	int ret;
	ret = swFactory_check_callback(factory);
	if (ret < 0)
	{
		return SW_ERR;
	}
	//必须先启动worker，否则manager进程会带线程fork
	ret = swFactoryProcess_worker_start(factory);
	if (ret < 0)
	{
		return SW_ERR;
	}
	//主进程需要设置为直写模式
	factory->finish = swFactory_finish;
	return SW_OK;
}

//create worker child proccess
static int swFactoryProcess_worker_start(swFactory *factory)
{
	swFactoryProcess *object = factory->object;
	int i, pid, ret;
	swPipes *worker_pipes;
	int writer_pti;

	swServer *serv = factory->ptr;
	if(serv->dispatch_mode == SW_DISPATCH_QUEUE)
	{
		if(swPipeMsg_create(&object->msg_queue, 1, SW_WORKER_MSGQUEUE_KEY, 1) <0)
		{
			swError("[Main] swPipeMsg_create fail\n");
			return SW_ERR;
		}
	}

	//此处内存可不释放，仅启动时分配一次
	worker_pipes = sw_calloc(object->worker_num, sizeof(swPipes));
	if (worker_pipes == NULL)
	{
		swError("malloc fail.Errno=%d\n", errno);
		return SW_ERR;
	}
	//worker进程的pipes
	for (i = 0; i < object->worker_num; i++)
	{
		if (socketpair(PF_LOCAL, SOCK_DGRAM, 0, worker_pipes[i].pipes) < 0)
		{
			swError("create unix socket[1] fail");
			return SW_ERR;
		}
	}

	if( manager_controller_count > 0)
	{
		manager_controller_pipes = sw_calloc(manager_controller_count, sizeof(swPipes));
		//controller进程的pipes
		for (i = 0; i < manager_controller_count; i++)
		{
			if (socketpair(PF_LOCAL, SOCK_DGRAM, 0, manager_controller_pipes[i].pipes) < 0)
			{
				swError("create unix socket[2] fail");
				return SW_ERR;
			}
		}
	}

	//创建共享内存
	for (i = 0; i < object->writer_num; i++)
	{
#ifdef SW_USE_SHM_CHAN
		void *mm;
#if defined(SW_CHAN_USE_MMAP) || SW_CHAN_USE_MMAP==1
		mm = swShareMemory_mmap_create(&object->writers[i].shm, SW_CHAN_BUFFER_SIZE, 0);
#else
		mm = swShareMemory_sysv_create(&object->writers[i].shm, SW_CHAN_BUFFER_SIZE, SW_CHAN_SYSV_KEY + i);
#endif
		if (mm == NULL)
		{
			swError("swShareMemory create fail");
			return SW_ERR;
		}
		if (swChan_create(&object->writers[i].chan, mm, SW_CHAN_BUFFER_SIZE, SW_CHAN_ELEM_SIZE, SW_BUFFER_SIZE + sizeof(swDataHead)) < 0)
		{
			swError("swChan_create fail");
			return SW_ERR;
		}
#endif
	}

	pid = fork();
	switch (pid)
	{
	//创建manager进程
	case 0:
		for (i = 0; i < object->worker_num; i++)
		{
//			close(worker_pipes[i].pipes[0]);
			writer_pti = (i % object->writer_num);
			object->workers[i].pipe_fd = worker_pipes[i].pipes[1];
			object->workers[i].writer_id = writer_pti;
			pid = swFactoryProcess_worker_spawn(factory, writer_pti, i);
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
		//创建controller进程
		if(manager_controller_count > 0)
		{
			swFactoryProcess_controller_start(factory);
		}
		//标识为管理进程
		sw_process_type = SW_PROCESS_MANAGER;
		ret = swFactoryProcess_manager_loop(factory);
		exit(ret);
		break;
		//主进程
	default:
		object->manager_pid = pid;
		int ret = swFactoryProcess_writer_start(factory);
		if (ret < 0)
		{
			return SW_ERR;
		}
		for (i = 0; i < object->worker_num; i++)
		{
			writer_pti = (i % object->writer_num);
#ifndef SW_USE_SHM_CHAN
			object->writers[writer_pti].reactor.add(&(object->writers[writer_pti].reactor), worker_pipes[i].pipes[0],
					SW_FD_PIPE);
#endif
			close(worker_pipes[i].pipes[1]);
			object->workers[i].pipe_fd = worker_pipes[i].pipes[0];
			object->workers[i].writer_id = writer_pti;
		}
		break;
	case -1:
		swError("[swFactoryProcess_worker_start]fork manager process fail\n");
		return SW_ERR;
	}
	return SW_OK;
}

static void swManagerSignalHanlde(int sig)
{
	switch (sig)
	{
	case SIGUSR1:
		manager_worker_reloading = 1;
		manager_reload_flag = 0;
		break;
	default:
		break;
	}
}

static int swFactoryProcess_manager_loop(swFactory *factory)
{
	int pid, new_pid;
	int i, writer_pti;
	int reload_worker_i = 0;
	int ret;

	swFactoryProcess *object = factory->object;
	swServer *serv = factory->ptr;
	swWorkerChild *reload_workers;

	reload_workers = sw_calloc(object->worker_num, sizeof(swWorkerChild));
	if (reload_workers == NULL)
	{
		swError("[manager] malloc[reload_workers] fail.\n");
		return SW_ERR;
	}

	//for reload
	swSignalSet(SIGUSR1, swManagerSignalHanlde, 1, 0);

	while (1)
	{
		pid = wait(NULL);
		swTrace("[manager] worker stop.pid=%d\n", pid);
		if (pid < 0)
		{
			if (manager_worker_reloading == 0)
			{
				swTrace("wait fail.errno=%d\n", errno);
			}
			else if (manager_reload_flag == 0)
			{
				memcpy(reload_workers, object->workers, sizeof(swWorkerChild) * object->worker_num);
				manager_reload_flag = 1;
				goto kill_worker;
			}
		}
		if (swoole_running == 1)
		{
			for (i = 0; i < object->worker_num; i++)
			{
				//对比pid
				if (pid != object->workers[i].pid)
					continue;

				writer_pti = (i % object->writer_num);
				new_pid = swFactoryProcess_worker_spawn(factory, writer_pti, i);
				if (new_pid < 0)
				{
					swWarn("Fork worker process fail.Errno=%d", errno);
					return SW_ERR;
				}
				else
				{
					object->workers[i].pid = new_pid;
				}
			}
			swController *controller;
			LL_FOREACH(manager_controller_list, controller)
			{
				//对比pid
				if (pid != controller->pid)
				{
					continue;
				}
				else
				{
					return swFactoryProcess_controller_spawn(factory, controller);
				}
			}
		}
		//reload worker
		kill_worker: if (manager_worker_reloading == 1)
		{
			//reload finish
			if (reload_worker_i >= object->worker_num)
			{
				manager_worker_reloading = 0;
				reload_worker_i = 0;
				continue;
			}
			ret = kill(reload_workers[reload_worker_i].pid, SIGTERM);
			if (ret < 0)
			{
				swWarn("kill fail.pid=%d|errno=%d\n", reload_workers[reload_worker_i].pid, errno);
				continue;
			}
			reload_worker_i++;
		}
	}
	sw_free(reload_workers);
	return SW_OK;
}

static int swFactoryProcess_worker_spawn(swFactory *factory, int writer_pti, int worker_pti)
{
	swFactoryProcess *object = factory->object;
	int i, pid, ret;

	pid = fork();
	if (pid < 0)
	{
		swTrace("[swFactoryProcess_worker_spawn]Fork Worker fail\n");
		return SW_ERR;
	}
	//worker child processor
	else if (pid == 0)
	{
		for (i = 0; i < object->worker_num; i++)
		{
			//非当前
			if (worker_pti != i)
			{
				close(object->workers[i].pipe_fd);
			}
		}
		c_writer_pti = writer_pti;
		//标识为worker进程
		sw_process_type = SW_PROCESS_WORKER;
		ret = swFactoryProcess_worker_loop(factory, object->workers[worker_pti].pipe_fd, worker_pti);
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
	int ret;
	swFactoryProcess *object = factory->object;
	swServer *serv = factory->ptr;
	swEventData send_data;

	send_data.info.fd = event->fd;
	send_data.info.len = 0; //len=0表示关闭此连接
	send_data.info.from_id = event->from_id;

	int sendn = sizeof(send_data.info);
#ifdef SW_USE_SHM_CHAN
	int count;
	swChan *chan = object->writers[c_writer_pti].chan;
	for (count = 0; count < SW_CHAN_PUSH_TRY_COUNT; count++)
	{
		ret = swChan_push(chan, &send_data, sendn);
		//printf("[worker]push[close].fd=%d|from_id=%d|last_from_id=%d\n", send_data.info.fd, send_data.info.from_id, factory->last_from_id);
		//send success
		if (ret == 0)
		{
			break;
		}
	}
	if (ret < 0)
	{
		swWarn("Error: push try count > %d\n", SW_CHAN_PUSH_TRY_COUNT);
	}
	else
	{
		swChan_notify(chan);
	}
	//printf("closeFd.fd=%d|from_id=%d\n", send_data.fd, send_data.from_id);
#else
	do
	{
		ret = write(c_worker_pipe, &send_data, sendn);
	}
	while(ret < 0 && errno == EINTR);
#endif
	return ret;
}

int swFactoryProcess_finish(swFactory *factory, swSendData *resp)
{
	//UDP直接在worker进程内发送
	int ret, sendn;
	swFactoryProcess *object = factory->object;
	swEventData send_data;
	memcpy(send_data.data, resp->data, resp->info.len);

	send_data.info.fd = resp->info.fd;
	send_data.info.len = resp->info.len;
	send_data.info.from_id = resp->info.from_id;
	sendn =  resp->info.len + sizeof(resp->info);
#ifdef SW_USE_SHM_CHAN
	int count;
	swChan *chan = object->writers[c_writer_pti].chan;
	for (count = 0; count < SW_CHAN_PUSH_TRY_COUNT; count++)
	{
		ret = swChan_push(chan, &send_data, sendn);
		//printf("[worker]push[send].fd=%d|from_id=%d|last_from_id=%d|data=%s\n", send_data.info.fd, send_data.info.from_id, factory->last_from_id, send_data.data);
		if (ret == 0)
		{
			break;
		}
		swYield();
	}
	if (ret < 0)
	{
		swWarn("Error: push try count > %d\n", SW_CHAN_PUSH_TRY_COUNT);
	}
	else
	{
		swChan_notify(chan);
	}
	//printf("push data.fd=%d|from_id=%d|data=%s\n", send_data.fd, send_data.from_id, send_data.data);
#else
	do
	{
		ret = write(c_worker_pipe, &send_data, sendn);
	}
	while(ret < 0 && errno == EINTR);
#endif
	return ret;
}

static int swFactoryProcess_worker_loop(swFactory *factory, int c_pipe, int worker_pti)
{
	swEventData req;
	swFactoryProcess *object = factory->object;
	swServer *serv = factory->ptr;
	c_worker_pipe = c_pipe;
	c_worker_pti = worker_pti;

	int n;
	int task_num = factory->max_request;

#ifdef HAVE_CPU_AFFINITY
	if (serv->open_cpu_affinity == 1)
	{
		cpu_set_t cpu_set;
		CPU_ZERO(&cpu_set);
		CPU_SET(worker_pti % SW_CPU_NUM, &cpu_set);
		if (0 != sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set))
		{
			swWarn("pthread_setaffinity_np set fail\n");
		}
	}
#endif

	if (serv->onWorkerStart != NULL)
	{
		//worker进程启动时调用
		serv->onWorkerStart(serv, worker_pti);
	}
	//主线程
	while (swoole_running > 0 && task_num > 0)
	{
		if (serv->dispatch_mode == SW_DISPATCH_QUEUE)
		{
			n = object->msg_queue.read(&object->msg_queue, &req, sizeof(req));
					swTrace("read msgqueue.errno=%d|pid=%d\n", errno, getpid());
		}
		else
		{
			do
			{
				n = read(c_pipe, &req, sizeof(req));
			}
			while(n < 0 && errno == EINTR);
			swTrace("[Worker]Recv: pipe=%d|pti=%d\n", c_pipe, req.info.from_id);
		}

		if (n > 0)
		{
			factory->last_from_id = req.info.from_id;
			switch(req.info.type)
			{
			case SW_EVENT_DATA:
				factory->onTask(factory, &req);
				break;
			case SW_EVENT_CLOSE:
				serv->onClose(serv, req.info.fd, req.info.from_id);
				break;
			case SW_EVENT_CONNECT:
				serv->onConnect(serv, req.info.fd, req.info.from_id);
				break;
			case SW_EVENT_CONTROL:
				serv->onWorkerEvent(serv, &req);
				break;
			default:
				swWarn("Error event[type=%d]", (int)req.info.type);
				break;
			}
			task_num--;
		}
		else
		{
			swWarn("[Worker]read pipe error.Errno=%d\n", errno);
		}
	}
	if (serv->onWorkerStop != NULL)
	{
		//worker进程结束时调用
		serv->onWorkerStop(serv, worker_pti);
	}
	swTrace("[Worker]max request\n");
	return SW_OK;
}

int swFactoryProcess_notify(swFactory *factory, swDataHead *ev)
{
	swFactoryProcess *object = factory->object;
	swDataHead _send;
	int send_len = sizeof(swDataHead);
	memcpy(&_send, ev, sizeof(swDataHead));
	return swFactoryProcess_send2worker(factory, (swEventData *)ev, send_len);
}

static int swFactoryProcess_send2worker(swFactory *factory, swEventData *data, int send_len)
{
	swFactoryProcess *object = factory->object;
	swServer *serv = factory->ptr;
	int pti;
	int ret;

	//使用抢占式队列(IPC消息队列)分配
	if(serv->dispatch_mode == SW_DISPATCH_QUEUE)
	{
		ret = object->msg_queue.write(&object->msg_queue, data, send_len);
	}
	else
	{
		if(serv->dispatch_mode == SW_DISPATCH_ROUND)
		{
			pti = object->worker_pti;
			if (object->worker_pti >= object->worker_num)
			{
				object->worker_pti = 0;
				pti = 0;
			}
			object->worker_pti++;
		 }
		 //使用fd取摸来散列
		 else
		 {
			 pti = data->info.fd % object->worker_num;
		 }
		 swTrace("[ReadThread]sendto: pipe=%d|worker=%d\n", object->workers[pti].pipe_fd, pti);
		 //send to unix sock
		 ret = swWrite(object->workers[pti].pipe_fd, (char *) data, send_len);
	}
	if (ret < 0)
	{
		return SW_ERR;
	}
	return SW_OK;
}

int swFactoryProcess_dispatch(swFactory *factory, swEventData *data)
{
	swFactoryProcess *object = factory->object;
	int send_len = data->info.len + sizeof(data->info);
	data->info.type = SW_EVENT_DATA; //这是一个数据事件
	return swFactoryProcess_send2worker(factory, data, send_len);
}

static int swFactoryProcess_writer_start(swFactory *factory)
{
	swFactoryProcess *object = factory->object;
	swThreadParam *param;
	int i;
	pthread_t pidt;
	swThreadStartFunc thread_main;

#ifdef SW_USE_SHM_CHAN
	thread_main = (swThreadStartFunc) swFactoryProcess_writer_loop_ex;
#else
	thread_main = (swThreadStartFunc) swFactoryProcess_writer_loop;
#endif

	for (i = 0; i < object->writer_num; i++)
	{
		//内存可不释放，仅分配一次
		param = sw_malloc(sizeof(swThreadParam));
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
		object->writers[i].ptid = pidt;
		SW_START_SLEEP;
	}
	return SW_OK;
}

int swFactoryProcess_writer_excute(swFactory *factory, swEventData *resp)
{
	int ret;
	swServer *serv = factory->ptr;

	swSendData send_data;
	swDataHead closeFd;

	//表示关闭
	if (resp->info.len == 0)
	{
		close_fd:
		{
			closeFd.fd = resp->info.fd;
			closeFd.from_id = resp->info.from_id;
			//printf("closeFd.fd=%d|from_id=%d\n", closeFd.fd, closeFd.from_id);
			swServer_close(serv, &closeFd);
		}
		return SW_ERR;
	}
	else
	{
		send_data.data = resp->data;
		send_data.info.len = resp->info.len;
		send_data.info.from_id = resp->info.from_id;
		send_data.info.fd = resp->info.fd;
		ret = factory->onFinish(factory, &send_data);
		if (ret < 0)
		{
			//连接已被关闭
			if (errno == EBADF)
			{
				goto close_fd;
			}
			swWarn("factory->onFinish fail.fd=%d|from_id=%d|errno=%d\n", resp->info.fd, resp->info.from_id, errno);
		}
		//printf("[writer]pop.fd=%d|from_id=%d|data=%s\n", resp->info.fd, resp->info.from_id, resp->data);
	}
	return SW_OK;
}

int swFactoryProcess_writer_receive(swReactor *reactor, swDataHead *ev)
{
	int n, ret;
	swFactory *factory = reactor->factory;
	swServer *serv = factory->ptr;
	swEventData resp;

	//Unix Sock UDP
	n = read(ev->fd, &resp, sizeof(resp));
	swTrace("[WriteThread]recv: writer=%d|pipe=%d\n", ev->from_id, ev->fd);
	if (n > 0)
	{
		return swFactoryProcess_writer_excute(factory, &resp);
	}
	else
	{
		swWarn("[WriteThread]sento fail.errno=%d\n", errno);
		return SW_ERR;
	}
}

int swFactoryProcess_writer_loop(swThreadParam *param)
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
		swTrace("swReactorSelect_create fail\n");
		pthread_exit((void *) param);
	}
	reactor->setHandle(reactor, SW_FD_PIPE, swFactoryProcess_writer_receive);
	reactor->wait(reactor, &tmo);
	reactor->free(reactor);
	pthread_exit((void *) param);
	return SW_OK;
}
/**
 * 使用共享内存队列
 */
int swFactoryProcess_writer_loop_ex(swThreadParam *param)
{
	swFactory *factory = param->object;
	swFactoryProcess *object = factory->object;
	swServer *serv = factory->ptr;
	swChan *chan;
	swChanElem *elem;
	swEventData *resp;

	int ret;
	int pti = param->pti;
	chan = object->writers[pti].chan;

	while (swoole_running > 0)
	{
		elem = swChan_pop(chan);
		if (elem == NULL)
		{
			swChan_wait(chan);
		}
		else
		{
			resp = (swEventData *) elem->ptr;
			swFactoryProcess_writer_excute(factory, resp);
			//释放掉内存
			swMemoryPool_free(&chan->pool, elem->ptr);
		}
	}
	pthread_exit((void *) param);
	return SW_OK;
}
