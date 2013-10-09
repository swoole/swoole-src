#include "swoole.h"
#include "Server.h"
#include <signal.h>
#include <sys/wait.h>

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
static int swFactoryProcess_worker_loop(swFactory *factory, int worker_pti);
static int swFactoryProcess_worker_spawn(swFactory *factory, int worker_pti);
static int swFactoryProcess_writer_start(swFactory *factory);

static int swFactoryProcess_writer_loop_unsock(swThreadParam *param);
static int swFactoryProcess_writer_loop_queue(swThreadParam *param);
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

static int c_worker_pti = 0; //Current Proccess Worker's id

static int manager_worker_reloading = 0;
static int manager_reload_flag = 0;
static swController *manager_controller_list;
static swPipe *manager_controller_pipes;
static int manager_controller_count = 0;

int swFactoryProcess_create(swFactory *factory, int writer_num, int worker_num)
{
	swFactoryProcess *object;
	object = sw_memory_pool->alloc(sw_memory_pool, sizeof(swFactoryProcess));
	if (object == NULL)
	{
		swWarn("[swFactoryProcess_create] malloc[0] fail");
		return SW_ERR;
	}
	object->writers = sw_memory_pool->alloc(sw_memory_pool, writer_num*sizeof(swThreadWriter));
	if (object->writers == NULL)
	{
		swWarn("[Main] malloc[object->writers] fail");
		return SW_ERR;
	}
	object->writer_num = writer_num;
	object->writer_pti = 0;

	object->workers = sw_memory_pool->alloc(sw_memory_pool, worker_num* sizeof(swWorkerChild));
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
	swController *controller = sw_memory_pool->alloc(sw_memory_pool, sizeof(swController));
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
	pipe_fd = manager_controller_pipes[controller_id].getFd(&manager_controller_pipes[controller_id], 0);
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
		controller->pipe_fd = manager_controller_pipes[controller->id].getFd(&manager_controller_pipes[controller->id], 1);
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
		close(manager_controller_pipes[controller->id].getFd(&manager_controller_pipes[controller->id], 0));
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
#if SW_WORKER_IPC_MODE == 2
	object->rd_queue.free(&object->rd_queue);
	object->wt_queue.free(&object->wt_queue);
#else
	//close pipes
#endif
	return SW_OK;
}

int swFactoryProcess_start(swFactory *factory)
{
	int ret;
	ret = swFactory_check_callback(factory);
	if (ret < 0)
	{
		swWarn("XXXXXXXXXXX: %d", __LINE__);
		return SW_ERR;
	}
	//必须先启动worker，否则manager进程会带线程fork
	ret = swFactoryProcess_worker_start(factory);
	if (ret < 0)
	{
		swWarn("XXXXXXXXXXX: %d", __LINE__);
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
	int writer_pti;

	swServer *serv = factory->ptr;

#if SW_WORKER_IPC_MODE == 2
#define _SW_PATH_BUF_LEN   128
	//这里使用ftok来获取消息队列的key
	char path_buf[_SW_PATH_BUF_LEN];
	char *path_ptr = getcwd(path_buf, _SW_PATH_BUF_LEN);
	//读数据队列
	if(swQueueMsg_create(&object->rd_queue, 1, ftok(path_ptr, 1), 1) < 0)
	{
		swError("[Master] swPipeMsg_create[In] fail.errno=%d", errno);
		return SW_ERR;
	}
	//为TCP创建写队列
	if (serv->have_tcp_sock == 1)
	{
		//写数据队列
		if(swQueueMsg_create(&object->wt_queue, 1, ftok(path_ptr, 2), 1) < 0)
		{
			swError("[Master] swPipeMsg_create[out] fail.errno=%d", errno);
			return SW_ERR;
		}
	}
#else
	object->pipes = sw_memory_pool->alloc(sw_memory_pool, object->worker_num * sizeof(swPipe));
	if (object->pipes == NULL)
	{
		swError("malloc[worker_pipes] fail.Errno=%d\n", errno);
		return SW_ERR;
	}
	//worker进程的pipes
	for (i = 0; i < object->worker_num; i++)
	{
		if (swPipeUnsock_create(&object->pipes[i], 1, SOCK_DGRAM) < 0)
		{
			swError("create unix socket[1] fail");
			return SW_ERR;
		}
		object->workers[i].pipe_master = object->pipes[i].getFd(&object->pipes[i], 1);
		object->workers[i].pipe_worker = object->pipes[i].getFd(&object->pipes[i], 0);
	}
#endif
	if (manager_controller_count > 0)
	{
		manager_controller_pipes = sw_memory_pool->alloc(sw_memory_pool, manager_controller_count * sizeof(swPipe));
		//controller进程的pipes
		for (i = 0; i < manager_controller_count; i++)
		{
			if (swPipeUnsock_create(&object->pipes[i], 1, SOCK_DGRAM) < 0)
			{
				swError("create unix socket[2] fail");
				return SW_ERR;
			}
		}
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
			object->workers[i].writer_id = writer_pti;
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
		//创建controller进程
		if (manager_controller_count > 0)
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
		//TCP需要writer线程
		if (serv->have_tcp_sock == 1)
		{
			int ret = swFactoryProcess_writer_start(factory);
			if (ret < 0)
			{
				return SW_ERR;
			}
		}
#if SW_WORKER_IPC_MODE != 2
		for (i = 0; i < object->worker_num; i++)
		{
			writer_pti = (i % object->writer_num);
			object->workers[i].writer_id = writer_pti;

			if (serv->have_tcp_sock == 1)
			{
				//将写pipe设置到writer的reactor中
				object->writers[writer_pti].reactor.add(&(object->writers[writer_pti].reactor),
						object->workers[i].pipe_master, SW_FD_PIPE);
			}
		}
#endif
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

	reload_workers = sw_memory_pool->alloc(sw_memory_pool, object->worker_num *sizeof(swWorkerChild));
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

				new_pid = swFactoryProcess_worker_spawn(factory, i);
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
	return SW_OK;
}

static int swFactoryProcess_worker_spawn(swFactory *factory, int worker_pti)
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
#if SW_WORKER_IPC_MODE != 2
		for (i = 0; i < object->worker_num; i++)
		{
			//非当前的worker_pipe
			if (worker_pti != i)
			{
				close(object->workers[i].pipe_worker);
			}
			//关闭master_pipe
			close(object->workers[i].pipe_master);
		}
#endif
		//标识为worker进程
		sw_process_type = SW_PROCESS_WORKER;
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
	int ret;
	swFactoryProcess *object = factory->object;
	swServer *serv = factory->ptr;
	swEventData send_data;

	send_data.info.fd = event->fd;
	send_data.info.len = 0; //len=0表示关闭此连接
	send_data.info.from_id = event->from_id;
	return swFactoryProcess_finish(factory, (swSendData *)event);
}
/**
 * Worker进程,向writer发送数据
 */
int swFactoryProcess_finish(swFactory *factory, swSendData *resp)
{
	//UDP直接在worker进程内发送
	int ret, sendn, count;;
	swFactoryProcess *object = factory->object;
	swServer *serv = factory->ptr;

	//from_id超过serv->poll_thread_num，这是一个UDP
	//UDP在worker进程中直接发送到客户端
	if(resp->info.from_id >= serv->poll_thread_num)
	{
		ret = swServer_send_udp_packet(serv, resp);
		goto finish;
	}

	//swQueue_data for msg queue
	struct {
		long pti;
		swEventData _send;
	} sdata;

	//写队列mtype
	sdata.pti = (c_worker_pti % serv->writer_num) + 1;

	//copy
	memcpy(sdata._send.data, resp->data, resp->info.len);

	sdata._send.info.fd = resp->info.fd;
	sdata._send.info.len = resp->info.len;
	sdata._send.info.from_id = resp->info.from_id;
	sendn =  resp->info.len + sizeof(resp->info);

	swTrace("[Worker]wt_queue[%ld]->in| fd=%d", sdata.pti, sdata._send.info.fd);

	for (count = 0; count < SW_WORKER_SENDTO_COUNT; count++)
	{
#if SW_WORKER_IPC_MODE == 2
		ret = object->wt_queue.in(&object->wt_queue, (swQueue_data *)&sdata, sendn);
#else
		ret = write(object->workers[c_worker_pti].pipe_worker, &sdata._send, sendn);
#endif
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
		swWarn("[Worker#%d]sendto writer pipe or queue fail. errno=%d", getpid(), errno);
	}
	return ret;
}

static int swFactoryProcess_worker_loop(swFactory *factory, int worker_pti)
{
	struct {
		long pti;
		swEventData req;
	} rdata;

	swFactoryProcess *object = factory->object;
	swServer *serv = factory->ptr;

	int pipe_rd = object->workers[worker_pti].pipe_worker;
	c_worker_pti = worker_pti;
	object->manager_pid = getppid();

#if SW_WORKER_IPC_MODE == 2
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
#endif

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
#if SW_WORKER_IPC_MODE == 2
		swTrace("[Worker]rd_queue[%ld]->out wait", rdata.pti);
		n = object->rd_queue.out(&object->rd_queue, (swQueue_data *)&rdata, sizeof(rdata.req));
#else
		do
		{
			n = read(pipe_rd, &rdata.req, sizeof(rdata.req));
		}
		while(n < 0 && errno == EINTR);
		swTrace("[Worker]pipe_recv: pipe=%d|pti=%d\n", c_pipe, req.info.from_id);
#endif
		swTrace("[Worker]recv fd=%d|type=%d|len=%d", rdata.req.info.fd, rdata.req.info.type, rdata.req.info.len);
		if (n > 0)
		{
			factory->last_from_id = rdata.req.info.from_id;
			switch(rdata.req.info.type)
			{
			case SW_EVENT_DATA:
				factory->onTask(factory, &rdata.req);
				//只有数据请求任务才计算task_num
				task_num--;
				break;
			case SW_EVENT_CLOSE:
				serv->onClose(serv, rdata.req.info.fd, rdata.req.info.from_id);
				break;
			case SW_EVENT_CONNECT:
				serv->onConnect(serv, rdata.req.info.fd, rdata.req.info.from_id);
				break;
			default:
				swWarn("[Worker] error event[type=%d]", (int)rdata.req.info.type);
				break;
			}
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

/**
 * for msg queue
 * 头部放一个long让msg queue可以直接插入到消息队列中
 */
static struct {
	long pti;
	swDataHead _send;
} sw_notify_data;

/**
 * 主进程通知worker进程
 */
int swFactoryProcess_notify(swFactory *factory, swDataHead *ev)
{
	swFactoryProcess *object = factory->object;
	memcpy(&sw_notify_data._send, ev, sizeof(swDataHead));
	sw_notify_data._send.len = 0;
	return swFactoryProcess_send2worker(factory, (swEventData *)&sw_notify_data._send, sizeof(swDataHead));
}

/**
 * 主进程向worker进程发送数据
 */
static int swFactoryProcess_send2worker(swFactory *factory, swEventData *data, int send_len)
{
	swFactoryProcess *object = factory->object;
	swServer *serv = factory->ptr;
	int pti;
	int ret;

	//轮询
	if (serv->dispatch_mode == SW_DISPATCH_ROUND)
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
	else if (serv->dispatch_mode == SW_DISPATCH_FDMOD)
	{
		pti = data->info.fd % object->worker_num;
	}
	//使用抢占式队列(IPC消息队列)分配
	else
	{

#if SW_WORKER_IPC_MODE != 2
		swError("SW_DISPATCH_QUEUE must use (SW_WORKER_IPC_MODE = 2)");
#endif
		//msgsnd参数必须>0
		//worker进程中正确的mtype应该是pti + 1
		pti = object->worker_num;
	}
	swTrace("[ReadThread]sendto: pipe=%d|worker=%d\n", object->workers[pti].pipe_fd, pti);

#if SW_WORKER_IPC_MODE == 2
	//insert to msg queue
	swQueue_data *in_data = (swQueue_data *)((void *)data - sizeof(long));

	//加1防止id为0的worker进程出错
	in_data->mtype = pti + 1;

	swDataHead *info = (swDataHead *)in_data->mdata;
	ret = object->rd_queue.in(&object->rd_queue, in_data, send_len);
	swTrace("[Master]rd_queue[%ld]->in: fd=%d|type=%d|len=%d", in_data->mtype, info->fd, info->type, info->len);
#else
	//send to unix sock
	ret = swWrite(object->workers[pti].pipe_master, (char *) data, send_len);
#endif
	return ret;
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

#if SW_WORKER_IPC_MODE == 2
	thread_main = (swThreadStartFunc) swFactoryProcess_writer_loop_queue;
#else
	thread_main = (swThreadStartFunc) swFactoryProcess_writer_loop_unsock;
#endif

	for (i = 0; i < object->writer_num; i++)
	{
		param = sw_memory_pool->alloc(sw_memory_pool, sizeof(swThreadParam));
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
 * 使用消息队列通信
 */
int swFactoryProcess_writer_loop_queue(swThreadParam *param)
{
	swFactory *factory = param->object;
	swFactoryProcess *object = factory->object;
	swServer *serv = factory->ptr;

	int ret;
	int pti = param->pti;

	swQueue_data sdata;
	//必须加1,msg_type必须不能为0
	sdata.mtype = pti + 1;

	while (swoole_running > 0)
	{
		swTrace("[Writer]wt_queue[%ld]->out wait", sdata.mtype);
		int ret = object->wt_queue.out(&object->wt_queue, &sdata, sizeof(sdata.mdata));
		if (ret < 0)
		{
			swWarn("queue out fail.errno=%d", errno);
		}
		else
		{
			swFactoryProcess_writer_excute(factory, (swEventData *)sdata.mdata);
		}
	}
	pthread_exit((void *) param);
	return SW_OK;
}
