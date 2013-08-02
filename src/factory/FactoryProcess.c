#include "swoole.h"
#include "Server.h"
#include <signal.h>
#include <sys/wait.h>

typedef struct _swPipes
{
	int pipes[2];
} swPipes;

static int swFactoryProcess_manager_loop(swFactory *factory);
static int swFactoryProcess_worker_start(swFactory *factory);
static int swFactoryProcess_worker_loop(swFactory *factory, int c_pipe, int worker_pti);
static int swFactoryProcess_worker_spawn(swFactory *factory, int writer_pti, int worker_pti);
static int swFactoryProcess_writer_start(swFactory *factory);

int swFactoryProcess_writer_loop(swThreadParam *param);
int swFactoryProcess_writer_loop_ex(swThreadParam *param);
int swFactoryProcess_writer_receive(swReactor *, swEvent *);

static int c_worker_pipe = 0; //Current Proccess Worker's pipe
static int c_worker_pti = 0; //Current Proccess Worker's id
static int c_writer_pti = 0; //Current Proccess writer's id

static int manager_worker_reloading = 0;
static int manager_reload_flag = 0;

int swFactoryProcess_create(swFactory *factory, int writer_num, int worker_num)
{
	swFactoryProcess *this;
	this = sw_malloc(sizeof(swFactoryProcess));
	if (this == NULL)
	{
		swWarn("[swFactoryProcess_create] malloc[0] fail");
		return SW_ERR;
	}
	this->writers = sw_calloc(writer_num, sizeof(swThreadWriter));
	if (this->writers == NULL)
	{
		swWarn("[Main] malloc[this->writers] fail");
		return SW_ERR;
	}
	this->writer_num = writer_num;
	this->writer_pti = 0;

	this->workers = sw_calloc(worker_num, sizeof(swWorkerChild));
	if (this->workers == NULL)
	{
		swWarn("[Main] malloc[this->workers] fail");
		return SW_ERR;
	}
	this->worker_num = worker_num;

	factory->running = 1;
	factory->object = this;
	factory->dispatch = swFactoryProcess_dispatch;
	factory->finish = swFactoryProcess_finish;
	factory->start = swFactoryProcess_start;
	factory->shutdown = swFactoryProcess_shutdown;
	factory->end = swFactoryProcess_end;

	factory->onTask = NULL;
	factory->onFinish = NULL;
	return SW_OK;
}

int swFactoryProcess_shutdown(swFactory *factory)
{
	swFactoryProcess *this = factory->object;
	int i;
	//kill manager process
	kill(this->manager_pid, SIGTERM);
	//kill all child process
	for (i = 0; i < this->worker_num; i++)
	{
		swTrace("[Main]kill worker processor\n");
		kill(this->workers[i].pid, SIGTERM);
	}
#ifdef SW_USE_SHM_CHAN
	//kill all child process
	for (i = 0; i < this->writer_num; i++)
	{
#if defined(SW_CHAN_USE_MMAP) || SW_CHAN_USE_MMAP==1
		swShareMemory_mmap_free(&this->writers[i].shm);
#else
		swShareMemory_sysv_free(&this->writers[i].shm, 1);
#endif
	}
#endif

#if SW_DISPATCH_MODE == 3
	this->msg_queue.close(&this->msg_queue);
#endif

	free(this->workers);
	free(this->writers);
	free(this);
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
	swFactoryProcess *this = factory->object;
	int i, pid;
	swPipes *worker_pipes;
	int writer_pti;

#if SW_DISPATCH_MODE == 3
	if(swPipeMsg_create(&this->msg_queue, 1, SW_WORKER_MSGQUEUE_KEY, 1) <0)
	{
		swError("[Main] swPipeMsg_create fail\n");
		return SW_ERR;
	}
#else
	worker_pipes = sw_calloc(this->worker_num, sizeof(swPipes));
	if (worker_pipes == NULL)
	{
		swError("malloc fail.Errno=%d\n", errno);
		return SW_ERR;
	}
	for (i = 0; i < this->worker_num; i++)
	{
		if (socketpair(PF_LOCAL, SOCK_DGRAM, 0, worker_pipes[i].pipes) < 0)
		{
			swError("create unix socket fail");
			return SW_ERR;
		}
	}
	//创建共享内存
	for (i = 0; i < this->writer_num; i++)
	{
#ifdef SW_USE_SHM_CHAN
		void *mm;
#if defined(SW_CHAN_USE_MMAP) || SW_CHAN_USE_MMAP==1
		mm = swShareMemory_mmap_create(&this->writers[i].shm, SW_CHAN_BUFFER_SIZE, 0);
#else
		mm = swShareMemory_sysv_create(&this->writers[i].shm, SW_CHAN_BUFFER_SIZE, SW_CHAN_SYSV_KEY + i);
#endif
		if (mm == NULL)
		{
			swError("swShareMemory create fail");
			return SW_ERR;
		}
		if (swChan_create(&this->writers[i].chan, mm, SW_CHAN_BUFFER_SIZE, SW_CHAN_ELEM_SIZE, SW_BUFFER_SIZE + sizeof(swDataHead)) < 0)
		{
			swError("swChan_create fail");
			return SW_ERR;
		}
#endif
	}

#endif
	pid = fork();
	switch (pid)
	{
	//创建manager进程
	case 0:
		for (i = 0; i < this->worker_num; i++)
		{
			close(worker_pipes[i].pipes[0]);
			writer_pti = (i % this->writer_num);
			this->workers[i].pipe_fd = worker_pipes[i].pipes[1];
			this->workers[i].writer_id = writer_pti;
			pid = swFactoryProcess_worker_spawn(factory, writer_pti, i);
			if (pid < 0)
			{
				swError("Fork worker process fail");
				return SW_ERR;
			}
			else
			{
				this->workers[i].pid = pid;
			}
		}
		//标识为管理进程
		sw_process_type = SW_PROCESS_MANAGER;
		swFactoryProcess_manager_loop(factory);
		break;
		//主进程
	default:
		this->manager_pid = pid;
		int ret = swFactoryProcess_writer_start(factory);
		if (ret < 0)
		{
			return SW_ERR;
		}
		for (i = 0; i < this->worker_num; i++)
		{
			writer_pti = (i % this->writer_num);
#ifndef SW_USE_SHM_CHAN
			this->writers[writer_pti].reactor.add(&(this->writers[writer_pti].reactor), worker_pipes[i].pipes[0],
					SW_FD_PIPE);
#endif
			close(worker_pipes[i].pipes[1]);
			this->workers[i].pipe_fd = worker_pipes[i].pipes[0];
			this->workers[i].writer_id = writer_pti;
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

	swFactoryProcess *this = factory->object;
	swWorkerChild *reload_workers;

	reload_workers = sw_calloc(this->worker_num, sizeof(swWorkerChild));
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
				memcpy(reload_workers, this->workers, sizeof(swWorkerChild) * this->worker_num);
				manager_reload_flag = 1;
				goto kill_worker;
			}
		}
		if (swoole_running == 1)
		{
			for (i = 0; i < this->worker_num; i++)
			{

				if (pid != this->workers[i].pid)
					continue;

				writer_pti = (i % this->writer_num);
				new_pid = swFactoryProcess_worker_spawn(factory, writer_pti, i);
				if (new_pid < 0)
				{
					swWarn("Fork worker process fail.Errno=%d\n", errno);
					return SW_ERR;
				}
				else
				{
					this->workers[i].pid = new_pid;
				}
			}
		}
		//reload worker
		kill_worker: if (manager_worker_reloading == 1)
		{
			//reload finish
			if (reload_worker_i >= this->worker_num)
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

static int swFactoryProcess_worker_spawn(swFactory *factory, int writer_pti, int worker_pti)
{
	swFactoryProcess *this = factory->object;
	int i, pid;

	pid = fork();
	if (pid < 0)
	{
		swTrace("[swFactoryProcess_worker_spawn]Fork Worker fail\n");
		return SW_ERR;
	}
	//worker child processor
	else if (pid == 0)
	{
		for (i = 0; i < this->worker_num; i++)
		{
			//非当前
			if (worker_pti != i)
			{
				close(this->workers[i].pipe_fd);
			}
		}
		c_writer_pti = writer_pti;
		//标识为worker进程
		sw_process_type = SW_PROCESS_WORKER;
		swFactoryProcess_worker_loop(factory, this->workers[worker_pti].pipe_fd, worker_pti);
		exit(0);
	}
	//parent,add to writer
	else
	{
		return pid;
	}
}

int swFactoryProcess_end(swFactory *factory, swEvent *event)
{
	int ret;
	swFactoryProcess *this = factory->object;
	swEventData send_data;

	send_data.info.fd = event->fd;
	send_data.info.len = 0; //len=0表示关闭此连接
	send_data.info.from_id = event->from_id;

	int sendn = sizeof(send_data.info);
#ifdef SW_USE_SHM_CHAN
	int count;
	swChan *chan = this->writers[c_writer_pti].chan;
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
	ret = write(c_worker_pipe, &send_data, sendn);
#endif
	return ret;
}

int swFactoryProcess_finish(swFactory *factory, swSendData *resp)
{
	int ret, sendn;
	swFactoryProcess *this = factory->object;
	swEventData send_data;
	memcpy(send_data.data, resp->data, resp->info.len);
	send_data.info.fd = resp->info.fd;
	send_data.info.len = resp->info.len;
	send_data.info.from_id = resp->info.from_id;
	sendn =  resp->info.len + sizeof(resp->info);
#ifdef SW_USE_SHM_CHAN
	int count;
	swChan *chan = this->writers[c_writer_pti].chan;
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
	ret = write(c_worker_pipe, &send_data, sendn);
#endif
	return ret;
}

static int swFactoryProcess_worker_loop(swFactory *factory, int c_pipe, int worker_pti)
{
	swEventData req;
	swFactoryProcess *this = factory->object;
	swServer *serv = factory->ptr;
	c_worker_pipe = c_pipe;
	c_worker_pti = worker_pti;

	int n;
	int task_num = factory->max_request;

#if HAVE_CPU_AFFINITY
	if (serv->open_cpu_affinity)
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
#if SW_DISPATCH_MODE == 3
		n = this->msg_queue.read(&this->msg_queue, &req, sizeof(req));
		swTrace("read msgqueue.errno=%d|pid=%d\n", errno, getpid());
#else
		n = read(c_pipe, &req, sizeof(req));
		swTrace("[Worker]Recv: pipe=%d|pti=%d\n", c_pipe, req.info.from_id);
#endif
		if (n > 0)
		{
			factory->last_from_id = req.info.from_id;
			factory->onTask(factory, &req);
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

int swFactoryProcess_dispatch(swFactory *factory, swEventData *data)
{
	swFactoryProcess *this = factory->object;
	int ret;
	int send_len = data->info.len + sizeof(data->info);
	int pti;

#if SW_DISPATCH_MODE == 3
	//使用抢占式队列(IPC消息队列)分配
	ret = this->msg_queue.write(&this->msg_queue, data, send_len);
#else
#if SW_DISPATCH_MODE == 1
	//使用平均分配
	pti = this->worker_pti;
	if (this->worker_pti >= this->worker_num)
	{
		this->worker_pti = 0;
		pti = 0;
	}
	this->worker_pti++;
#elif SW_DISPATCH_MODE == 2
	//使用fd取摸来散列
	pti = data->info.fd % this->worker_num;
#endif
	swTrace("[ReadThread]sendto: pipe=%d|worker=%d\n", this->workers[pti].pipe_fd, pti);
	//send to unix sock
	ret = swWrite(this->workers[pti].pipe_fd, (char *) data, send_len);
#endif
	if (ret < 0)
	{
		return SW_ERR;
	}
	return SW_OK;
}

static int swFactoryProcess_writer_start(swFactory *factory)
{
	swFactoryProcess *this = factory->object;
	swThreadParam *param;
	int i;
	pthread_t pidt;
	swThreadStartFunc thread_main;

#ifdef SW_USE_SHM_CHAN
	thread_main = (swThreadStartFunc) swFactoryProcess_writer_loop_ex;
#else
	thread_main = (swThreadStartFunc) swFactoryProcess_writer_loop;
#endif

	for (i = 0; i < this->writer_num; i++)
	{
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
		this->writers[i].ptid = pidt;
		SW_START_SLEEP;
	}
	return SW_OK;
}

int swFactoryProcess_writer_excute(swFactory *factory, swEventData *resp)
{
	int ret;
	swServer *serv = factory->ptr;

	swSendData send_data;
	swEvent closeFd;

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

int swFactoryProcess_writer_receive(swReactor *reactor, swEvent *ev)
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
	swFactoryProcess *this = factory->object;
	int pti = param->pti;
	swReactor *reactor = &(this->writers[pti].reactor);

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
	swFactoryProcess *this = factory->object;
	swServer *serv = factory->ptr;
	swChan *chan;
	swChanElem *elem;
	swEventData *resp;

	int ret;
	int pti = param->pti;
	chan = this->writers[pti].chan;

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
			swMemPool_free(elem->ptr);
		}
	}
	pthread_exit((void *) param);
	return SW_OK;
}
