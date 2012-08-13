#include "swoole.h"
#include <signal.h>

typedef struct _swWorkerChild
{
	pid_t pid;
	int pipe_fd;
	int writer_id;
} swWorkerChild;

typedef struct _swFactoryProcess
{
	swThreadWriter *writers;
	swWorkerChild *workers;

	int writer_num; //writer thread num
	int worker_num; //worker child process num
	int writer_pti; //current writer id
	int worker_pti; //current worker id
} swFactoryProcess;

static int swFactoryProcess_worker_start(swFactory *factory);
static int swFactoryProcess_worker_loop(swFactory *factory, int c_pipe);
static int swFactoryProcess_worker_spawn(swFactory *factory, int writer_pti, int worker_pti);
static int swFactoryProcess_writer_start(swFactory *factory);
static int swFactoryProcess_writer_loop(swThreadParam *param);
int swFactoryProcess_writer_receive(swReactor *, swEvent *);

static int c_worker_pipe = 0; //Current Proccess Worker's pipe

int swFactoryProcess_create(swFactory *factory, int writer_num, int worker_num)
{
	swFactoryProcess *this;
	this = sw_malloc(sizeof(swFactoryProcess));
	int step = 0;
	if (this == NULL)
	{
		swTrace("[swFactoryProcess_create] malloc[0] fail\n");
		return --step;
	}
	this->writers = sw_calloc(writer_num, sizeof(swThreadWriter));
	if (this->writers == NULL)
	{
		swTrace("[swFactoryProcess_create] malloc[1] fail\n");
		return --step;
	}
	this->writer_num = writer_num;
	this->writer_pti = 0;

	this->workers = sw_calloc(worker_num, sizeof(swWorkerChild));
	if (this->workers == NULL)
	{
		swTrace("[swFactoryProcess_create] malloc[2] fail\n");
		return --step;
	}
	this->worker_num = worker_num;
	this->worker_pti = 0;
	factory->object = this;
	factory->dispatch = swFactoryProcess_dispatch;
	factory->finish = swFactoryProcess_finish;
	factory->start = swFactoryProcess_start;
	factory->shutdown = swFactoryProcess_shutdown;

	factory->onTask = NULL;
	factory->onFinish = NULL;
	return SW_OK;
}

int swFactoryProcess_shutdown(swFactory *factory)
{
	swFactoryProcess *this = factory->object;
	int i;
	//kill all child process
	for (i = 0; i < this->worker_num; i++)
	{
		swTrace("[Main]kill worker processor\n");
		kill(this->workers[i].pid, SIGTERM);
	}
	free(this->workers);
	free(this->writers);
	free(this);
	return SW_OK;
}

int swFactoryProcess_start(swFactory *factory)
{
	int ret, step = 0;
	ret = swFactory_check_callback(factory);
	if (ret < 0)
	{
		return --step;
	}
	ret = swFactoryProcess_writer_start(factory);
	if (ret < 0)
	{
		return --step;
	}
	ret = swFactoryProcess_worker_start(factory);
	if (ret < 0)
	{
		return --step;
	}
	return SW_OK;
}

//create worker child proccess
static int swFactoryProcess_worker_start(swFactory *factory)
{
	swFactoryProcess *this = factory->object;
	int i, ret = 0;

	for (i = 0; i < this->worker_num; i++)
	{
		printf("[Main]spawn worker processor\n");
		ret = swFactoryProcess_worker_spawn(factory, (i % this->writer_num), i);
	}
	return SW_OK;
}

static int swFactoryProcess_worker_spawn(swFactory *factory, int writer_pti, int worker_pti)
{
	swFactoryProcess *this = factory->object;
	int pid;
	int pipes[2];

	if (socketpair(PF_LOCAL, SOCK_DGRAM, 0, pipes) < 0)
	{
		swTrace("[swFactoryProcess_worker_spawn]create unix socket fail\n");
		return SW_ERR;
	}

	pid = fork();
	if (pid < 0)
	{
		swTrace("[swFactoryProcess_worker_spawn]Fork Worker fail\n");
		exit(5);
	}
	//worker child processor
	else if (pid == 0)
	{
		close(pipes[0]);
		swFactoryProcess_worker_loop(factory, pipes[1]);
		exit(0);
	}
	//parent,add to writer
	else
	{
		close(pipes[1]);
		this->writers[writer_pti].reactor.add(&(this->writers[writer_pti].reactor), pipes[0], SW_FD_CONN);
		this->workers[worker_pti].pid = pid;
		this->workers[worker_pti].writer_id = writer_pti;
		this->workers[worker_pti].pipe_fd = pipes[0];
		return pid;
	}
}

int swFactoryProcess_finish(swFactory *factory, swSendData *resp)
{
	//swFactoryProcess *this = factory->object;
	swEventData send_data;
	memcpy(send_data.data, resp->data, resp->len);
	send_data.fd = resp->fd;
	send_data.len = resp->len;
	return write(c_worker_pipe, &send_data, resp->len + (3 * sizeof(int)));
}

static int swFactoryProcess_worker_loop(swFactory *factory, int c_pipe)
{
	swEventData req;
	c_worker_pipe = c_pipe;
	int n;
	//主线程
	while (1)
	{
		n = read(c_pipe, &req, sizeof(req));
		swTrace("[Worker]Recv: pipe=%d|pti=%d\n", c_pipe, req.from_id);
		if (n > 0)
		{
			factory->onTask(factory, &req);
		}
		else
		{
			swTrace("[Worker]read pipe error\n");
		}
	}
	return SW_OK;
}

int swFactoryProcess_dispatch(swFactory *factory, swEventData *data)
{
	swFactoryProcess *this = factory->object;
	int pti = this->worker_pti;
	int ret;

	if (this->worker_pti >= this->worker_num)
	{
		this->worker_pti = 0;
		pti = 0;
	}
	swTrace("[ReadThread]sendto: pipe=%d|worker=%d\n", this->workers[pti].pipe_fd, pti);
	//send to unix sock
	ret = write(this->workers[pti].pipe_fd, data, data->len + (3 * sizeof(int)));
	if(ret < 0)
	{
		return SW_ERR;
	}
	this->worker_pti++;
	return SW_OK;
}
static int swFactoryProcess_writer_start(swFactory *factory)
{
	swFactoryProcess *this = factory->object;
	swThreadParam *param;
	int i;
	pthread_t pidt;

	for (i = 0; i < this->writer_num; i++)
	{
		param = sw_malloc(sizeof(swThreadParam));
		if (param == NULL)
		{
			swTrace("malloc fail\n");
			return SW_ERR;
		}
		param->object = factory;
		param->pti = i;

		if (pthread_create(&pidt, NULL, (void * (*)(void *)) swFactoryProcess_writer_loop, (void *) param) < 0)
		{
			swTrace("pthread_create fail\n");
			return SW_ERR;
		}
		this->writers[i].ptid = pidt;
		SW_START_SLEEP;
	}
	return SW_OK;
}

int swFactoryProcess_writer_receive(swReactor *reactor, swEvent *ev)
{
	swFactory *factory = reactor->factory;
	swEventData resp;
	swSendData send_data;
	int n;

	//Unix Sock UDP
	n = read(ev->fd, &resp, sizeof(resp));
	swTrace("[WriteThread]recv: writer=%d|pipe=%d\n", ev->from_id, ev->fd);
	if (n > 0)
	{
		send_data.data = resp.data;
		send_data.len = resp.len;
		send_data.fd = resp.fd;
		return factory->onFinish(factory, &send_data);
	}
	else
	{
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
		pthread_exit((void *)param);
	}
	reactor->setHandle(reactor, SW_FD_CONN, swFactoryProcess_writer_receive);
	reactor->wait(reactor, &tmo);
	reactor->free(reactor);
	pthread_exit((void *)param);
	return SW_OK;
}

