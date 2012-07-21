#include "swoole.h"

typedef struct _swFactoryThread
{
	int writer_num;
	int writer_pti;
	swThreadWriter *writers;
} swFactoryThread;

static int swFactoryThread_writer_loop(swThreadParam *param);

int swFactoryThread_create(swFactory *factory, int writer_num)
{
	swFactoryThread *this;
	this = sw_calloc(writer_num, sizeof(swFactoryThread));
	int step = 0;
	if (this == NULL)
	{
		swTrace("malloc[0] fail\n");
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

	factory->object = this;
	factory->dispatch = swFactoryThread_dispatch;
	factory->finish = swFactory_finish;
	factory->start = swFactoryThread_start;
	factory->shutdown = swFactoryThread_shutdown;

	factory->onTask = NULL;
	factory->onFinish = NULL;
	return SW_OK;
}

int swFactoryThread_start(swFactory *factory)
{
	swFactoryThread *this = factory->object;
	swThreadParam *param;
	int i, evfd;
	int ret, step = 0;
	pthread_t pidt;

	ret = swFactory_check_callback(factory);
	if (ret < 0)
	{
		return --step;
	}
	for (i = 0; i < this->writer_num; i++)
	{
		evfd = eventfd(0, 0);
		if (evfd < 0)
		{
			swTrace("create eventfd fail\n");
			return --step;
		}
		param = sw_malloc(sizeof(swThreadParam));
		if (param == NULL)
		{
			return --step;
		}
		param->object = factory;
		param->pti = i;
		if (pthread_create(&pidt, NULL, (void * (*)(void *)) swFactoryThread_writer_loop, (void *) param) < 0)
		{
			swTrace("pthread_create fail\n");
			return --step;
		}
		this->writers[i].ptid = pidt;
		this->writers[i].evfd = evfd;
		SW_START_SLEEP;
	}
	return SW_OK;
}
int swFactoryThread_shutdown(swFactory *factory)
{
	swoole_running = 0;
	swFactoryThread *this = factory->object;
	free(this->writers);
	free(this);
	return SW_OK;
}
/**
 * 写线程模式
 */
int swFactoryThread_dispatch(swFactory *factory, swEventData *buf)
{
	swFactoryThread *this = factory->object;
	int ret;
	int pti;
	//will switch to writer,muse copy the data
	//will free after onFinish
	swEventData *send_data = sw_malloc(sizeof(*buf));
	if (send_data == NULL)
	{
		swTrace("[swFactoryThread_dispatch]malloc fail\n");
		return SW_ERR;
	}
	bzero(send_data, sizeof(*buf));

	send_data->fd = buf->fd;
	send_data->len = buf->len;
	memcpy(send_data->data, buf->data, buf->len);

	pti = this->writer_pti;
	if (this->writer_pti >= this->writer_num)
	{
		this->writer_pti = 0;
		pti = 0;
	}

	swTrace("[Thread #%ld]write to client.fd=%d|str=%s", pthread_self(), buf->fd, buf->data);
	//send data ptr. use event_fd
	ret = write(this->writers[pti].evfd, &send_data, sizeof(&send));
	if (ret < 0)
	{
		swTrace("Error.ret=%d|writer_pti=%d\n", ret, this->writer_pti);
		return SW_ERR;
	}
	else
	{
		this->writer_pti++;
		return SW_OK;
	}
}

static int swFactoryThread_writer_loop(swThreadParam *param)
{
	swFactory *factory = param->object;
	swFactoryThread *this = factory->object;
	int pti = param->pti;
	int ret;
	swEventData *req;

	//main loop
	while (swoole_running > 0)
	{
		ret = read(this->writers[pti].evfd, &req, sizeof(&req));
		printf("[WriteThread]recv: %d|ret=%d\n", pti, ret);
		if (ret > 0)
		{
			factory->onTask(factory, req);
			sw_free(req);
		}
		else
		{
			swTrace("[swFactoryThread_writer_loop]read eventfd error");
		}
	}
	//shutdown
	close(this->writers[pti].evfd);
	sw_free(param);
	pthread_exit(SW_OK);
	return SW_OK;
}
