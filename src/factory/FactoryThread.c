#include "swoole.h"
#include "RingBuffer.h"

typedef struct _swFactoryThread
{
	int writer_num;
	int writer_pti;
	swRingBuffer *buffers;
	swThreadWriter *writers;
} swFactoryThread;

static int swFactoryThread_writer_loop(swThreadParam *param);

int swFactoryThread_create(swFactory *factory, int writer_num)
{
	swFactoryThread *this;
	this = sw_calloc(writer_num, sizeof(swFactoryThread));
	if (this == NULL)
	{
		swTrace("malloc[0] fail\n");
		return SW_ERR;
	}
	this->writers = sw_calloc(writer_num, sizeof(swThreadWriter));
	if (this->writers == NULL)
	{
		swTrace("[swFactoryProcess_create] malloc[1] fail\n");
		return SW_ERR;
	}
	this->buffers = sw_calloc(writer_num, sizeof(swRingBuffer));
	if (this->buffers == NULL)
	{
		swTrace("[swFactoryProcess_create] malloc[2] fail\n");
		return SW_ERR;
	}
	this->writer_num = writer_num;
	this->writer_pti = 0;

	factory->running = 1;
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
			return SW_ERR;
		}
		param = sw_malloc(sizeof(swThreadParam));
		if (param == NULL)
		{
			return SW_ERR;
		}
		param->object = factory;
		param->pti = i;
		if (pthread_create(&pidt, NULL, (void * (*)(void *)) swFactoryThread_writer_loop, (void *) param) < 0)
		{
			swTrace("pthread_create fail\n");
			return --step;
		}
		swRingBuffer_init(&(this->buffers[i]));
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
	int pti;
	//使用pti，避免线程切换造成错误的writer_pti
	pti = this->writer_pti;
	if (this->writer_pti >= this->writer_num)
	{
		this->writer_pti = 0;
		pti = 0;
	}
	swTrace("[Thread #%ld]write to client.fd=%d|str=%s", pthread_self(), buf->fd, buf->data);
	//send data ptr. use event_fd

	if(swRingBuffer_push(&(this->buffers[pti]), buf) < 0)
	{
		swTrace("swRingBuffer_push fail.Buffer is full.Writer=%d\n", pti);
		return SW_ERR;
	}
	else
	{
		write(this->writers[pti].evfd, &buf, sizeof(&buf));
		this->writer_pti++;
		return SW_OK;
	}
}

static int swFactoryThread_writer_loop(swThreadParam *param)
{
	swFactory *factory = param->object;
	swFactoryThread *this = factory->object;
	int pti = param->pti;
	swEventData *req;
	uint64_t flag;

	//main loop
	while (swoole_running > 0)
	{
		if(swRingBuffer_pop(&(this->buffers[pti]), (void **)&req)==0)
		{
			factory->onTask(factory, req);
			sw_free(req);
		}
		else
		{
			read(this->writers[pti].evfd, &flag, sizeof(flag));
		}
	}
	factory->running = 0;
	//shutdown
	close(this->writers[pti].evfd);
	sw_free(param);
	pthread_exit(SW_OK);
	return SW_OK;
}
