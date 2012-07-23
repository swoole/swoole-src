#include "swoole.h"
#include "Server.h"
#include <signal.h>

static int child_fork = 0;
static int swServer_poll_loop(swThreadParam *param);
static int swServer_poll_start(swServer *serv);
static int swServer_check_callback(swServer *serv);
static int swServer_poll_onClose(swReactor *reactor, swEvent *event);
static int swServer_poll_onReceive(swReactor *reactor, swEvent *event);
static int swServer_poll_onReceive2(swReactor *reactor, swEvent *event);

int swServer_onClose(swReactor *reactor, swEvent *event)
{
	swServer *serv = reactor->ptr;
	swEventClose cev;
	swReactor *from_reactor;
	int ret;
	ret = read(serv->event_fd, &cev, sizeof(uint64_t));
	if (ret < 0)
	{
		return SW_ERR;
	}
	swTrace("Close Event.fd=%d|from=%d\n", cev.fd, cev.from_id);
	serv->onClose(serv, cev.fd, cev.from_id);
	from_reactor = &(serv->threads[cev.from_id].reactor);
	from_reactor->del(from_reactor, cev.fd);
	ret = close(cev.fd);
	return ret;
}

int swServer_onAccept(swReactor *reactor, swEvent *event)
{
	swServer *serv = reactor->ptr;
	int clilen;
	int conn_fd;
	int ret;
	struct sockaddr_in clientaddr;
	clilen = sizeof(clientaddr);
	bzero(&clientaddr, clilen);
	swTrace("[Main]accept start\n");
	//得到连接套接字
	conn_fd = accept(serv->sock, (struct sockaddr *) &clientaddr, (socklen_t *) &clilen);
	if (conn_fd < 0)
	{
		swTrace("[Main]accept fail Errno=%d|SockFD=%d|\n", errno, serv->sock);
		return SW_ERR;
	}
	swTrace("[Main]swSetNonBlock\n");
	swSetNonBlock(conn_fd);

	char *str;
	str = inet_ntoa(clientaddr.sin_addr);
	swTrace("[Main]connect from %s, by process %d\n", str, getpid());

	if (serv->c_pti >= serv->poll_thread_num)
	{
		serv->c_pti = 0;
	}
	ret = serv->threads[serv->c_pti].reactor.add(&(serv->threads[serv->c_pti].reactor), conn_fd, SW_FD_CONN);
	if (ret < 0)
	{
		swTrace("[Main]add event fail Errno=%d|FD=%d\n", errno, conn_fd);
		return SW_ERR;
	}
	serv->onConnect(serv, conn_fd, serv->c_pti);
	serv->c_pti++;
	return SW_OK;
}

static int swServer_check_callback(swServer *serv)
{
	int step = 0;
	if (serv->onStart == NULL)
	{
		return --step;
	}
	if (serv->onConnect == NULL)
	{
		return --step;
	}
	if (serv->onReceive == NULL)
	{
		return --step;
	}
	if (serv->onClose == NULL)
	{
		return --step;
	}
	if (serv->onShutdown == NULL)
	{
		return --step;
	}
	return SW_OK;
}

int swServer_start(swServer *serv)
{
	swReactor main_reactor;
	swFactory *factory = &serv->factory;

	struct sockaddr_in serveraddr;
	struct timeval tmo;
	int ret, step = 0;
	int option;

	ret = swServer_check_callback(serv);
	if (ret < 0)
	{
		return ret;
	}
	//run as daemon
	if(serv->daemonize > 0 )
	{
		if(daemon(1, 1) < 0)
		{
			return SW_ERR;
		}
	}
	ret = factory->start(factory);
	if (ret < 0)
	{
		return ret;
	}
	ret = swServer_poll_start(serv);
	if (ret < 0)
	{
		return ret;
	}
	bzero(&serveraddr, sizeof(struct sockaddr_in));
	//设置serveraddr
	inet_aton(serv->host, &(serveraddr.sin_addr));
	serveraddr.sin_port = htons(serv->port);
	swTrace("Bind host=%s,port=%d \n", serv->host, serv->port);
	//创建监听套接字
	serv->sock = socket(AF_INET, SOCK_STREAM, 0);
	option = 1;
	setsockopt(serv->sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(int));
	if (serv->sock < 0)
	{
		swTrace("[swServerCreate]create socket fail\n");
		return --step;
	}
	//将监听套接字同sockaddr绑定
	ret = bind(serv->sock, (struct sockaddr *) &serveraddr, sizeof(struct sockaddr_in));
	if (ret != 0)
	{
		swTrace("[swServerCreate]bind fail\n");
		return --step;
	}
	//开始监听套接字
	ret = listen(serv->sock, serv->backlog);
	if (ret != 0)
	{
		swTrace("[swServerCreate]listen fail\n");
		return --step;
	}
	ret = swReactorSelect_create(&main_reactor);
	if (ret < 0)
	{
		return SW_ERR;
	}
	main_reactor.ptr = serv;
	main_reactor.setHandle(&main_reactor, SW_EVENT_CLOSE, swServer_onClose);
	main_reactor.setHandle(&main_reactor, SW_EVENT_CONNECT, swServer_onAccept);
	main_reactor.add(&main_reactor, serv->event_fd, SW_EVENT_CLOSE);
	main_reactor.add(&main_reactor, serv->sock, SW_EVENT_CONNECT);

	tmo.tv_sec = 5;
	tmo.tv_usec = 0;

	serv->onStart(serv);
	main_reactor.wait(&main_reactor, &tmo);
	serv->onShutdown(serv);
	return SW_OK;
}

/**
 * 关闭连接
 */
int swServer_close(swServer *serv, swEvent *event)
{
	swEventClose cev;
	cev.fd = event->fd;
	cev.from_id = event->from_id;
	return write(serv->event_fd, &cev, sizeof(cev));
}
/**
 * initializing server config, set default
 */
void swServer_init(swServer *serv)
{
	bzero(serv, sizeof(swServer));
	serv->backlog = SW_BACKLOG;
	serv->factory_mode = SW_MODE_CALL;
	serv->poll_thread_num = SW_THREAD_NUM;
	serv->daemonize = 0;

	serv->timeout_sec = 0;
	serv->timeout_usec = 300000; //300ms;

	serv->writer_num = SW_CPU_NUM;
	serv->worker_num = SW_CPU_NUM;
	serv->max_conn = SW_MAX_FDS;

	serv->onClose = NULL;
	serv->onConnect = NULL;
	serv->onStart = NULL;
	serv->onShutdown = NULL;
	serv->onReceive = NULL;
}
int swServer_create(swServer *serv)
{
	int ret = 0, step = 0;
	//创建event_fd
	serv->event_fd = eventfd(0, EFD_NONBLOCK);
	if (serv->event_fd < 0)
	{
		swTrace("[swServerCreate]create event_fd fail\n");
		return --step;
	}
	//创始化线程池
	serv->threads = sw_calloc(serv->poll_thread_num, sizeof(swThreadPoll));
	if (serv->threads == NULL)
	{
		swTrace("[swServerCreate]calloc[0] fail\n");
		return --step;
	}
	//create factry object
	if (serv->factory_mode == SW_MODE_THREAD)
	{
		if (serv->writer_num < 1)
		{
			swTrace("serv->writer_num < 1\n");
			return --step;
		}
		ret = swFactoryThread_create(&(serv->factory), serv->writer_num);
	}
	else if (serv->factory_mode == SW_MODE_PROCESS)
	{
		if (serv->writer_num < 1 || serv->worker_num < 1)
		{
			swTrace("serv->writer_num < 1 or serv->worker_num < 1\n");
			return --step;
		}
		ret = swFactoryProcess_create(&(serv->factory), serv->writer_num, serv->worker_num);
	}
	else
	{
		ret = swFactory_create(&(serv->factory));
	}
	if (ret < 0)
	{
		swTrace("[swServerCreate]create factory fail\n");
		return --step;
	}
	serv->factory.ptr = serv;
	serv->factory.onTask = serv->onReceive;
	serv->factory.onFinish = swServer_onFinish;
	return SW_OK;
}

int swServer_shutdown(swServer *serv)
{
	//stop all thread
	swoole_running = 0;
	return SW_OK;
}

int swServer_free(swServer *serv)
{
	if (serv->factory.shutdown != NULL)
	{
		serv->factory.shutdown(&(serv->factory));
	}
	if (serv->reactor.free != NULL)
	{
		serv->reactor.free(&(serv->reactor));
	}
	if (serv->threads != NULL)
	{
		sw_free(serv->threads);
	}
	if (serv->event_fd != 0)
	{
		close(serv->event_fd);
	}
	return SW_OK;
}

static int swServer_poll_start(swServer *serv)
{
	swThreadParam *param;
	int i;
	pthread_t pidt;

	for (i = 0; i < serv->poll_thread_num; i++)
	{
		param = sw_malloc(sizeof(swThreadParam));
		if (param == NULL)
		{
			return SW_ERR;
		}
		param->object = serv;
		param->pti = i;
		pthread_create(&pidt, NULL, (void * (*)(void *)) swServer_poll_loop, (void *) param);
		serv->threads[i].ptid = pidt;
	}
	return SW_OK;
}

int swServer_onFinish(swFactory *factory, swSendData *resp)
{
	return swWrite(resp->fd, resp->data, resp->len);
}
/**
 * Main Loop
 */
static int swServer_poll_loop(swThreadParam *param)
{
	swServer *serv = param->object;
	int ret, pti = param->pti;
	swReactor *reactor = &(serv->threads[pti].reactor);
	struct timeval timeo;

	ret = swReactorEpoll_create(reactor, (serv->max_conn / serv->poll_thread_num) + 1);
	if (ret < 0)
	{
		return SW_ERR;
	}
	timeo.tv_sec = serv->timeout_sec;
	timeo.tv_usec = serv->timeout_usec; //300ms
	reactor->ptr = serv;
	reactor->setHandle(reactor, SW_FD_CLOSE, swServer_poll_onClose);
	//Thread mode must copy the data.
	//will free after onFinish
	if(serv->factory_mode == SW_MODE_THREAD)
	{
		reactor->setHandle(reactor, SW_FD_CONN, swServer_poll_onReceive2);
	}
	else
	{
		reactor->setHandle(reactor, SW_FD_CONN, swServer_poll_onReceive);
	}
	//main loop
	reactor->wait(reactor, &timeo);
	//shutdown
	reactor->free(reactor);
	sw_free(param);
	return SW_OK;
}

static int swServer_poll_onReceive(swReactor *reactor, swEvent *event)
{
	int ret, n;
	swServer *serv = reactor->ptr;
	swFactory *factory = &(serv->factory);
	swEventData buf;
	bzero(buf.data, sizeof(buf.data));
	ret = swRead(event->fd, buf.data, SW_BUFFER_SIZE);
	if (ret < 0)
	{
		//printf("error: %d\n", errno);
		return SW_ERR;
	}
	else if (ret == 0)
	{
		swTrace("Close Event.FD=%d|From=%d\n", event->fd, event->from_id);
		return swServer_close(serv, event);
	}
	else
	{
		buf.fd = event->fd;
		buf.len = ret;
		buf.from_id = event->from_id;
		//swTrace("recv: %s|fd=%d|ret=%d|errno=%d\n", buf.data, event->fd, ret, errno);
		n = factory->dispatch(factory, &buf);
	}
	return SW_OK;
}

static int swServer_poll_onReceive2(swReactor *reactor, swEvent *event)
{
	int ret;
	swServer *serv = reactor->ptr;
	swFactory *factory = &(serv->factory);
	swEventData *buf = sw_malloc(sizeof(swEventData));
	if(buf==NULL)
	{
		swTrace("Malloc fail\n");
		return SW_ERR;
	}
	bzero(buf->data, sizeof(buf->data));
	ret = swRead(event->fd, buf->data, SW_BUFFER_SIZE);
	if (ret < 0)
	{
		swTrace("Receive Error.Fd=%d.From=%d\n", event->fd, event->from_id);
		return SW_ERR;
	}
	else if (ret == 0)
	{
		swTrace("Close Event.FD=%d|From=%d\n", event->fd, event->from_id);
		sw_free(buf);
		return swServer_close(serv, event);
	}
	else
	{
		buf->fd = event->fd;
		buf->len = ret;
		buf->from_id = event->from_id;
		//swTrace("recv: %s|fd=%d|ret=%d|errno=%d\n", buf->data, event->fd, ret, errno);
		factory->dispatch(factory, buf);
	}
	return SW_OK;
}

static int swServer_poll_onClose(swReactor *reactor, swEvent *event)
{
	swServer *serv = reactor->ptr;
	//swFactory *factory = &(serv->factory);
	return swServer_close(serv, event);
}

void swSignalInit(void)
{
	swSignalSet(SIGHUP, SIG_IGN, 1, 0);
	swSignalSet(SIGINT, SIG_IGN, 1, 0);
	swSignalSet(SIGQUIT, SIG_IGN, 1, 0);
	swSignalSet(SIGTERM, swSignalHanlde, 0, 0);
	swSignalSet(SIGCHLD, swSignalHanlde, 1, 0);
}

swSignalFunc swSignalSet(int sig, swSignalFunc func, int restart, int mask)
{
	struct sigaction act, oact;
	act.sa_handler = func;
	if (mask)
	{
		sigfillset(&act.sa_mask);
	}
	else
	{
		sigemptyset(&act.sa_mask);
	}
	act.sa_flags = 0;
	if (sigaction(sig, &act, &oact) < 0)
		return NULL;

	return oact.sa_handler;
}

void swSignalHanlde(int sig)
{
	switch (sig)
	{
	case SIGTERM:
		swoole_running = 0;
		break;
	case SIGCHLD:
		if (swoole_running > 0)
		{
			//Fork
			child_fork++;
		}
		break;
	default:
		break;
	}
	swSignalInit();
}
