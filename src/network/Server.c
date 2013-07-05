#include "swoole.h"
#include "Server.h"

static void swSignalInit(void);
static int swServer_poll_loop(swThreadParam *param);
static int swServer_poll_start(swServer *serv);
static int swServer_check_callback(swServer *serv);
static int swServer_listen(swServer *serv, swReactor *reactor);
static int swServer_poll_onClose(swReactor *reactor, swEvent *event);
static int swServer_poll_onReceive_no_buffer(swReactor *reactor, swEvent *event);
static int swServer_poll_onReceive(swReactor *reactor, swEvent *event);
static int swServer_poll_onPackage(swReactor *reactor, swEvent *event);
static int swServer_timer_start(swServer *serv);
static void swSignalHanlde(int sig);

int sw_nouse_timerfd;
swPipe timer_pipe;

int swServer_onClose(swReactor *reactor, swEvent *event)
{
	swServer *serv = reactor->ptr;
	swEventClose cev;
	swReactor *from_reactor;
	int ret;
	ret = serv->main_pipe.read(&serv->main_pipe, &cev, sizeof(uint64_t));
	if (ret < 0)
	{
		return SW_ERR;
	} swTrace("Close Event.fd=%d|from=%d\n", cev.fd, cev.from_id);
	serv->onClose(serv, cev.fd, cev.from_id);
	from_reactor = &(serv->poll_threads[cev.from_id].reactor);
	from_reactor->del(from_reactor, cev.fd);
	if (serv->open_eof_check)
	{
		//释放buffer区
		swDataBuffer *data_buffer = &serv->poll_threads[event->from_id].data_buffer;
		swDataBuffer_clear(data_buffer, cev.fd);
	}
	return close(cev.fd);
}

int swServer_onTimer(swReactor *reactor, swEvent *event)
{
	swServer *serv = reactor->ptr;
	uint64_t exp;
	int ret;
	swTimerList_node *timer_node;
	time_t now;

	time(&now);
	ret = read(serv->timer_fd, &exp, sizeof(uint64_t));
	if (ret < 0)
	{
		return SW_ERR;
	}
	LL_FOREACH(serv->timer_list, timer_node)
	{
		if (timer_node->lasttime < now - timer_node->interval)
		{
			serv->onTimer(serv, timer_node->interval);
			timer_node->lasttime += timer_node->interval;
		}
	}swTrace("Timer Call\n");
	return ret;
}

int swServer_onAccept(swReactor *reactor, swEvent *event)
{
	swServer *serv = reactor->ptr;
	struct sockaddr_in client_addr;
	int conn_fd, ret, c_pti;

	swTrace("[Main]accept start\n");
#ifdef SW_ACCEPT_AGAIN
	while (1)
#endif
	{
		//accept得到连接套接字
		conn_fd = swAccept(event->fd, &client_addr, sizeof(client_addr));
#ifdef SW_ACCEPT_AGAIN
		//listen队列中的连接已全部处理完毕
		if (conn_fd < 0 && errno == EAGAIN)
		{
			break;
		}
#endif
		//TCP Nodelay
		if (serv->open_tcp_nodelay == 1)
		{
			int flag = 1;
			setsockopt(conn_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
		}
		swTrace("[Main]connect from %s, by process %d\n", inet_ntoa(client_addr.sin_addr), getpid());

#if SW_REACTOR_DISPATCH == 1
		//平均分配
		if (serv->c_pti >= serv->poll_thread_num)
		{
			serv->c_pti = 0;
		}
		c_pti = serv->c_pti;
		serv->c_pti++;
#else
		//使用fd取模来散列
		c_pti = conn_fd % serv->poll_thread_num;
#endif
		ret = serv->poll_threads[c_pti].reactor.add(&(serv->poll_threads[c_pti].reactor), conn_fd, SW_FD_TCP);
		if (ret < 0)
		{
			swTrace("[Main]add event fail Errno=%d|FD=%d\n", errno, conn_fd);
		}
		serv->onConnect(serv, conn_fd, c_pti);
	}
	return SW_OK;
}

int swServer_addTimer(swServer *serv, int interval)
{
	swTimerList_node *timer_new = sw_malloc(sizeof(swTimerList_node));
	time_t now;
	time(&now);
	if (timer_new == NULL)
	{
		swWarn("malloc fail\n");
		return SW_ERR;
	}
	timer_new->lasttime = now;
	timer_new->interval = interval;
	LL_APPEND(serv->timer_list, timer_new);
	if (serv->timer_interval == 0 || interval < serv->timer_interval)
	{
		serv->timer_interval = interval;
	}
	return SW_OK;
}

void swServer_timer_free(swServer *serv)
{
	swTimerList_node *node;
	LL_FOREACH(serv->timer_list, node)
	{
		LL_DELETE(serv->timer_list, node);
		sw_free(node);
	}
	close(serv->timer_fd);
}

static int swServer_check_callback(swServer *serv)
{
	if (serv->onStart == NULL)
	{
		return SW_ERR;
	}
	if (serv->onConnect == NULL)
	{
		return SW_ERR;
	}
	if (serv->onReceive == NULL)
	{
		return SW_ERR;
	}
	if (serv->onClose == NULL)
	{
		return SW_ERR;
	}
	if (serv->onShutdown == NULL)
	{
		return SW_ERR;
	}
	if (serv->timer_list != NULL && serv->onTimer == NULL)
	{
		return SW_ERR;
	}
	return SW_OK;
}

int swServer_start(swServer *serv)
{
	swReactor main_reactor;
	swFactory *factory = &serv->factory;

	struct timeval tmo;
	int ret;

	ret = swServer_check_callback(serv);
	if (ret < 0)
	{
		swError("Callback function is null.");
		return ret;
	}
	//run as daemon
	if (serv->daemonize > 0)
	{
		if (daemon(0, 0) < 0)
		{
			return SW_ERR;
		}
	}
	ret = factory->start(factory);
	if (ret < 0)
	{
		return SW_ERR;
	}
	ret = swServer_poll_start(serv);
	if (ret < 0)
	{
		return SW_ERR;
	}
	SW_START_SLEEP;
#ifdef SW_MAINREACTOR_USE_POLL
	ret = swReactorPoll_create(&main_reactor, 10);
#else
	ret = swReactorSelect_create(&main_reactor);
#endif

	if (ret < 0)
	{
		return SW_ERR;
	}
	main_reactor.ptr = serv;
	main_reactor.id = 0;
	main_reactor.setHandle(&main_reactor, SW_EVENT_CLOSE, swServer_onClose);
	main_reactor.setHandle(&main_reactor, SW_EVENT_CONNECT, swServer_onAccept);
	main_reactor.setHandle(&main_reactor, SW_EVENT_TIMER, swServer_onTimer);

	//Signal Init
	swSignalInit();

	main_reactor.add(&main_reactor, serv->main_pipe.getFd(&serv->main_pipe, 0), SW_EVENT_CLOSE);
	if (serv->timer_interval != 0)
	{
		ret = swServer_timer_start(serv);
		if (ret < 0)
		{
			return SW_ERR;
		}
		main_reactor.add(&main_reactor, serv->timer_fd, SW_EVENT_TIMER);
	}

	SW_START_SLEEP;
	ret = swServer_listen(serv, &main_reactor);
	if (ret < 0)
	{
		return SW_ERR;
	}

	tmo.tv_sec = SW_MAINREACTOR_TIMEO;
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
	if (event->from_id > serv->poll_thread_num)
	{
		swWarn("Error: From_id > serv->poll_thread_num\n");
		return -1;
	}
	cev.fd = event->fd;
	cev.from_id = event->from_id;
	return serv->main_pipe.write(&serv->main_pipe, &cev, sizeof(cev));
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

	serv->ringbuffer_size = SW_QUEUE_SIZE;

	serv->timeout_sec = SW_REACTOR_TIMEO_SEC;
	serv->timeout_usec = SW_REACTOR_TIMEO_USEC; //300ms;

	serv->timer_interval = 0;

	serv->writer_num = SW_CPU_NUM;
	serv->worker_num = SW_CPU_NUM;
	serv->max_conn = SW_MAX_FDS;
	serv->max_request = SW_MAX_REQUEST;
	serv->max_trunk_num = SW_MAX_TRUNK_NUM;

	serv->open_udp = 0;
	serv->open_cpu_affinity = 0;
	serv->open_tcp_nodelay = 0;
	serv->open_eof_check = 0; //默认不检查EOF

	serv->udp_max_tmp_pkg = SW_MAX_TMP_PKG;
	serv->timer_list = NULL;

	char eof[] = SW_DATA_EOF;
	serv->data_eof_len = sizeof(SW_DATA_EOF) - 1;
	memcpy(serv->data_eof, eof, serv->data_eof_len);

	serv->onClose = NULL;
	serv->onConnect = NULL;
	serv->onStart = NULL;
	serv->onShutdown = NULL;
	serv->onReceive = NULL;
	serv->onTimer = NULL;
}
static int swServer_timer_start(swServer *serv)
{
	int timer_fd;
	struct timespec now;

	if (clock_gettime(CLOCK_REALTIME, &now) == -1)
	{
		swError("clock_gettime fail\n");
		return SW_ERR;
	}

#ifdef HAVE_TIMERFD
	struct itimerspec timer_set;
	memset(&timer_set, 0, sizeof(timer_set));
	timer_fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK | TFD_CLOEXEC);
	if (timer_fd < 0)
	{
		swError("create timerfd fail\n");
		return SW_ERR;
	}

	timer_set.it_value.tv_sec = now.tv_sec + serv->timer_interval;
	timer_set.it_value.tv_nsec = now.tv_nsec;
	timer_set.it_interval.tv_sec = serv->timer_interval;
	timer_set.it_interval.tv_nsec = 0;

	if (timerfd_settime(timer_fd, TFD_TIMER_ABSTIME, &timer_set, NULL) == -1)
	{
		swError("set timer fail\n");
		return SW_ERR;
	}
	serv->timer_fd = timer_fd;
	sw_nouse_timerfd = 0;
#else
	struct itimerval timer_set;
#ifdef HAVE_EVENTFD
	timer_fd = swPipeEventfd_create(&timer_pipe, 0);
#else
	timer_fd = swPipeBase_create(&timer_pipe, 0);
#endif
	if(timer_fd < 0)
	{
		swError("create timer pipe fail\n");
		return SW_ERR;
	}
	memset(&timer_set, 0, sizeof(timer_set));
	timer_set.it_value.tv_sec = serv->timer_interval;
	timer_set.it_value.tv_usec = 0;
	timer_set.it_interval.tv_sec = serv->timer_interval;
	timer_set.it_interval.tv_usec = 0;
	if(setitimer(ITIMER_REAL, &timer_set, NULL) < 0)
	{
		swError("set timer fail\n");
		return SW_ERR;
	}
	sw_nouse_timerfd = 1;
	serv->timer_fd = timer_pipe.getFd(&timer_pipe, 0);
#endif
	return SW_OK;
}
int swServer_create(swServer *serv)
{
	int ret = 0;

	swoole_running = 1;
	sw_errno = 0;
	bzero(sw_error, SW_ERROR_MSG_SIZE);

	ret = swPipeBase_create(&serv->main_pipe, 0);
	if (ret < 0)
	{
		swTrace("[swServerCreate]create event_fd fail\n");
		return SW_ERR;
	}
	//创始化线程池
	serv->poll_threads = sw_calloc(serv->poll_thread_num, sizeof(swThreadPoll));
	if (serv->poll_threads == NULL)
	{
		swError("[swServerCreate]calloc[0] fail\n");
		return SW_ERR;
	}
	//EOF最大长度为8字节
	if (serv->data_eof_len > sizeof(serv->data_eof))
	{
		serv->data_eof_len = sizeof(serv->data_eof);
	}
	//create factry object
	if (serv->factory_mode == SW_MODE_THREAD)
	{
		if (serv->writer_num < 1)
		{
			swError("serv->writer_num < 1\n");
			return SW_ERR;
		}
		ret = swFactoryThread_create(&(serv->factory), serv->writer_num);
	}
	else if (serv->factory_mode == SW_MODE_PROCESS)
	{
		if (serv->writer_num < 1 || serv->worker_num < 1)
		{
			swError("serv->writer_num < 1 or serv->worker_num < 1\n");
			return SW_ERR;
		}
		if (serv->max_request < 1)
		{
			swError("serv->max_request < 1 \n");
			return SW_ERR;
		}
		serv->factory.max_request = serv->max_request;
		ret = swFactoryProcess_create(&(serv->factory), serv->writer_num, serv->worker_num);
	}
	else
	{
		ret = swFactory_create(&(serv->factory));
	}
	if (ret < 0)
	{
		swError("[swServerCreate]create factory fail\n");
		return SW_ERR;
	}
	serv->factory.ptr = serv;
	serv->factory.onTask = serv->onReceive;
	if (serv->open_udp == 1)
	{
		serv->factory.onFinish = swServer_onFinish2;
	}
	else
	{
		serv->factory.onFinish = swServer_onFinish;
	}
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
	if (serv->poll_threads != NULL)
	{
		sw_free(serv->poll_threads);
	}
	if (serv->main_pipe.close != NULL)
	{
		serv->main_pipe.close(&serv->main_pipe);
	}
	if (serv->timer_interval != 0)
	{
		swServer_timer_free(serv);
	}
	return SW_OK;
}

static int swServer_poll_start(swServer *serv)
{
	swThreadParam *param;
	swThreadPoll *poll_thread;
	int i;
	pthread_t pidt;

	for (i = 0; i < serv->poll_thread_num; i++)
	{
		poll_thread = &(serv->poll_threads[i]);
		param = sw_malloc(sizeof(swThreadParam));
		if (param == NULL)
		{
			swError("malloc fail\n");
			return SW_ERR;
		}
		if (serv->open_udp == 1)
		{
			poll_thread->udp_addrs = sw_calloc(serv->udp_max_tmp_pkg, sizeof(swUdpFd));
			if (poll_thread->udp_addrs == NULL)
			{
				swError("malloc fail\n");
				return SW_ERR;
			}
			poll_thread->c_udp_fd = 0;
		}
		param->object = serv;
		param->pti = i;
		pthread_create(&pidt, NULL, (void * (*)(void *)) swServer_poll_loop, (void *) param);
		poll_thread->ptid = pidt;
	}
	return SW_OK;
}
/**
 * only tcp
 */
int swServer_onFinish(swFactory *factory, swSendData *resp)
{
	return swWrite(resp->fd, resp->data, resp->len);
}
/**
 * for udp + tcp
 */
int swServer_onFinish2(swFactory *factory, swSendData *resp)
{
	swServer *serv = factory->ptr;
	swThreadPoll *poll_thread = &(serv->poll_threads[resp->from_id]);
	int ret;
	swUdpFd *fd;
	//UDP
	if (resp->fd <= 0)
	{
		fd = &(poll_thread->udp_addrs[-resp->fd]);
		while (1)
		{
			ret = sendto(fd->sock, resp->data, resp->len, 0, (struct sockaddr *) &(fd->addr), sizeof(fd->addr));
			swTrace("sendto sock=%d|from_id=%d\n", fd->sock, resp->from_id);
			if (ret < 0)
			{
				if (errno == EINTR || errno == EAGAIN)
				{
					swYield();
					continue;
				}
				else
				{
					swTrace("sendto fail.errno=%d\n", errno);
				}
			}
			break;
		}
		return ret;
	}
	else
	{
		return swWrite(resp->fd, resp->data, resp->len);
	}
}
/**
 * Main Loop
 */
static int swServer_poll_loop(swThreadParam *param)
{
	swServer *serv = param->object;
	int ret, pti = param->pti;
	swReactor *reactor = &(serv->poll_threads[pti].reactor);
	swThreadPoll *this = &(serv->poll_threads[pti]);
	struct timeval timeo;

	//cpu affinity setting
#if HAVE_CPU_AFFINITY
	if(serv->open_cpu_affinity)
	{
		cpu_set_t cpu_set;
		CPU_ZERO(&cpu_set);
		CPU_SET(pti % SW_CPU_NUM, &cpu_set);
		if(0 != pthread_setaffinity_np(pthread_self(), sizeof(cpu_set), &cpu_set))
		{
			swTrace("pthread_setaffinity_np set fail\n");
		}
	}
#endif

#ifdef HAVE_EPOLL
	ret = swReactorEpoll_create(reactor, (serv->max_conn / serv->poll_thread_num) + 1);
#elif defined(HAVE_KQUEUE)
	ret = swReactorKqueue_create(reactor, (serv->max_conn / serv->poll_thread_num) + 1);
#else
	ret = swReactorPoll_create(reactor, (serv->max_conn / serv->poll_thread_num) + 1);
#endif

	if (ret < 0)
	{
		return SW_ERR;
	}
	timeo.tv_sec = serv->timeout_sec;
	timeo.tv_usec = serv->timeout_usec; //300ms
	reactor->ptr = serv;
	reactor->id = pti;
	reactor->setHandle(reactor, SW_FD_CLOSE, swServer_poll_onClose);

	//Thread mode must copy the data.
	//will free after onFinish
	if (serv->open_eof_check == 0)
	{
		reactor->setHandle(reactor, SW_FD_TCP, swServer_poll_onReceive_no_buffer);
	}
	else
	{
		reactor->setHandle(reactor, SW_FD_TCP, swServer_poll_onReceive);
		this->data_buffer.trunk_size = SW_BUFFER_SIZE;
		this->data_buffer.max_trunk = serv->max_trunk_num;
	}
	reactor->setHandle(reactor, SW_FD_UDP, swServer_poll_onPackage);
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
	int isEOF = -1;

	swServer *serv = reactor->ptr;
	swFactory *factory = &(serv->factory);
	//swDispatchData send_data;
	swEventData send_data;
	swDataBuffer_item *buffer_item = NULL;
	swDataBuffer *data_buffer = &serv->poll_threads[event->from_id].data_buffer;
	swDataBuffer_trunk *trunk;
	buffer_item = swDataBuffer_getItem(data_buffer, event->fd);

	//buffer不存在，创建一个新的buffer区
	if (buffer_item == NULL)
	{
		buffer_item = swDataBuffer_newItem(data_buffer, event->fd, SW_BUFFER_SIZE);
		if (buffer_item == NULL)
		{
			swWarn("create buffer item fail\n");
			return swServer_poll_onReceive_no_buffer(reactor, event);
		}
	}

	recv_data:
	//trunk
	trunk = swDataBuffer_getTrunk(data_buffer, buffer_item);
	n = swRead(event->fd, trunk->data, SW_BUFFER_SIZE);
	if (n < 0)
	{
		swWarn("swRead error: %d\n", errno);
		return SW_ERR;
	}
	else if (n == 0)
	{
		swTrace("Close Event.FD=%d|From=%d\n", event->fd, event->from_id);
		return swServer_close(serv, event);
	}
	else
	{
		trunk->len = n;
		trunk->data[trunk->len] = 0; //TODO 这里是为了printf
		//printf("buffer------------: %s|fd=%d|len=%d\n", trunk->data, event->fd, trunk->len);

		if (serv->open_eof_check == 1)
		{
			isEOF = memcmp(trunk->data + trunk->len - serv->data_eof_len, serv->data_eof, serv->data_eof_len);
		}
		//printf("buffer ok.isEOF=%d\n", isEOF);

		swDataBuffer_append(data_buffer, buffer_item, trunk);
		if (sw_errno == EAGAIN)
		{
			goto recv_data;
		}

		//超过buffer_size或者收到EOF
		if (buffer_item->trunk_num >= data_buffer->max_trunk || isEOF == 0)
		{
			send_data.fd = event->fd;
			send_data.from_id = event->from_id;
			/*TODO 这里需要改成直接writev写trunk
			 send_data.data = buffer_item->first;
			 ret = factory->dispatch(factory, &send_data);
			 //处理数据失败，数据将丢失
			 if (ret < 0)
			 {
			 swWarn("factory->dispatch fail\n");
			 return SW_ERR;
			 }
			 */
			swDataBuffer_trunk *send_trunk = buffer_item->first;
			while (send_trunk != NULL && send_trunk->len != 0)
			{
				send_data.len = send_trunk->len;
				memcpy(send_data.data, send_trunk->data, send_data.len);
				send_trunk = send_trunk->next;
				ret = factory->dispatch(factory, &send_data);
				//处理数据失败，数据将丢失
				if (ret < 0)
				{
					swWarn("factory->dispatch fail\n");
				}
			}
			swDataBuffer_flush(data_buffer, buffer_item);
		}
	}
	return SW_OK;
}
static int swServer_poll_onReceive_no_buffer(swReactor *reactor, swEvent *event)
{
	int ret, n;
	swServer *serv = reactor->ptr;
	swFactory *factory = &(serv->factory);
	swEventData buf;

	n = swRead(event->fd, buf.data, SW_BUFFER_SIZE);
	if (n < 0)
	{
		swTrace("swRead error: %d\n", errno);
		return SW_ERR;
	}
	else if (n == 0)
	{
		swTrace("Close Event.FD=%d|From=%d\n", event->fd, event->from_id);
		return swServer_close(serv, event);
	}
	else
	{
		swTrace("recv: %s|fd=%d|len=%d\n", buf.data, event->fd, n);
		buf.fd = event->fd;
		buf.len = n;
		buf.from_id = event->from_id;

		ret = factory->dispatch(factory, &buf);
		//处理数据失败，数据将丢失
		if (ret < 0)
		{
			swTrace("factory->dispatch fail\n");
		}
		if (sw_errno == SW_OK)
		{
			return ret;
		}
		//缓存区还有数据没读完，继续读，EPOLL的ET模式
		else if (sw_errno == EAGAIN)
		{
			ret = swServer_poll_onReceive_no_buffer(reactor, event);
		}
		return ret;
	}
	return SW_OK;
}

/**
 * for udp
 */
static int swServer_poll_onPackage(swReactor *reactor, swEvent *event)
{
	int ret;
	swServer *serv = reactor->ptr;
	swFactory *factory = &(serv->factory);
	swThreadPoll *poll_thread = &(serv->poll_threads[event->from_id]);
	swEventData buf;

	socklen_t addrlen = sizeof(poll_thread->udp_addrs[poll_thread->c_udp_fd].addr);

	while (1)
	{
		ret = recvfrom(event->fd, buf.data, SW_BUFFER_SIZE, 0, &(poll_thread->udp_addrs[poll_thread->c_udp_fd].addr),
				&addrlen);
		if (ret < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}
			return SW_ERR;
		}
		break;
	}
	poll_thread->udp_addrs[poll_thread->c_udp_fd].sock = event->fd;
	buf.fd = -poll_thread->c_udp_fd; //区分TCP和UDP
	buf.len = ret;
	buf.from_id = event->from_id;

	swTrace("recv package: %s|fd=%d|size=%d\n", buf.data, event->fd, ret);
	ret = factory->dispatch(factory, &buf);
	if (ret < 0)
	{
		swTrace("factory->dispatch fail\n");
	}
	poll_thread->c_udp_fd++;
	if (poll_thread->c_udp_fd == serv->udp_max_tmp_pkg)
	{
		poll_thread->c_udp_fd = 0;
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
	//swSignalSet(SIGINT, SIG_IGN, 1, 0);
	swSignalSet(SIGPIPE, SIG_IGN, 1, 0);
	swSignalSet(SIGUSR1, SIG_IGN, 1, 0);
	swSignalSet(SIGUSR2, SIG_IGN, 1, 0);
	swSignalSet(SIGTERM, swSignalHanlde, 1, 0);
	swSignalSet(SIGALRM, swSignalHanlde, 1, 0);
}

int swServer_addListen(swServer *serv, int type, char *host, int port)
{
	swListenList_node *listen_host = sw_malloc(sizeof(swListenList_node));
	listen_host->type = type;
	listen_host->port = port;
	listen_host->sock = 0;
	bzero(listen_host->host, SW_HOST_MAXSIZE);
	strncpy(listen_host->host, host, SW_HOST_MAXSIZE);
	LL_APPEND(serv->listen_list, listen_host);
	if (type == SW_SOCK_UDP || type == SW_SOCK_UDP6)
	{
		serv->open_udp = 1;
	}
	return SW_OK;
}

static int swServer_listen(swServer *serv, swReactor *reactor)
{
	int sock;
	int reactor_i = 0;

	swListenList_node *listen_host;
	swReactor *poll_reactor;

	LL_FOREACH(serv->listen_list, listen_host)
	{
		sock = swSocket_listen(listen_host->type, listen_host->host, listen_host->port, serv->backlog);
		if (sock < 0)
		{
			swTrace("Listen fail.type=%d|host=%s|port=%d|errno=%d\n",
					listen_host->type, listen_host->host, listen_host->port, errno);
			return SW_ERR;
		}
		//UDP
		if (listen_host->type == SW_SOCK_UDP || listen_host->type == SW_SOCK_UDP6)
		{
			poll_reactor = &(serv->poll_threads[reactor_i % serv->poll_thread_num].reactor);
			poll_reactor->add(poll_reactor, sock, SW_FD_UDP);
			reactor_i++;
		}
		//TCP
		else
		{
			reactor->add(reactor, sock, SW_EVENT_CONNECT);
		}
		listen_host->sock = sock;
	}
	return SW_OK;
}

int swServer_reload(swServer *serv)
{
	swFactoryProcess *factory;
	if (SW_MODE_PROCESS != serv->factory_mode)
	{
		return SW_ERR;
	}
	factory = serv->factory.object;
	return kill(factory->manager_pid, SIGUSR1);
}

static void swSignalHanlde(int sig)
{
	uint64_t flag = 1;
	switch (sig)
	{
	case SIGTERM:
		swoole_running = 0;
		break;
	case SIGALRM:
		if (sw_nouse_timerfd == 1)
		{
			timer_pipe.write(&timer_pipe, &flag, sizeof(flag));
		}
		break;
	default:
		break;
	}
	//swSignalInit();
}
