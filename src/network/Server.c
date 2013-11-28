#include "swoole.h"
#include "Server.h"
#include "memory.h"

static void swSignalInit(void);
static int swServer_poll_loop(swThreadParam *param);
static int swServer_poll_start(swServer *serv, swReactor *main_reactor_ptr);
static int swServer_check_callback(swServer *serv);
static int swServer_listen(swServer *serv, swReactor *reactor);

static void swServer_poll_udp_loop(swThreadParam *param);
static int swServer_udp_start(swServer *serv);
static int swServer_poll_onPackage(swReactor *reactor, swEvent *event);
static int swServer_poll_onClose(swReactor *reactor, swEvent *event);
static int swServer_poll_onClose_queue(swReactor *reactor, swEventClose_queue *close_queue);
static int swServer_poll_onReceive_no_buffer(swReactor *reactor, swEvent *event);
static int swServer_poll_onReceive_conn_buffer(swReactor *reactor, swEvent *event);
static int swServer_poll_onReceive_data_buffer(swReactor *reactor, swEvent *event);

static int swServer_timer_start(swServer *serv);
static void swSignalHanlde(int sig);
static int swConnection_close(swServer *serv, int fd, int *from_id);

static int swServer_single_start(swServer *serv);
static int swServer_single_loop(swWorker *worker);
static int swServer_single_onCloseQueue(swReactor *reactor, swEventClose_queue *close_queue);
static int swServer_single_onClose(swReactor *reactor, swEvent *event);

static int swServer_master_onClose(swReactor *reactor, swDataHead *event);
static int swServer_master_onAccept(swReactor *reactor, swDataHead *event);
static int swServer_master_onTimer(swReactor *reactor, swEvent *event);

int sw_nouse_timerfd;
static swPipe timer_pipe;
swReactor *swoole_worker_reactor = NULL;

//全局变量
char swoole_running = 0;
int16_t sw_errno;
uint8_t sw_process_type; //进程类型
char sw_error[SW_ERROR_MSG_SIZE];
swAllocator *sw_memory_pool = NULL;

SWINLINE int swConnection_close(swServer *serv, int fd, int *from_id)
{
	swConnection *conn = swServer_get_connection(serv, fd);
	swReactor *from_reactor;

	if(conn == NULL)
	{
		swWarn("[Master]connection not found. fd=%d|max_fd=%d", fd, swServer_get_maxfd(serv));
		return SW_ERR;
	}
	//关闭此连接，必须放在最前面，以保证线程安全
	conn->tag = 0;

	//from_id < 0表示已经在Reactor中关闭连接了
	if((*from_id) >= 0)
	{
		from_reactor = &(serv->poll_threads[conn->from_id].reactor);
		if(from_reactor->del(from_reactor, fd) < 0)
		{
			return SW_ERR;
		}
	}
	(*from_id) = conn->from_id;

	swTrace("Close Event.fd=%d|from=%d\n", fd, (*from_id));
	if (serv->open_eof_check)
	{
		//释放buffer区
#ifdef SW_USE_CONN_BUFFER
		swConnection_clear_buffer(conn);
#else
		swDataBuffer *data_buffer = &serv->poll_threads[(*from_id)].data_buffer;
		swDataBuffer_clear(data_buffer, fd);
#endif
	}
	//重新设置max_fd,此代码为了遍历connection_list服务
	if(fd == swServer_get_maxfd(serv))
	{
		int find_max_fd = fd - 1;
		//找到第二大的max_fd作为新的max_fd
		for (; serv->connection_list[find_max_fd].tag == 0 && find_max_fd > swServer_get_minfd(serv); find_max_fd--);
		swServer_set_maxfd(serv, find_max_fd);
		swTrace("set_maxfd=%d|close_fd=%d", find_max_fd, fd);
	}
	serv->connect_count--;
	return SW_OK;
}

int swServer_master_onClose(swReactor *reactor, swEvent *event)
{
	swServer *serv = reactor->ptr;
	swFactory *factory = &(serv->factory);
	swEventClose cev_queue[SW_CLOSE_QLEN];
	swEvent notify_ev;

	int i, n, fd, from_id, ret;
	n = serv->main_pipe.read(&serv->main_pipe, cev_queue, sizeof(cev_queue));

	if (n <= 0)
	{
		swWarn("[Master]main_pipe read fail. errno=%d", errno);
		return SW_ERR;
	}

	for(i = 0; i < n/sizeof(swEventClose); i++)
	{
		fd = cev_queue[i].fd;
		from_id = cev_queue[i].from_id;

		if(swConnection_close(serv, fd, &from_id) == 0)
		{
			if(serv->onMasterClose != NULL)
			{
				serv->onMasterClose(serv, fd, cev_queue[i].from_id);
			}
			if(serv->onClose != NULL)
			{
				notify_ev.from_id = from_id;
				notify_ev.fd = cev_queue[i].fd;
				notify_ev.type = SW_EVENT_CLOSE;
				factory->notify(factory, &notify_ev);
			}
		}
	}
	return SW_OK;
}

static int swServer_master_onTimer(swReactor *reactor, swEvent *event)
{
	swServer *serv = reactor->ptr;
	if(serv->onTimer == NULL)
	{
		swWarn("serv->onTimer is NULL");
		return SW_ERR;
	}
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
	}
	swTrace("Timer Call\n");
	return ret;
}

static int swServer_master_onAccept(swReactor *reactor, swEvent *event)
{
	swServer *serv = reactor->ptr;
	swEvent connEv;
	struct sockaddr_in client_addr;
	int conn_fd, ret, c_pti;

	swTrace("[Main]accept start.event->fd=%d|event->from_id=%d", event->fd, event->from_id);
#ifdef SW_ACCEPT_AGAIN
	while (1)
#endif
	{
		//accept得到连接套接字
		conn_fd = swAccept(event->fd, &client_addr, sizeof(client_addr));

		//listen队列中的连接已全部处理完毕
		if (conn_fd < 0 && errno == EAGAIN)
		{
#ifdef SW_ACCEPT_AGAIN
			break;
#else
			return SW_OK;
#endif
		}

		//连接过多
		if(serv->connect_count >= serv->max_conn)
		{
			swWarn("too many connection");
			close(conn_fd);
			return SW_OK;
		}
		//TCP Nodelay
		if (serv->open_tcp_nodelay == 1)
		{
			int flag = 1;
			setsockopt(conn_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
		}

#ifdef SO_KEEPALIVE
		//TCP keepalive
		if(serv->open_tcp_keepalive == 1)
		{
			int keepalive = 1;
			int keep_idle = serv->tcp_keepidle;
			int keep_interval = serv->tcp_keepinterval;
			int keep_count = serv->tcp_keepcount;

#ifndef __MACH__
			setsockopt(conn_fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive , sizeof(keepalive));
			setsockopt(conn_fd, IPPROTO_TCP, TCP_KEEPIDLE, (void*)&keep_idle , sizeof(keep_idle));
			setsockopt(conn_fd, IPPROTO_TCP, TCP_KEEPINTVL, (void *)&keep_interval , sizeof(keep_interval));
			setsockopt(conn_fd, IPPROTO_TCP, TCP_KEEPCNT, (void *)&keep_count , sizeof(keep_count));
#endif

		}
#endif
		swTrace("[Main]connect from %s, by process %d\n", inet_ntoa(client_addr.sin_addr), getpid());

#if SW_REACTOR_DISPATCH == 1
		//平均分配
		c_pti = (serv->c_pti++) % serv->poll_thread_num;
#else
		//使用fd取模来散列
		c_pti = conn_fd % serv->poll_thread_num;
#endif
		ret = serv->poll_threads[c_pti].reactor.add(&(serv->poll_threads[c_pti].reactor), conn_fd, SW_FD_TCP);
		if (ret < 0)
		{
			swWarn("[Master]add event fail Errno=%d|FD=%d", errno, conn_fd);
			close(conn_fd);
			return SW_OK;
		}
		else
		{
			connEv.type = SW_EVENT_CONNECT;
			connEv.from_id = c_pti;
			connEv.fd = conn_fd;
			connEv.from_fd = event->fd;

			//增加到connection_list中
			swServer_new_connection(serv, &connEv);
			memcpy(&serv->connection_list[conn_fd].addr, &client_addr, sizeof(client_addr));
			serv->connect_count++;

			if(serv->onMasterConnect != NULL)
			{
				serv->onMasterConnect(serv, conn_fd, c_pti);
			}
			if(serv->onConnect != NULL)
			{
				serv->factory.notify(&serv->factory, &connEv);
			}
		}
	}
	return SW_OK;
}

int swServer_addTimer(swServer *serv, int interval)
{
	swTimerList_node *timer_new = sw_memory_pool->alloc(sw_memory_pool, sizeof(swTimerList_node));
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

/**
 * no use
 */
int swServer_reactor_add(swServer *serv, int fd, int sock_type)
{
	int poll_id = (serv->c_pti++) % serv->poll_thread_num;
	swReactor *reactor = &(serv->poll_threads[poll_id].reactor);
	swSetNonBlock(fd); //must be nonblock
	if(sock_type == SW_SOCK_TCP || sock_type == SW_SOCK_TCP6)
	{
		reactor->add(reactor, fd, SW_FD_TCP);
	}
	else
	{
		reactor->add(reactor, fd, SW_FD_UDP);
	}
	return SW_OK;
}

/**
 * no use
 */
int swServer_reactor_del(swServer *serv, int fd, int reacot_id)
{
	swReactor *reactor = &(serv->poll_threads[reacot_id].reactor);
	reactor->del(reactor, fd);
	return SW_OK;
}

void swServer_timer_free(swServer *serv)
{
	swTimerList_node *node;
	LL_FOREACH(serv->timer_list, node)
	{
		LL_DELETE(serv->timer_list, node);
	}
	close(serv->timer_fd);
}

static int swServer_check_callback(swServer *serv)
{
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
	if (serv->timer_list != NULL && serv->onTimer == NULL)
	{
		return SW_ERR;
	}
	return SW_OK;
}



int swServer_start_base(swServer *serv)
{
	int ret;
	if (serv->onStart != NULL)
	{
		serv->onStart(serv);
	}
	return swServer_single_start(serv);
}

int swServer_start_proxy(swServer *serv)
{
	int ret;
	swReactor *main_reactor = sw_memory_pool->alloc(sw_memory_pool, sizeof(swReactor));
	#ifdef SW_MAINREACTOR_USE_POLL
		ret = swReactorPoll_create(main_reactor, 10);
#else
		ret = swReactorSelect_create(main_reactor);
#endif
	if (ret < 0)
	{
		swWarn("Swoole reactor create fail");
		return SW_ERR;
	}
	ret = swServer_poll_start(serv, main_reactor);
	if (ret < 0)
	{
		swWarn("Swoole poll thread start fail");
		return SW_ERR;
	}

	main_reactor->id = serv->poll_thread_num; //设为一个特别的ID
	main_reactor->ptr = serv;
	main_reactor->setHandle(main_reactor, SW_FD_LISTEN, swServer_master_onAccept);
	main_reactor->setHandle(main_reactor, SW_FD_TIMER, swServer_master_onTimer);

	if (serv->timer_interval != 0)
	{
		ret = swServer_timer_start(serv);
		if (ret < 0)
		{
			return SW_ERR;
		}
		main_reactor->add(main_reactor, serv->timer_fd, SW_FD_TIMER);
	}
	//no use
	//SW_START_SLEEP;
	if (serv->onStart != NULL)
	{
		serv->onStart(serv);
	}
	struct timeval tmo;
	tmo.tv_sec = SW_MAINREACTOR_TIMEO;
	tmo.tv_usec = 0;
	return main_reactor->wait(main_reactor, &tmo);
}

int swServer_start(swServer *serv)
{
	swReactor main_reactor;
	swReactor *main_reactor_ptr = &main_reactor;
	swFactory *factory = &serv->factory;

	struct timeval tmo;
	int ret;

	ret = swServer_check_callback(serv);
	if (ret < 0)
	{
		swWarn("Swoole callback function is null.");
		return SW_ERR;
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
		swWarn("Swoole factory start fail");
		return SW_ERR;
	}
	//Signal Init
	swSignalInit();
	//标识为主进程
	sw_process_type = SW_PROCESS_MASTER;

	if(serv->factory_mode == SW_MODE_SINGLE)
	{
		ret = swServer_start_base(serv);
	}
	else
	{
		ret = swServer_start_proxy(serv);
	}

	//server stop
	if (serv->onShutdown != NULL)
	{
		serv->onShutdown(serv);
	}
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
		swWarn("Error: From_id > serv->poll_thread_num.from_id=%d", event->from_id);
		return SW_ERR;
	}
	cev.fd = event->fd;
	cev.from_id = event->from_id;
	if( serv->main_pipe.write(&(serv->main_pipe), &cev, sizeof(cev)) < 0)
	{
		swWarn("write to main_pipe fail. errno=%d|fd=%d", errno, event->fd);
		return SW_ERR;
	}
	return SW_OK;
}

void swoole_init(void)
{
	extern FILE *swoole_log_fn;
	if (swoole_running == 0)
	{
		//初始化全局内存
		sw_memory_pool = swMemoryGlobal_create(SW_GLOBAL_MEMORY_PAGESIZE, 1);
		if(sw_memory_pool == NULL)
		{
			swError("[Master] Fatal Error: create global memory fail. Errno=%d", errno);
		}
		//初始化全局变量
		swoole_running = 1;
		sw_errno = 0;
		bzero(sw_error, SW_ERROR_MSG_SIZE);
		//将日志设置为标准输出
		swoole_log_fn = stdout;
	}
}

void swoole_clean(void)
{
	//释放全局内存
	if(sw_memory_pool != NULL)
	{
		sw_memory_pool->destroy(sw_memory_pool);
		sw_memory_pool = NULL;
	}
}

/**
 * initializing server config, set default
 */
void swServer_init(swServer *serv)
{
	swoole_init();
	bzero(serv, sizeof(swServer));

	serv->backlog = SW_BACKLOG;
	serv->factory_mode = SW_MODE_BASE;
	serv->poll_thread_num = SW_THREAD_NUM;
	serv->dispatch_mode = SW_DISPATCH_FDMOD;
	serv->ringbuffer_size = SW_QUEUE_SIZE;

	serv->timeout_sec = SW_REACTOR_TIMEO_SEC;
	serv->timeout_usec = SW_REACTOR_TIMEO_USEC; //300ms;

	serv->writer_num = SW_CPU_NUM;
	serv->worker_num = SW_CPU_NUM;
	serv->max_conn = SW_MAX_FDS;
	serv->max_request = SW_MAX_REQUEST;
	serv->max_trunk_num = SW_MAX_TRUNK_NUM;

	serv->udp_sock_buffer_size = SW_UDP_SOCK_BUFSIZE;
	serv->timer_list = NULL;

	//tcp keepalive
	serv->tcp_keepcount = SW_TCP_KEEPCOUNT;
	serv->tcp_keepinterval = SW_TCP_KEEPINTERVAL;
	serv->tcp_keepidle = SW_TCP_KEEPIDLE;

	char eof[] = SW_DATA_EOF;
	serv->data_eof_len = sizeof(SW_DATA_EOF) - 1;
	memcpy(serv->data_eof, eof, serv->data_eof_len);
}
static int swServer_timer_start(swServer *serv)
{
	int timer_fd;
	struct timeval now;

	if (gettimeofday(&now, NULL) == -1)
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
	timer_set.it_value.tv_nsec = 0;
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
		swError("create timer pipe fail");
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

int swServer_new_connection(swServer *serv, swEvent *ev)
{
	int conn_fd = ev->fd;
	swConnection* connection = NULL;

	if(conn_fd > swServer_get_maxfd(serv))
	{
		swServer_set_maxfd(serv, conn_fd);
#ifdef SW_CONNECTION_LIST_EXPAND
	//新的fd超过了最大fd

		//需要扩容
		if(conn_fd == serv->connection_list_capacity - 1)
		{
			void *new_ptr = sw_shm_realloc(serv->connection_list, sizeof(swConnection)*(serv->connection_list_capacity + SW_CONNECTION_LIST_EXPAND));
			if(new_ptr == NULL)
			{
				swWarn("connection_list realloc fail");
				return SW_ERR;
			}
			else
			{
				serv->connection_list_capacity += SW_CONNECTION_LIST_EXPAND;
				serv->connection_list = (swConnection *)new_ptr;
			}
		}
#endif
	}

	connection = &(serv->connection_list[conn_fd]);
	connection->buffer_num = 0;
	connection->fd = conn_fd;
	connection->from_id = ev->from_id;
	connection->from_fd = ev->from_fd;
	connection->buffer = NULL;
	connection->tag = 1; //使此连接激活,必须在最后，保证线程安全

	return SW_OK;
}

int swServer_create_base(swServer *serv)
{
	int ret = 0;
	serv->poll_thread_num = 1;
	serv->poll_threads = sw_calloc(1, sizeof(swThreadPoll));
	if (serv->poll_threads == NULL)
	{
		swError("calloc[poll_threads] fail.alloc_size=%d", (int )(serv->poll_thread_num * sizeof(swThreadPoll)));
		return SW_ERR;
	}
	serv->connection_list = sw_calloc(serv->max_conn, sizeof(swConnection));

	if (serv->connection_list == NULL)
	{
		swError("calloc[1] fail");
		return SW_ERR;
	}
	//create factry object
	if (swFactory_create(&(serv->factory)) < 0)
	{
		swError("create factory fail\n");
		return SW_ERR;
	}
	serv->factory.ptr = serv;
	serv->factory.onTask = serv->onReceive;
	//线程模式
	if (serv->have_udp_sock == 1)
	{
		serv->factory.onFinish = swServer_onFinish2;
	}
	else
	{
		serv->factory.onFinish = swServer_onFinish;
	}
	return SW_OK;
}

int swServer_create_proxy(swServer *serv)
{
	int ret = 0;
	//初始化master pipe
#ifdef SW_MAINREACTOR_USE_UNSOCK
	ret = swPipeUnsock_create(&serv->main_pipe, 0, SOCK_STREAM);
#else
	ret = swPipeBase_create(&serv->main_pipe, 0);
#endif

	if (ret < 0)
	{
		swError("[swServerCreate]create event_fd fail");
		return SW_ERR;
	}

	//初始化poll线程池
	serv->poll_threads = sw_memory_pool->alloc(sw_memory_pool, (serv->poll_thread_num * sizeof(swThreadPoll)));
	if (serv->poll_threads == NULL)
	{
		swError("calloc[poll_threads] fail.alloc_size=%d", (int )(serv->poll_thread_num * sizeof(swThreadPoll)));
		return SW_ERR;
	}

	serv->connection_list = sw_shm_calloc(serv->max_conn, sizeof(swConnection));
	if (serv->connection_list == NULL)
	{
		swError("calloc[1] fail");
		return SW_ERR;
	}

	//create factry object
	if (serv->factory_mode == SW_MODE_THREAD)
	{
		if (serv->writer_num < 1)
		{
			swError("Fatal Error: serv->writer_num < 1");
			return SW_ERR;
		}
		ret = swFactoryThread_create(&(serv->factory), serv->writer_num);
	}
	else if (serv->factory_mode == SW_MODE_PROCESS)
	{
		if (serv->writer_num < 1 || serv->worker_num < 1)
		{
			swError("Fatal Error: serv->writer_num < 1 or serv->worker_num < 1");
			return SW_ERR;
		}
//		if (serv->max_request < 1)
//		{
//			swError("Fatal Error: serv->max_request < 1");
//			return SW_ERR;
//		}
		serv->factory.max_request = serv->max_request;
		ret = swFactoryProcess_create(&(serv->factory), serv->writer_num, serv->worker_num);
	}
	else
	{
		ret = swFactory_create(&(serv->factory));
	}

	if (ret < 0)
	{
		swError("create factory fail\n");
		return SW_ERR;
	}
	serv->factory.ptr = serv;
	serv->factory.onTask = serv->onReceive;
	//线程模式
	if (serv->have_udp_sock == 1 && serv->factory_mode != SW_MODE_PROCESS)
	{
		serv->factory.onFinish = swServer_onFinish2;
	}
	else
	{
		serv->factory.onFinish = swServer_onFinish;
	}
	return SW_OK;
}

int swServer_create(swServer *serv)
{
	//EOF最大长度为8字节
	if (serv->data_eof_len > sizeof(serv->data_eof))
	{
		serv->data_eof_len = sizeof(serv->data_eof);
	}
	//初始化日志
	if(serv->log_file[0] != 0)
	{
		swLog_init(serv->log_file);
	}
	if(serv->factory_mode == SW_MODE_SINGLE)
	{
		return swServer_create_base(serv);
	}
	else
	{
		return swServer_create_proxy(serv);
	}
}

int swServer_shutdown(swServer *serv)
{
	//stop all thread
	swoole_running = 0;
	return SW_OK;
}

int swServer_free(swServer *serv)
{
	//factory释放
	if (serv->factory.shutdown != NULL)
	{
		serv->factory.shutdown(&(serv->factory));
	}

	//reactor释放
	if (serv->reactor.free != NULL)
	{
		serv->reactor.free(&(serv->reactor));
	}

	//master pipe
	if (serv->main_pipe.close != NULL)
	{
		serv->main_pipe.close(&serv->main_pipe);
	}

	//定时器释放
	if (serv->timer_interval != 0)
	{
		swServer_timer_free(serv);
	}

	//connection_list释放
	if (serv->factory_mode == SW_MODE_SINGLE)
	{
		sw_free(serv->connection_list);
	}
	else
	{
		sw_shm_free(serv->connection_list);
	}

	//close log file
	if(serv->log_file[0] != 0)
	{
		swLog_free();
	}

	swoole_clean();
	return SW_OK;
}

static int swServer_udp_start(swServer *serv)
{
	swThreadParam *param;
	pthread_t pidt;
	swListenList_node *listen_host;

	LL_FOREACH(serv->listen_list, listen_host)
	{
		param = sw_memory_pool->alloc(sw_memory_pool, sizeof(swThreadParam));
		//UDP
		if (listen_host->type == SW_SOCK_UDP || listen_host->type == SW_SOCK_UDP6)
		{
			serv->connection_list[listen_host->sock].addr.sin_port = listen_host->port;
			param->object = serv;
			param->pti = listen_host->sock;

			if (pthread_create(&pidt, NULL, (void * (*)(void *)) swServer_poll_udp_loop, (void *) param) < 0)
			{
				swWarn("pthread_create[udp_listener] fail");
				return SW_ERR;
			}
			pthread_detach(pidt);
		}
	}
	return SW_OK;
}

static int swServer_poll_start(swServer *serv, swReactor *main_reactor_ptr)
{
	swThreadParam *param;
	swThreadPoll *poll_threads;
	pthread_t pidt;
	swListenList_node *listen_host;

	int i, ret;
	//listen UDP
	if(serv->have_udp_sock == 1)
	{
		swServer_udp_start(serv);
	}
	//listen TCP
	if (serv->have_tcp_sock == 1)
	{
		//listen server socket
		ret = swServer_listen(serv, main_reactor_ptr);
		if (ret < 0)
		{
			return SW_ERR;
		}

		for (i = 0; i < serv->poll_thread_num; i++)
		{
			poll_threads = &(serv->poll_threads[i]);
			param = sw_memory_pool->alloc(sw_memory_pool, sizeof(swThreadParam));
			if (param == NULL)
			{
				swError("malloc fail\n");
				return SW_ERR;
			}
			param->object = serv;
			param->pti = i;
			if(pthread_create(&pidt, NULL, (void * (*)(void *)) swServer_poll_loop, (void *) param) < 0)
			{
				swWarn("pthread_create[tcp_reactor] fail");
			}
			pthread_detach(pidt);
			poll_threads->ptid = pidt;
		}
	}
	main_reactor_ptr->setHandle(main_reactor_ptr, SW_FD_CLOSE, swServer_master_onClose);
	main_reactor_ptr->add(main_reactor_ptr, serv->main_pipe.getFd(&serv->main_pipe, 0), SW_FD_CLOSE);
	//wait poll thread
	SW_START_SLEEP;
	return SW_OK;
}
/**
 * only tcp
 */
int swServer_onFinish(swFactory *factory, swSendData *resp)
{
	return swWrite(resp->info.fd, resp->data, resp->info.len);
}

int swServer_send_udp_packet(swServer *serv, swSendData *resp)
{
	int count, ret;
	struct sockaddr_in to_addr;
	to_addr.sin_family = AF_INET;
	to_addr.sin_port = htons((unsigned short) resp->info.from_id); //from_id is port
	to_addr.sin_addr.s_addr = resp->info.fd; //from_id is port
	int sock = resp->info.from_fd;

	for (count = 0; count < SW_WORKER_SENDTO_COUNT; count++)
	{
		ret = sendto(sock, resp->data, resp->info.len, MSG_DONTWAIT, (struct sockaddr *) &to_addr, sizeof(to_addr));
		if (ret == 0)
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
	return ret;
}

/**
 * for udp + tcp
 */
int swServer_onFinish2(swFactory *factory, swSendData *resp)
{
	swServer *serv = factory->ptr;
	swThreadPoll *poll_thread = &(serv->poll_threads[resp->info.from_id]);
	int ret;
	swUdpFd *fd;
	//UDP
	if (resp->info.from_id >= serv->poll_thread_num)
	{
		ret = swServer_send_udp_packet(serv, resp);
	}
	else
	{
		ret = swWrite(resp->info.fd, resp->data, resp->info.len);
	}
	if (ret < 0)
	{
		swWarn("[Writer]sendto client fail. errno=%d", errno);
	}
	return ret;
}

/**
 * UDP监听线程
 */
static void swServer_poll_udp_loop(swThreadParam *param)
{
	int ret;
	swServer *serv = param->object;
	swFactory *factory = &(serv->factory);

	swEventData buf;
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);

	//使用pti保存fd
	int sock = param->pti;

	//阻塞读取UDP
	swSetBlock(sock);

	bzero(&buf.info, sizeof(buf.info));
	buf.info.from_fd = sock;

	while (swoole_running == 1)
	{
		ret = recvfrom(sock, buf.data, SW_BUFFER_SIZE, 0, &addr, &addrlen);
		if (ret > 0)
		{
			buf.info.len = ret;
			//UDP的from_id是PORT，FD是IP
			buf.info.from_id = ntohs(addr.sin_port); //转换字节序
			buf.info.fd = addr.sin_addr.s_addr;

			swTrace("recvfrom udp socket.fd=%d|data=%s", sock, buf.data);
			ret = factory->dispatch(factory, &buf);
			if (ret < 0)
			{
				swWarn("factory->dispatch[udp packet] fail\n");
			}
		}
	}
	pthread_exit(0);
}

static int swServer_single_start(swServer *serv)
{
	int i, ret;
	int status;

	swProcessPool ma;
	swProcessPool_create(&ma, serv->worker_num);

	for (i = 0; i < serv->worker_num; i++)
	{
		swProcessPool_add_worker(&ma, swServer_single_loop);
		//保存swServer的指针
		swProcessPool_worker((&ma), i).ptr = serv;
	}

	//listen UDP
	if (serv->have_udp_sock == 1)
	{
		swListenList_node *listen_host;
		LL_FOREACH(serv->listen_list, listen_host)
		{
			//UDP
			if (listen_host->type == SW_SOCK_UDP || listen_host->type == SW_SOCK_UDP6)
			{
				serv->connection_list[listen_host->sock].addr.sin_port = listen_host->port;
			}
		}
	}
	//listen TCP
	if (serv->have_tcp_sock == 1)
	{
		//listen server socket
		ret = swServer_listen(serv, NULL);
		if (ret < 0)
		{
			return SW_ERR;
		}
	}

	return swProcessPool_run(&ma);
}

static int swServer_single_loop(swWorker *worker)
{
	int ret;
	swServer *serv = worker->ptr;
	swReactor *reactor = &(serv->poll_threads[0].reactor);
#ifdef HAVE_EPOLL
	ret = swReactorEpoll_create(reactor, serv->max_conn);
#elif defined(HAVE_KQUEUE)
	ret = swReactorKqueue_create(reactor, serv->max_conn);
#else
	ret = swReactorPoll_create(reactor, serv->max_conn);
#endif
	if (ret < 0)
	{
		swWarn("Swoole reactor create fail");
		return SW_ERR;
	}

	swListenList_node *listen_host;
	int type;
	LL_FOREACH(serv->listen_list, listen_host)
	{
		type = (listen_host->type == SW_SOCK_UDP || listen_host->type == SW_SOCK_UDP6) ? SW_FD_UDP : SW_FD_LISTEN;
		reactor->add(reactor, listen_host->sock, type);
	}
	swoole_worker_reactor = reactor;

	reactor->id = 0;
	reactor->ptr = serv;
	reactor->setHandle(reactor, SW_FD_LISTEN, swServer_master_onAccept);
	reactor->setHandle(reactor, SW_FD_TIMER, swServer_master_onTimer);
	reactor->setHandle(reactor, SW_FD_CLOSE, swServer_single_onClose);
	reactor->setHandle(reactor, SW_FD_CLOSE_QUEUE, swServer_single_onCloseQueue);
	reactor->setHandle(reactor, SW_FD_UDP, swServer_poll_onPackage);
	reactor->setHandle(reactor, SW_FD_TCP, (serv->open_eof_check == 0)?swServer_poll_onReceive_no_buffer:swServer_poll_onReceive_conn_buffer);

	struct timeval timeo;
	if (serv->onWorkerStart != NULL)
	{
		serv->onWorkerStart(serv, 0);
	}
	timeo.tv_sec = SW_MAINREACTOR_TIMEO;
	timeo.tv_usec = 0;
	reactor->wait(reactor, &timeo);
	return SW_OK;
}

static int swServer_single_onClose(swReactor *reactor, swEvent *event)
{
	swServer *serv = reactor->ptr;
	swFactory *factory = &(serv->factory);
	swEvent notify_ev;

	if(swConnection_close(serv, event->fd, &(event->from_id)) == 0)
	{
		if(serv->onClose != NULL)
		{
			serv->onClose(serv, event->fd, &(event->from_id));
		}
		serv->connect_count--;
	}
	return SW_OK;
}

static int swServer_single_onCloseQueue(swReactor *reactor, swEventClose_queue *close_queue)
{
	swServer *serv = reactor->ptr;
	swFactory *factory = &(serv->factory);
	swEvent notify_ev;
	int ret, i;
	int fd, from_id = -1;

	for(i=0;i<close_queue->num;i++)
	{
		fd = close_queue->events[i].fd;
		if(swConnection_close(serv, fd, &from_id) == 0)
		{
			if(serv->onClose != NULL)
			{
				serv->onClose(serv, fd, 0);
			}
		}
	}
	return SW_OK;
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
			swWarn("pthread_setaffinity_np set fail\n");
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

	swSingalNone();

	timeo.tv_sec = serv->timeout_sec;
	timeo.tv_usec = serv->timeout_usec; //300ms
	reactor->ptr = serv;
	reactor->id = pti;
	reactor->setHandle(reactor, SW_FD_CLOSE, swServer_poll_onClose);
	reactor->setHandle(reactor, SW_FD_CLOSE_QUEUE, swServer_poll_onClose_queue);
	reactor->setHandle(reactor, SW_FD_UDP, swServer_poll_onPackage);

	//Thread mode must copy the data.
	//will free after onFinish
	if (serv->open_eof_check == 0)
	{
		reactor->setHandle(reactor, SW_FD_TCP, swServer_poll_onReceive_no_buffer);
	}
	else
	{
#ifdef SW_USE_CONN_BUFFER
		reactor->setHandle(reactor, SW_FD_TCP, swServer_poll_onReceive_conn_buffer);
#else
		reactor->setHandle(reactor, SW_FD_TCP, swServer_poll_onReceive_data_buffer);
		this->data_buffer.trunk_size = SW_BUFFER_SIZE;
		this->data_buffer.max_trunk = serv->max_trunk_num;
#endif
	}
	//main loop
	reactor->wait(reactor, &timeo);
	//shutdown
	reactor->free(reactor);
	pthread_exit(0);
	return SW_OK;
}

static int swServer_poll_onReceive_data_buffer(swReactor *reactor, swEvent *event)
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
		swEvent closeEv;
		memcpy(&closeEv, event, sizeof(swEvent));
		closeEv.type = SW_EVENT_CLOSE;
		return swServer_close(serv, event);
	}
	else
	{
		trunk->len = n;
//		trunk->data[trunk->len] = 0; //TODO 这里是为了printf
//		printf("buffer------------: %s|fd=%d|len=%d\n", trunk->data, event->fd, trunk->len);

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
			send_data.info.fd = event->fd;
			send_data.info.from_id = event->from_id;
			swDataBuffer_trunk *send_trunk = buffer_item->first;
			while (send_trunk != NULL && send_trunk->len != 0)
			{
				send_data.info.len = send_trunk->len;
				memcpy(send_data.data, send_trunk->data, send_data.info.len);
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

/**
 * for udp
 */
static int swServer_poll_onPackage(swReactor *reactor, swEvent *event)
{
	int ret;
	swServer *serv = reactor->ptr;
	swFactory *factory = &(serv->factory);
	swEventData buf;

	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	while (1)
	{
		ret = recvfrom(event->fd, buf.data, SW_BUFFER_SIZE, 0, &addr, &addrlen);
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
	buf.info.len = ret;
	//UDP的from_id是PORT，FD是IP
	buf.info.from_fd = event->fd; //from fd
	buf.info.from_id = ntohs(addr.sin_port); //转换字节序
	buf.info.fd = addr.sin_addr.s_addr;
	swTrace("recvfrom udp socket.fd=%d|data=%s", sock, buf.data);
	ret = factory->dispatch(factory, &buf);
	if (ret < 0)
	{
		swWarn("factory->dispatch[udp packet] fail\n");
	}
	return SW_OK;
}

static int swServer_poll_onReceive_conn_buffer(swReactor *reactor, swEvent *event)
{
	int ret, n;
	int isEOF = -1;

	swServer *serv = reactor->ptr;
	swFactory *factory = &(serv->factory);
	swConnection *connection = swServer_get_connection(serv, event->fd);
	swEvent closeEv;
	swConnBuffer *buffer = swConnection_get_buffer(connection);

	if(buffer==NULL)
	{
		return SW_ERR;
	}
	n = swRead(event->fd, buffer->data.data + buffer->data.info.len, SW_BUFFER_SIZE - buffer->data.info.len);
	if (n < 0)
	{
		swWarn("swRead error: %d\n", errno);
		return SW_ERR;
	}
	else if (n == 0)
	{
		swTrace("Close Event.FD=%d|From=%d\n", event->fd, event->from_id);
		memcpy(&closeEv, event, sizeof(swEvent));
		closeEv.type = SW_EVENT_CLOSE;
		return swServer_close(serv, event);
	}
	else
	{
		buffer->data.info.len += n;
		buffer->data.data[buffer->data.info.len] = 0; //这里是为了printf
//		printf("buffer------------: %s|fd=%d|len=%d\n", buffer->data.data, event->fd, buffer->data.info.len);

		if (serv->open_eof_check == 1)
		{
			isEOF = memcmp(buffer->data.data + buffer->data.info.len - serv->data_eof_len, serv->data_eof, serv->data_eof_len);
		}
		printf("buffer ok.isEOF=%d\n", isEOF);
//		if (sw_errno == EAGAIN)
//		{
//			goto recv_data;
//		}

		//收到EOF，或buffer区已满
		if (isEOF == 0)
		{
			buffer->data.info.fd = event->fd;
			buffer->data.info.from_id = event->from_id;
			ret = factory->dispatch(factory, &buffer->data);
			//清理buffer
			swConnection_clear_buffer(connection);
			//处理数据失败，数据将丢失
			if (ret < 0)
			{
				swWarn("factory->dispatch fail\n");
			}
		}
	}
	return SW_OK;
}
static int swServer_poll_onReceive_no_buffer(swReactor *reactor, swEvent *event)
{
	int ret, n;
	swServer *serv = reactor->ptr;
	swFactory *factory = &(serv->factory);

	struct
	{
		/**
		 * For Message Queue
		 * 这里多一个long int 就可以直接插入到队列中，不需要内存拷贝
		 */
		long queue_type;
		swEventData buf;
	} rdata;

	n = swRead(event->fd, rdata.buf.data, SW_BUFFER_SIZE);
	if (n < 0)
	{
		if (errno == EAGAIN)
		{
			return SW_OK;
		}
		else
		{
			swWarn("Read from socket[%d] fail. Error: %s [%d]", event->fd, strerror(errno), errno);
			return SW_ERR;
		}
	}
	//需要检测errno来区分是EAGAIN还是ECONNRESET
	else if (n == 0)
	{
		swTrace("Close Event.FD=%d|From=%d\n", event->fd, event->from_id);
		swEvent closeEv;
		memcpy(&closeEv, event, sizeof(swEvent));
		closeEv.type = SW_EVENT_CLOSE;
		return swServer_close(serv, event);
	}
	else
	{
		swTrace("recv: %s|fd=%d|len=%d\n", buf.data, event->fd, n);
		rdata.buf.info.fd = event->fd;
		rdata.buf.info.len = n;
		rdata.buf.info.from_id = event->from_id;

		ret = factory->dispatch(factory, &rdata.buf);
		//处理数据失败，数据将丢失
		if (ret < 0)
		{
			swWarn("factory->dispatch fail.errno=%d|sw_errno=%d", errno, sw_errno);
		}
		if (sw_errno == SW_OK)
		{
			return ret;
		}
		//缓存区还有数据没读完，继续读，EPOLL的ET模式
		else if (sw_errno == EAGAIN)
		{
			swWarn("sw_errno == EAGAIN");
			ret = swServer_poll_onReceive_no_buffer(reactor, event);
		}
		return ret;
	}
	return SW_OK;
}

static int swServer_poll_onClose(swReactor *reactor, swEvent *event)
{
	swServer *serv = reactor->ptr;
	//swFactory *factory = &(serv->factory);
	return swServer_close(serv, event);
}

static int swServer_poll_onClose_queue(swReactor *reactor, swEventClose_queue *close_queue)
{
	swServer *serv = reactor->ptr;
	int ret;
	//swFactory *factory = &(serv->factory);
	while (1)
	{
		ret = serv->main_pipe.write(&(serv->main_pipe), close_queue->events, sizeof(swEventClose) * close_queue->num);
		if (ret < 0)
		{
			//close事件缓存区满了，必须阻塞写入
			if (errno == EAGAIN && close_queue->num == SW_CLOSE_QLEN)
			{
				//切换一次进程
				swYield();
				continue;
			}
			else if (errno == EINTR)
			{
				continue;
			}
		}
		break;
	}
	if (ret < 0)
	{
		swWarn("CloseQueue: write to main_pipe fail. errno=%d", errno);
		return SW_ERR;
	}
	return SW_OK;
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
	swListenList_node *listen_host = sw_memory_pool->alloc(sw_memory_pool, sizeof(swListenList_node));
	listen_host->type = type;
	listen_host->port = port;
	listen_host->sock = 0;
	bzero(listen_host->host, SW_HOST_MAXSIZE);
	strncpy(listen_host->host, host, SW_HOST_MAXSIZE);
	LL_APPEND(serv->listen_list, listen_host);

	//UDP需要提前创建好
	if (type == SW_SOCK_UDP || type == SW_SOCK_UDP6)
	{
		int sock = swSocket_listen(type, listen_host->host, port, serv->backlog);
		if(sock < 0)
		{
			return SW_ERR;
		}
		//设置UDP缓存区尺寸，高并发UDP服务器必须设置
		int bufsize = serv->udp_sock_buffer_size;
		setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
		setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

		listen_host->sock = sock;
		serv->have_udp_sock = 1;
	}
	else
	{
		serv->have_tcp_sock = 1;
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
		//UDP
		if (listen_host->type == SW_SOCK_UDP || listen_host->type == SW_SOCK_UDP6)
		{
			//设置到fdList中，发送UDP包时需要
			serv->connection_list[listen_host->sock].fd = listen_host->sock;
			continue;
		}
		//TCP
		sock = swSocket_listen(listen_host->type, listen_host->host, listen_host->port, serv->backlog);
		if (sock < 0)
		{
			LL_DELETE(serv->listen_list, listen_host);
			return SW_ERR;
		}
		if(reactor!=NULL)
		{
			reactor->add(reactor, sock, SW_FD_LISTEN);
		}
		listen_host->sock = sock;
		//将server socket也放置到connection_list中
		serv->connection_list[sock].addr.sin_port = listen_host->port;
	}
	//将最后一个fd作为minfd和maxfd
	swServer_set_minfd(serv, sock);
	swServer_set_maxfd(serv, sock);
	return SW_OK;
}

int swServer_get_manager_pid(swServer *serv)
{
	if (SW_MODE_PROCESS != serv->factory_mode)
	{
		return SW_ERR;
	}
	swFactoryProcess *object = serv->factory.object;
	return object->manager_pid;
}

int swServer_reload(swServer *serv)
{
	int manager_pid = swServer_get_manager_pid(serv);
	if (manager_pid > 0)
	{
		return kill(manager_pid, SIGUSR1);
	}
	return SW_ERR;
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
