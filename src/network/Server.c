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
#include "memory.h"

#include <netinet/tcp.h>

static void swSignalInit(void);

SWINLINE static void swUpdateTime(void);

#if SW_REACTOR_SCHEDULE == 3
SWINLINE static swServer_reactor_schedule(swServer *serv);
#endif

static int swServer_check_callback(swServer *serv);
static int swServer_listen(swServer *serv, swReactor *reactor);

static void swServer_poll_udp_loop(swThreadParam *param);
static int swServer_udp_start(swServer *serv);
static int swServer_poll_onPackage(swReactor *reactor, swEvent *event);

static void swServer_poll_onReactorTimeout(swReactor *reactor);
static void swServer_poll_onReactorFinish(swReactor *reactor);

static void swServer_master_onReactorTimeout(swReactor *reactor);
static void swServer_master_onReactorFinish(swReactor *reactor);

static int swServer_poll_loop(swThreadParam *param);
static int swServer_poll_start(swServer *serv, swReactor *main_reactor_ptr);
static int swServer_poll_onClose(swReactor *reactor, swEvent *event);
static int swServer_poll_close_queue(swReactor *reactor, swCloseQueue *close_queue);
static int swServer_poll_onReceive_no_buffer(swReactor *reactor, swEvent *event);
static int swServer_poll_onReceive_conn_buffer(swReactor *reactor, swEvent *event);
static int swServer_poll_onReceive_data_buffer(swReactor *reactor, swEvent *event);

static void swSignalHanlde(int sig);
SWINLINE static int swConnection_close(swServer *serv, int fd, int16_t *from_id);

static int swServer_single_start(swServer *serv);
static int swServer_single_loop(swProcessPool *pool, swWorker *worker);
static int swServer_single_onClose(swReactor *reactor, swEvent *event);

static int swServer_master_onClose(swReactor *reactor, swDataHead *event);
static int swServer_master_onAccept(swReactor *reactor, swDataHead *event);
static int swServer_onTimer(swReactor *reactor, swEvent *event);

static int swServer_start_proxy(swServer *serv);
static int swServer_start_base(swServer *serv);
static int swServer_create_proxy(swServer *serv);
static int swServer_create_base(swServer *serv);

static void swServer_heartbeat_start(swServer *serv);
static void swServer_heartbeat_check(swThreadParam *heartbeat_param);

swServerG SwooleG;
swServerGS *SwooleGS;
swWorkerG SwooleWG;

int16_t sw_errno;
char sw_error[SW_ERROR_MSG_SIZE];

SWINLINE static int swConnection_close(swServer *serv, int fd, int16_t *from_id)
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

	//from_id == SW_CLOSE_DELETE,表示已经在Reactor中关闭连接
	if((*from_id) != SW_CLOSE_DELETE)
	{
		from_reactor = &(serv->reactor_threads[conn->from_id].reactor);
		if(from_reactor->del(from_reactor, fd) < 0)
		{
			return SW_ERR;
		}
	}
	(*from_id) = conn->from_id;

	swTrace("Close Event.fd=%d|from=%d", fd, (*from_id));
	if (serv->open_eof_check)
	{
		//释放buffer区
#ifdef SW_USE_CONN_BUFFER
		swConnection_clear_buffer(conn);
#else
		swDataBuffer *data_buffer = &serv->reactor_threads[(*from_id)].data_buffer;
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

static int swServer_master_onClose(swReactor *reactor, swEvent *event)
{
	swServer *serv = reactor->ptr;
	swFactory *factory = &(serv->factory);
	swEventClose cev_queue[SW_CLOSE_QLEN];
	swEvent notify_ev;

	int i, n, fd;
	int16_t from_id;
	n = serv->main_pipe.read(&serv->main_pipe, cev_queue, sizeof(cev_queue));

	if (n <= 0)
	{
		swWarn("[Master]main_pipe read fail. errno=%d", errno);
		return SW_ERR;
	}

	for (i = 0; i < n / sizeof(swEventClose); i++)
	{
		fd = cev_queue[i].fd;
		from_id = cev_queue[i].from_id;

		if (swConnection_close(serv, fd, &from_id) == 0)
		{
			if (serv->onMasterClose != NULL)
			{
				serv->onMasterClose(serv, fd, cev_queue[i].from_id);
			}
			if (serv->onClose == NULL || cev_queue[i].from_id == SW_CLOSE_NOTIFY)
			{
				continue;
			}
			else
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

static int swServer_onTimer(swReactor *reactor, swEvent *event)
{
	uint64_t exp;
	swServer *serv = reactor->ptr;
	swTimer *timer = &SwooleG.timer;

	if(serv->onTimer == NULL)
	{
		swWarn("swServer->onTimer is NULL");
		return SW_ERR;
	}
	if (read(SwooleG.timer.fd, &exp, sizeof(uint64_t)) < 0)
	{
		return SW_ERR;
	}
	return swTimer_select(timer, serv);
}

static void swServer_poll_onReactorTimeout(swReactor *reactor)
{
	swServer_poll_onReactorFinish(reactor);
}

static void swServer_master_onReactorTimeout(swReactor *reactor)
{
	swUpdateTime();
}

static void swServer_master_onReactorFinish(swReactor *reactor)
{
	swUpdateTime();
}

SWINLINE static void swUpdateTime(void)
{
	time_t now = time(NULL);
	if (now < 0)
	{
		swWarn("get time failed. Error: %s[%d]", strerror(errno), errno);
	}
	else
	{
		SwooleGS->now = now;
	}
}

#if SW_REACTOR_SCHEDULE == 3
SWINLINE static swServer_reactor_schedule(swServer *serv)
{
	//以第1个为基准进行排序，取出最小值
	int i, event_num = serv->reactor_threads[0].reactor.event_num;
	serv->reactor_next_i = 0;
	for (i = 1; i < serv->reactor_num; i++)
	{
		if (serv->reactor_threads[i].reactor.event_num < event_num)
		{
			serv->reactor_next_i = i;
			event_num = serv->reactor_threads[i].reactor.event_num;
		}
	}
}
#endif

static void swServer_poll_onReactorFinish(swReactor *reactor)
{
	swServer *serv = reactor->ptr;
	swCloseQueue *queue = &serv->reactor_threads[reactor->id].close_queue;
	//打开关闭队列
	if (queue->num > 0)
	{
		swServer_poll_close_queue(reactor, queue);
	}
}

static int swServer_master_onAccept(swReactor *reactor, swEvent *event)
{
	swServer *serv = reactor->ptr;
	swEvent connEv;
	struct sockaddr_in client_addr;
	uint32_t client_addrlen = sizeof(client_addr);
	int conn_fd, ret, c_pti, i;

	//SW_ACCEPT_AGAIN
	for (i = 0; i < SW_ACCEPT_MAX_COUNT; i++)
	{
		//accept得到连接套接字
#ifdef SW_USE_ACCEPT4
	    conn_fd = accept4(event->fd, (struct sockaddr *)&client_addr, &client_addrlen, SOCK_NONBLOCK);
#else
		conn_fd = accept(event->fd,  (struct sockaddr *)&client_addr, &client_addrlen);
#endif
		if (conn_fd < 0 )
		{
			switch(errno)
			{
			case EAGAIN:
				return SW_OK;
			case EINTR:
				continue;
			default:
				swWarn("accept fail. Error: %s[%d]", strerror(errno), errno);
				return SW_OK;
			}
		}
		swTrace("[Master]accept.event->fd=%d|event->from_id=%d|conn=%d", event->fd, event->from_id, conn_fd);
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

#ifdef TCP_KEEPIDLE
			setsockopt(conn_fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive , sizeof(keepalive));
			setsockopt(conn_fd, IPPROTO_TCP, TCP_KEEPIDLE, (void*)&keep_idle , sizeof(keep_idle));
			setsockopt(conn_fd, IPPROTO_TCP, TCP_KEEPINTVL, (void *)&keep_interval , sizeof(keep_interval));
			setsockopt(conn_fd, IPPROTO_TCP, TCP_KEEPCNT, (void *)&keep_count , sizeof(keep_count));
#endif
		}
#endif

#if SW_REACTOR_SCHEDULE == 1
		//轮询分配
		c_pti = (serv->reactor_round_i++) % serv->reactor_num;
#elif SW_REACTOR_SCHEDULE == 2
		//使用fd取模来散列
		c_pti = conn_fd % serv->reactor_num;
#else
		//平均调度法
		c_pti = serv->reactor_next_i;
		if ((serv->reactor_schedule_count++) % SW_SCHEDULE_INTERVAL == 0)
		{
			swServer_reactor_schedule(serv);
		}
#endif
		ret = serv->reactor_threads[c_pti].reactor.add(&(serv->reactor_threads[c_pti].reactor), conn_fd,
				SW_FD_TCP | SW_EVENT_READ);
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
#ifdef SW_ACCEPT_AGAIN
		continue;
#else
		break;
#endif
	}
	return SW_OK;
}

int swServer_addTimer(swServer *serv, int interval)
{
	if (interval < serv->timer_interval || serv->timer_interval == 0)
	{
		serv->timer_interval = interval;
	}
	int ret = swTimer_add(&SwooleG.timer, interval);
	if (SwooleG.timer.fd == 0)
	{
		swSignalSet(SIGALRM, swSignalHanlde, 1, 0);
		if(swTimer_start(&SwooleG.timer, serv->timer_interval) >= 0)
		{
			SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_TIMER, swServer_onTimer);
			SwooleG.main_reactor->add(SwooleG.main_reactor, SwooleG.timer.fd, SW_FD_TIMER);
		}
	}
	return ret;
}

/**
 * no use
 */
int swServer_reactor_add(swServer *serv, int fd, int sock_type)
{
	int poll_id = (serv->reactor_round_i++) % serv->reactor_num;
	swReactor *reactor = &(serv->reactor_threads[poll_id].reactor);
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
	swReactor *reactor = &(serv->reactor_threads[reacot_id].reactor);
	reactor->del(reactor, fd);
	return SW_OK;
}

static int swServer_check_callback(swServer *serv)
{
//	if (serv->onConnect == NULL)
//	{
//		swWarn("onConnect is null");
//		return SW_ERR;
//	}
//	if (serv->onClose == NULL)
//	{
//		swWarn("onClose is null");
//		return SW_ERR;
//	}
	if (serv->onReceive == NULL)
	{
		swWarn("onReceive is null");
		return SW_ERR;
	}
	//Timer
	if (SwooleG.timer.interval_ms > 0 && serv->onTimer == NULL)
	{
		swWarn("onTimer is null");
		return SW_ERR;
	}
	//AsyncTask
	if (serv->task_worker_num > 0)
	{
		if (serv->onTask == NULL)
		{
			swWarn("onTask is null");
			return SW_ERR;
		}
		if (serv->onFinish == NULL)
		{
			swWarn("onFinish is null");
			return SW_ERR;
		}
	}

	//check thread num
	if (serv->reactor_num > SW_CPU_NUM * SW_MAX_THREAD_NCPU)
	{
		serv->reactor_num = SW_CPU_NUM * SW_MAX_THREAD_NCPU;
	}
	if (serv->writer_num > SW_CPU_NUM * SW_MAX_THREAD_NCPU)
	{
		serv->writer_num = SW_CPU_NUM * SW_MAX_THREAD_NCPU;
	}
	if (serv->worker_num > SW_CPU_NUM * SW_MAX_WORKER_NCPU)
	{
		swWarn("serv->worker_num > %ld, Too many processes the system will be slow", SW_CPU_NUM * SW_MAX_WORKER_NCPU);
	}
	return SW_OK;
}

/**
 * base模式
 * 在worker进程中直接accept连接
 */
int swServer_start_base(swServer *serv)
{
	if (serv->onStart != NULL)
	{
		serv->onStart(serv);
	}
	return swServer_single_start(serv);
}

/**
 * proxy模式
 * 在单独的n个线程中接受维持TCP连接
 */
static int swServer_start_proxy(swServer *serv)
{
	int ret;
	swReactor *main_reactor = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swReactor));
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
	SwooleG.main_reactor = main_reactor;
	main_reactor->id = serv->reactor_num; //设为一个特别的ID
	main_reactor->ptr = serv;
	main_reactor->setHandle(main_reactor, SW_FD_LISTEN, swServer_master_onAccept);
	main_reactor->onFinish = swServer_master_onReactorFinish;
	main_reactor->onTimeout = swServer_master_onReactorTimeout;
	//no use
	//SW_START_SLEEP;
	if (serv->onStart != NULL)
	{
		serv->onStart(serv);
	}
	struct timeval tmo;
	tmo.tv_sec = SW_MAINREACTOR_TIMEO;
	tmo.tv_usec = 0;

	//先更新一次时间
	swUpdateTime();

	//心跳检测启动


	return main_reactor->wait(main_reactor, &tmo);
}

int swServer_start(swServer *serv)
{
	swFactory *factory = &serv->factory;
	int ret;

	ret = swServer_check_callback(serv);
	if (ret < 0)
	{
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

	//master pid
	SwooleGS->master_pid = getpid();

	//设置factory回调函数
	serv->factory.ptr = serv;
	serv->factory.onTask = serv->onReceive;
	if (serv->have_udp_sock == 1 && serv->factory_mode != SW_MODE_PROCESS)
	{
		serv->factory.onFinish = swServer_onFinish2;
	}
	else
	{
		serv->factory.onFinish = swServer_onFinish;
	}
	//for taskwait
	if (serv->task_worker_num > 0 && serv->worker_num > 0)
	{
		int i;
		SwooleG.task_result = sw_shm_calloc(serv->worker_num, sizeof(swEventData));
		SwooleG.task_notify = sw_calloc(serv->worker_num, sizeof(swPipe));
		for(i =0; i< serv->worker_num; i++)
		{
			if(swPipeNotify_auto(&SwooleG.task_notify[i], 1, 0))
			{
				return SW_ERR;
			}
		}
	}
	//factory start
	if (factory->start(factory) < 0)
	{
		return SW_ERR;
	}
	//Signal Init
	swSignalInit();
	//标识为主进程
	SwooleG.process_type = SW_PROCESS_MASTER;

	//启动心跳检测
	if(serv->heartbeat_check_interval >= 1 && serv->heartbeat_check_interval <= serv->heartbeat_idle_time)
	{
		swTrace("hb timer start, time: %d live time:%d", serv->heartbeat_check_interval, serv->heartbeat_idle_time);
		swServer_heartbeat_start(serv);
	}

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
	if (SwooleG.heartbeat_pidt)
	{
		pthread_cancel(SwooleG.heartbeat_pidt);
	}
	swServer_free(serv);
	return SW_OK;
}

/**
 * 关闭连接
 */
int swServer_close(swServer *serv, swEvent *event)
{
	swEventClose cev;
	if (event->from_id > serv->reactor_num)
	{
		swWarn("Error: From_id > serv->reactor_num.from_id=%d", event->from_id);
		return SW_ERR;
	}
	cev.fd = event->fd;
	cev.from_id = event->from_id;
	if( serv->main_pipe.write(&(serv->main_pipe), &cev, sizeof(cev)) < 0)
	{
		swWarn("write to main_pipe failed. Error: %s[%d]", strerror(errno), errno);
		return SW_ERR;
	}
	return SW_OK;
}

void swoole_init(void)
{
	extern FILE *swoole_log_fn;
	if (SwooleG.running == 0)
	{
		bzero(&SwooleG, sizeof(SwooleG));
		bzero(sw_error, SW_ERROR_MSG_SIZE);

		//初始化全局变量
		SwooleG.running = 1;
		sw_errno = 0;

		//将日志设置为标准输出
		swoole_log_fn = stdout;
		//初始化全局内存
		SwooleG.memory_pool = swMemoryGlobal_create(SW_GLOBAL_MEMORY_PAGESIZE, 1);
		if(SwooleG.memory_pool == NULL)
		{
			swError("[Master] Fatal Error: create global memory fail. Error: %s[%d]", strerror(errno), errno);
		}
		SwooleGS = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swServerGS));
		if(SwooleGS == NULL)
		{
			swError("[Master] Fatal Error: alloc memory for SwooleGS fail. Error: %s[%d]", strerror(errno), errno);
		}
	}
}

void swoole_clean(void)
{
	//释放全局内存
	if(SwooleG.memory_pool != NULL)
	{
		SwooleG.memory_pool->destroy(SwooleG.memory_pool);
		SwooleG.memory_pool = NULL;
		if(SwooleG.timer.fd > 0)
		{
			swTimer_free(&SwooleG.timer);
		}
		bzero(&SwooleG, sizeof(SwooleG));
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
	serv->reactor_num = SW_THREAD_NUM;
	serv->dispatch_mode = SW_DISPATCH_FDMOD;
	serv->ringbuffer_size = SW_QUEUE_SIZE;

	serv->timeout_sec = SW_REACTOR_TIMEO_SEC;
	serv->timeout_usec = SW_REACTOR_TIMEO_USEC; //300ms;

	serv->writer_num = SW_CPU_NUM;
	serv->worker_num = SW_CPU_NUM;
	serv->max_conn = SW_MAX_FDS;
	serv->max_request = SW_MAX_REQUEST;
	serv->max_trunk_num = SW_MAX_TRUNK_NUM;

	serv->udp_sock_buffer_size = SW_UNSOCK_BUFSIZE;

	//tcp keepalive
	serv->tcp_keepcount = SW_TCP_KEEPCOUNT;
	serv->tcp_keepinterval = SW_TCP_KEEPINTERVAL;
	serv->tcp_keepidle = SW_TCP_KEEPIDLE;

	char eof[] = SW_DATA_EOF;
	serv->data_eof_len = sizeof(SW_DATA_EOF) - 1;
	memcpy(serv->data_eof, eof, serv->data_eof_len);
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
	connection->connect_time = SwooleGS->now;
	connection->last_time = SwooleGS->now;
	connection->tag = 1; //使此连接激活,必须在最后，保证线程安全

	return SW_OK;
}

static int swServer_create_base(swServer *serv)
{
	serv->reactor_num = 1;
	serv->reactor_threads = sw_calloc(1, sizeof(swThreadPoll));
	if (serv->reactor_threads == NULL)
	{
		swError("calloc[reactor_threads] fail.alloc_size=%d", (int )(serv->reactor_num * sizeof(swThreadPoll)));
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
	return SW_OK;
}

static int swServer_create_proxy(swServer *serv)
{
	int ret = 0;
	SW_START_SLEEP;
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
	serv->reactor_threads = SwooleG.memory_pool->alloc(SwooleG.memory_pool, (serv->reactor_num * sizeof(swThreadPoll)));
	if (serv->reactor_threads == NULL)
	{
		swError("calloc[reactor_threads] fail.alloc_size=%d", (int )(serv->reactor_num * sizeof(swThreadPoll)));
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
	SwooleG.running = 0;
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

	//master pipe
	if (serv->task_worker_num > 0)
	{
		swProcessPool_shutdown(&SwooleG.task_workers);
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
		param = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swThreadParam));
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
	swThreadPoll *reactor_threads;
	pthread_t pidt;

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

		for (i = 0; i < serv->reactor_num; i++)
		{
			reactor_threads = &(serv->reactor_threads[i]);
			param = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swThreadParam));
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
			reactor_threads->ptid = pidt;
		}
	}


	if(SwooleG.timer.fd > 0)
	{
		main_reactor_ptr->add(main_reactor_ptr, SwooleG.timer.fd, SW_FD_TIMER);
	}
	main_reactor_ptr->setHandle(main_reactor_ptr, (SW_FD_USER+2), swServer_master_onClose);
	main_reactor_ptr->add(main_reactor_ptr, serv->main_pipe.getFd(&serv->main_pipe, 0), (SW_FD_USER+2));
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
	int ret;

	//UDP
	if (resp->info.from_id >= serv->reactor_num)
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

	swEventData buf;
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);

	//使用pti保存fd
	int sock = param->pti;

	//阻塞读取UDP
	swSetBlock(sock);

	bzero(&buf.info, sizeof(buf.info));
	buf.info.from_fd = sock;

	while (SwooleG.running == 1)
	{
		ret = recvfrom(sock, buf.data, SW_BUFFER_SIZE, 0, (struct sockaddr *)&addr, &addrlen);
		if (ret > 0)
		{
			buf.info.len = ret;
			buf.info.type = SW_EVENT_UDP;
			//UDP的from_id是PORT，FD是IP
			buf.info.from_id = ntohs(addr.sin_port); //转换字节序
			buf.info.fd = addr.sin_addr.s_addr;

			swTrace("recvfrom udp socket.fd=%d|data=%s", sock, buf.data);
			ret = serv->factory.dispatch(&serv->factory, &buf);
			if (ret < 0)
			{
				swWarn("factory->dispatch[udp packet] fail\n");
			}
		}
	}
	pthread_exit(0);
}

int swTaskWorker_onTask(swProcessPool *pool, swEventData *task)
{
	swServer *serv = pool->ptr;
	return serv->onTask(serv, task);
}

int swTaskWorker_onFinish(swReactor *reactor, swEvent *event)
{
	swServer *serv = reactor->ptr;
	swEventData task;
	int n;
	do
	{
		n = read(event->fd, &task, sizeof(task));
	}
	while(n < 0 && errno == EINTR);
	return serv->onFinish(serv, &task);
}

static int swServer_single_start(swServer *serv)
{
	int ret, i;

	swProcessPool pool;
	swProcessPool_create(&pool, serv->worker_num, serv->max_request);
	pool.onStart = swServer_single_loop;
	pool.ptr = serv;

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
	SwooleG.event_workers = &pool;
	//task workers
	if (serv->task_worker_num > 0)
	{
		pthread_t ptid;
		if (swProcessPool_create(&SwooleG.task_workers, serv->task_worker_num, serv->max_request)< 0)
		{
			swWarn("[Master] create task_workers fail");
			return SW_ERR;
		}
		//设置指针和回调函数
		SwooleG.task_workers.ptr = serv;
		SwooleG.task_workers.onTask = swTaskWorker_onTask;
		swProcessPool_start(&SwooleG.task_workers);

		//将taskworker也加入到wait中来
		for (i = 0; i < SwooleG.task_workers.worker_num; i++)
		{
			swProcessPool_add_worker(&pool, &SwooleG.task_workers.workers[i]);
		}
	}
	swProcessPool_start(&pool);
	return swProcessPool_wait(&pool);
}

static int swServer_single_loop(swProcessPool *pool, swWorker *worker)
{
	swServer *serv = pool->ptr;
	swReactor *reactor = &(serv->reactor_threads[0].reactor);
	if (swReactor_auto(reactor, serv->max_conn) < 0)
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
	SwooleG.main_reactor = reactor;

	reactor->id = 0;
	reactor->ptr = serv;
	//connect
	reactor->setHandle(reactor, SW_FD_LISTEN, swServer_master_onAccept);
	//close
	reactor->setHandle(reactor, SW_FD_CLOSE, swServer_single_onClose);
	//task finish
	reactor->setHandle(reactor, SW_FD_PIPE, swTaskWorker_onFinish);
	//udp receive
	reactor->setHandle(reactor, SW_FD_UDP, swServer_poll_onPackage);
	//tcp receive
	reactor->setHandle(reactor, SW_FD_TCP, (serv->open_eof_check == 0)?swServer_poll_onReceive_no_buffer:swServer_poll_onReceive_conn_buffer);

	reactor->add(reactor, worker->pipe_master, SW_FD_PIPE);

	reactor->onFinish = swServer_master_onReactorFinish;
	reactor->onTimeout = swServer_master_onReactorTimeout;

	//更新系统时间
	swUpdateTime();

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

	if(swConnection_close(serv, event->fd, &(event->from_id)) == 0)
	{
		if(serv->onClose != NULL)
		{
			serv->onClose(serv, event->fd, event->from_id);
		}
		serv->connect_count--;
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
	swReactor *reactor = &(serv->reactor_threads[pti].reactor);
	swThreadPoll *this = &(serv->reactor_threads[pti]);
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

	ret = swReactor_auto(reactor, (serv->max_conn / serv->reactor_num) + 1);
	if (ret < 0)
	{
		return SW_ERR;
	}

	swSingalNone();

	timeo.tv_sec = serv->timeout_sec;
	timeo.tv_usec = serv->timeout_usec; //300ms
	reactor->ptr = serv;
	reactor->id = pti;

	reactor->onFinish = swServer_poll_onReactorFinish;
	reactor->onTimeout = swServer_poll_onReactorTimeout;
	reactor->setHandle(reactor, SW_FD_CLOSE, swServer_poll_onClose);
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
	int ret, n, recv_again = SW_FALSE;
	int isEOF = -1;

	swServer *serv = reactor->ptr;
	swFactory *factory = &(serv->factory);
	swEvent closeEv;
	//swDispatchData send_data;
	swEventData send_data;
	swDataBuffer_item *buffer_item = NULL;
	swDataBuffer *data_buffer = &serv->reactor_threads[event->from_id].data_buffer;
	swDataBuffer_trunk *trunk;

	buffer_item = swDataBuffer_getItem(data_buffer, event->fd);

	//获取失败使用no_buffer处理
	if (buffer_item == NULL)
	{
		return swServer_poll_onReceive_no_buffer(reactor, event);
	}

	recv_data:
	//trunk
	trunk = swDataBuffer_getTrunk(data_buffer, buffer_item);
	int buf_size =  data_buffer->trunk_size - trunk->len;

#ifdef SW_USE_EPOLLET
	n = swRead(event->fd,  trunk->data, SW_BUFFER_SIZE);
#else
	//非ET模式会持续通知
	n = recv(event->fd,  trunk->data + trunk->len, buf_size, 0);
#endif

	if (n < 0)
	{
		if(errno == ECONNRESET)
		{
			goto close_fd;
		}
		swWarn("read from connection failed. Error: %s[%d]", strerror(errno), errno);
		return SW_ERR;
	}
	else if (n == 0)
	{
		close_fd:
		swTrace("Close Event.FD=%d|From=%d", event->fd, event->from_id);
		memcpy(&closeEv, event, sizeof(swEvent));
		closeEv.type = SW_EVENT_CLOSE;
		return swServer_poll_onClose(reactor, event);
	}
	else
	{
		//更新时间
		swConnection *connection = swServer_get_connection(serv, event->fd);
		connection->last_time =  SwooleGS->now;

		//读满buffer了,可能还有数据
		if((data_buffer->trunk_size - trunk->len) == n)
		{
			recv_again = SW_TRUE;
		}
		trunk->len += n;

		//trunk->data[trunk->len] = 0; //这里是为了printf
		//printf("buffer------------: %s|fd=%d|len=%d\n", trunk->data, event->fd, trunk->len);

		if (serv->open_eof_check == 1)
		{
			isEOF = memcmp(trunk->data + trunk->len - serv->data_eof_len, serv->data_eof, serv->data_eof_len);
		}
		//printf("buffer ok. EOF=%s|Len=%d|RecvEOF=%s|isEOF=%d\n", serv->data_eof, serv->data_eof_len, trunk->data + trunk->len - serv->data_eof_len, isEOF);

		//超过buffer_size或者收到EOF
		//发送数据到worker进程
		if (buffer_item->trunk_num >= data_buffer->max_trunk || isEOF == 0)
		{
			send_data.info.fd = event->fd;
			send_data.info.type = SW_EVENT_TCP;
			send_data.info.from_id = event->from_id;
			swDataBuffer_trunk *send_trunk = buffer_item->head;

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
		else if(recv_again)
		{
			swDataBuffer_newTrunk(data_buffer, buffer_item);
			goto recv_data;
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
		ret = recvfrom(event->fd, buf.data, SW_BUFFER_SIZE, 0, (struct sockaddr *)&addr, &addrlen);
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
	buf.info.type = SW_EVENT_UDP;
	buf.info.from_fd = event->fd; //from fd
	buf.info.from_id = ntohs(addr.sin_port); //转换字节序
	buf.info.fd = addr.sin_addr.s_addr;
	swTrace("recvfrom udp socket.fd=%d|data=%s", event->fd, buf.data);
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

	//更新时间
	connection->last_time =  SwooleGS->now;

	if(buffer==NULL)
	{
		return SW_ERR;
	}

#ifdef SW_USE_EPOLLET
	n = swRead(event->fd,  buffer->data.data + buffer->data.info.len, SW_BUFFER_SIZE - buffer->data.info.len);
#else
	//非ET模式会持续通知
	n = recv(event->fd,  buffer->data.data + buffer->data.info.len, SW_BUFFER_SIZE - buffer->data.info.len, 0);
#endif

	if (n < 0)
	{
		swWarn("swRead error: %d\n", errno);
		return SW_ERR;
	}
	else if (n == 0)
	{
		close_fd:
		swTrace("Close Event.FD=%d|From=%d\n", event->fd, event->from_id);
		memcpy(&closeEv, event, sizeof(swEvent));
		closeEv.type = SW_EVENT_CLOSE;
		return swServer_poll_onClose(reactor, event);
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
			buffer->data.info.type = SW_EVENT_TCP;
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

#ifdef SW_USE_EPOLLET
	n = swRead(event->fd, rdata.buf.data, SW_BUFFER_SIZE);
#else
	//非ET模式会持续通知
	n = recv(event->fd, rdata.buf.data, SW_BUFFER_SIZE, 0);
#endif
	if (n < 0)
	{
		if (errno == EAGAIN)
		{
			return SW_OK;
		}
		else if(errno == ECONNRESET)
		{
			goto close_fd;
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
		close_fd:
		swTrace("Close Event.FD=%d|From=%d|errno=%d", event->fd, event->from_id, errno);
		return swServer_poll_onClose(reactor, event);
	}
	else
	{
		swTrace("recv: %s|fd=%d|len=%d\n", rdata.buf.data, event->fd, n);
		rdata.buf.info.fd = event->fd;
		rdata.buf.info.len = n;
		rdata.buf.info.type = SW_EVENT_TCP;
		rdata.buf.info.from_id = event->from_id;

		//更新最近收包时间
		swConnection *connection = swServer_get_connection(serv, event->fd);
		connection->last_time =  SwooleGS->now;

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
//		else if (sw_errno == EAGAIN)
//		{
//			swWarn("sw_errno == EAGAIN");
//			ret = swServer_poll_onReceive_no_buffer(reactor, event);
//		}
		return ret;
	}
	return SW_OK;
}

static int swServer_poll_onClose(swReactor *reactor, swEvent *event)
{
	int ret = 0;
	swServer *serv = reactor->ptr;
	swCloseQueue *queue = &serv->reactor_threads[reactor->id].close_queue;

	//关闭连接
	reactor->del(reactor, event->fd);
	event->from_id = -1;

	queue->events[queue->num].fd = event->fd;
	//-1表示直接在reactor内关闭
	queue->events[queue->num].from_id = -1;
	//增加计数
	queue->num ++;
	//close队列已满
	if (queue->num == SW_CLOSE_QLEN)
	{
		return swServer_poll_close_queue(reactor, queue);
	}
	return SW_OK;
}

static int swServer_poll_close_queue(swReactor *reactor, swCloseQueue *close_queue)
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
		swWarn("write to main_pipe failed. Error: %s[%d]", strerror(errno), errno);
		return SW_ERR;
	}
	bzero(close_queue, sizeof(swCloseQueue));
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
}

int swServer_addListen(swServer *serv, int type, char *host, int port)
{
	swListenList_node *listen_host = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swListenList_node));
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
	int sock=-1;

	swListenList_node *listen_host;

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
	if (sock>=0)
	{
		swServer_set_minfd(serv, sock);
		swServer_set_maxfd(serv, sock);
	}
	return SW_OK;
}

int swServer_get_manager_pid(swServer *serv)
{
	if (SW_MODE_PROCESS != serv->factory_mode)
	{
		return SW_ERR;
	}
	return SwooleGS->manager_pid;
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
		SwooleG.running = 0;
		break;
	case SIGALRM:
		if (SwooleG.timer.use_pipe == 1)
		{
			SwooleG.timer.pipe.write(&SwooleG.timer.pipe, &flag, sizeof(flag));
		}
		break;
	default:
		break;
	}
	//swSignalInit();
}

static void swServer_heartbeat_start(swServer *serv)
{
	swThreadParam *heartbeat_param;
	pthread_t heartbeat_pidt;
	heartbeat_param = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swThreadParam));
	if (heartbeat_param == NULL)
	{
		swError("heartbeat_param malloc fail\n");
		return;
	}
	heartbeat_param->object = serv;
	heartbeat_param->pti = 0;
	if(pthread_create(&heartbeat_pidt, NULL, (void * (*)(void *)) swServer_heartbeat_check, (void *) heartbeat_param) < 0)
	{
		swWarn("pthread_create[hbcheck] fail");
	}
	SwooleG.heartbeat_pidt = heartbeat_pidt;
	pthread_detach(SwooleG.heartbeat_pidt);
}

static void swServer_heartbeat_check(swThreadParam *heartbeat_param)
{
	while(SwooleG.running)
	{
		swServer *serv = heartbeat_param->object;
		swFactory *factory = &serv->factory;

		int serv_max_fd = swServer_get_maxfd(serv);
		int serv_min_fd = swServer_get_minfd(serv);
		int16_t from_id;
		swEvent notify_ev;

		int fd;

		int checktime = (int) time(NULL) - serv->heartbeat_idle_time;

		//遍历到最大fd
		for(fd = serv_min_fd; fd<= serv_max_fd; fd++)
		{
			 swTrace("check fd=%d", fd);
			 if(1 == serv->connection_list[fd].tag && (serv->connection_list[fd].last_time  < checktime))
			 {

			 	if (swConnection_close(serv, fd, &from_id) == 0)
				{
					if (serv->onMasterClose != NULL)
					{
						serv->onMasterClose(serv, fd, from_id);
					}
					if (serv->onClose == NULL)
					{
						continue;
					}
					else
					{
						notify_ev.from_id = from_id;
						notify_ev.fd = fd;
						notify_ev.type = SW_EVENT_CLOSE;
						factory->notify(factory, &notify_ev);
					}
				}
			 }
		}
		sleep(serv->heartbeat_check_interval);
	}
	pthread_exit(0);
}
