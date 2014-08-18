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
#include "Connection.h"
#include "memory.h"

#include <netinet/tcp.h>

static void swServer_signal_init(void);

#if SW_REACTOR_SCHEDULE == 3
static sw_inline void swServer_reactor_schedule(swServer *serv)
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

static int swServer_start_check(swServer *serv);

static void swServer_signal_hanlder(int sig);
static int swServer_master_onClose(swReactor *reactor, swDataHead *event);

static int swServer_start_proxy(swServer *serv);

static void swServer_heartbeat_start(swServer *serv);
static void swServer_heartbeat_check(swThreadParam *heartbeat_param);

swServerG SwooleG;
swServerGS *SwooleGS;
swWorkerG SwooleWG;
swServerStats *SwooleStats;
__thread swThreadG SwooleTG;

int16_t sw_errno;
char sw_error[SW_ERROR_MSG_SIZE];

void swServer_worker_onStart(swServer *serv)
{
	/**
	 * Release other worker process
	 */
	int i;
	swWorker *worker;
	for (i = 0; i < serv->worker_num + SwooleG.task_worker_num; i++)
	{
		worker = swServer_get_worker(serv, i);
		if (SwooleWG.id == i)
		{
			continue;
		}
		else
		{
			swWorker_free(worker);
		}
		if (SwooleWG.id < serv->worker_num && i < serv->worker_num)
		{
			close(worker->pipe_master);
		}
	}

	SwooleG.process_type = SW_PROCESS_WORKER;

	if (serv->onWorkerStart)
	{
		serv->onWorkerStart(serv, SwooleWG.id);
	}
}

void swServer_worker_onStop(swServer *serv)
{
	if (serv->onWorkerStop)
	{
		serv->onWorkerStop(serv, SwooleWG.id);
	}
	swWorker_free(swServer_get_worker(serv, SwooleWG.id));
}

static int swServer_master_onClose(swReactor *reactor, swEvent *event)
{
	swServer *serv = reactor->ptr;
	int queue[SW_CLOSE_QLEN];

	int i, n, fd;
	n = serv->main_pipe.read(&serv->main_pipe, queue, sizeof(queue));

	if (n <= 0)
	{
		swWarn("[Master]main_pipe read failed. Error: %s[%d]", strerror(errno), errno);
		return SW_ERR;
	}

	for (i = 0; i < n / sizeof(int); i++)
	{
		fd = queue[i];
		/**
		 * Reset maxfd, use for connection_list
		 */
		if (fd == swServer_get_maxfd(serv))
		{
			int find_max_fd = fd - 1;

			/**
			 * Find the new max_fd
			 */
			for (; serv->connection_list[find_max_fd].active == 0 && find_max_fd > swServer_get_minfd(serv); find_max_fd--);
			swServer_set_maxfd(serv, find_max_fd);

			swTrace("set_maxfd=%d|close_fd=%d", find_max_fd, fd);
		}
	}
	return SW_OK;
}

void swServer_master_onReactorTimeout(swReactor *reactor)
{
	swServer_update_time();
}

void swServer_master_onReactorFinish(swReactor *reactor)
{
	swServer_update_time();
}

void swServer_update_time(void)
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

int swServer_master_onAccept(swReactor *reactor, swEvent *event)
{
	swServer *serv = reactor->ptr;
	swEvent connEv;
	struct sockaddr_in client_addr;
	uint32_t client_addrlen = sizeof(client_addr);
	int new_fd, ret, reactor_id = 0, i, sockopt;

	//SW_ACCEPT_AGAIN
	for (i = 0; i < SW_ACCEPT_MAX_COUNT; i++)
	{
		//accept得到连接套接字
#ifdef SW_USE_ACCEPT4
	    new_fd = accept4(event->fd, (struct sockaddr *)&client_addr, &client_addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
		new_fd = accept(event->fd,  (struct sockaddr *)&client_addr, &client_addrlen);
#endif
		if (new_fd < 0 )
		{
			switch(errno)
			{
			case EAGAIN:
				return SW_OK;
			case EINTR:
				continue;
			default:
				swWarn("accept() failed. Error: %s[%d]", strerror(errno), errno);
				return SW_OK;
			}
		}

		swTrace("[Master] Accept new connection. maxfd=%d|reactor_id=%d|conn=%d", swServer_get_maxfd(serv), reactor->id, new_fd);

		//too many connection
		if (new_fd >= serv->max_conn)
		{
			swWarn("Too many connections [now: %d].", swServer_get_maxfd(serv));
			close(new_fd);
			return SW_OK;
		}

		//TCP Nodelay
		if (serv->open_tcp_nodelay == 1)
		{
			sockopt = 1;
			setsockopt(new_fd, IPPROTO_TCP, TCP_NODELAY, &sockopt, sizeof(sockopt));
		}

#ifdef SO_KEEPALIVE
		//TCP keepalive
		if (serv->open_tcp_keepalive == 1)
		{
			int keepalive = 1;
			int keep_idle = serv->tcp_keepidle;
			int keep_interval = serv->tcp_keepinterval;
			int keep_count = serv->tcp_keepcount;

#ifdef TCP_KEEPIDLE
			setsockopt(new_fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive , sizeof(keepalive));
			setsockopt(new_fd, IPPROTO_TCP, TCP_KEEPIDLE, (void*)&keep_idle , sizeof(keep_idle));
			setsockopt(new_fd, IPPROTO_TCP, TCP_KEEPINTVL, (void *)&keep_interval , sizeof(keep_interval));
			setsockopt(new_fd, IPPROTO_TCP, TCP_KEEPCNT, (void *)&keep_count , sizeof(keep_count));
#endif
		}
#endif

#if SW_REACTOR_SCHEDULE == 1
		//轮询分配
		reactor_id = (serv->reactor_round_i++) % serv->reactor_num;
#elif SW_REACTOR_SCHEDULE == 2
		//使用fd取模来散列
		reactor_id = new_fd % serv->reactor_num;
#else
		//平均调度法
		reactor_id = serv->reactor_next_i;
		if (serv->reactor_num > 1 && (serv->reactor_schedule_count++) % SW_SCHEDULE_INTERVAL == 0)
		{
			swServer_reactor_schedule(serv);
		}
#endif

		connEv.type = SW_EVENT_CONNECT;
		connEv.from_id = reactor_id;
		connEv.fd = new_fd;
		connEv.from_fd = event->fd;

		//add to connection_list
		swConnection *conn = swServer_connection_new(serv, &connEv);

#ifdef SW_USE_OPENSSL
		if (serv->open_ssl)
		{
			swListenList_node *listen_host = serv->connection_list[event->fd].object;
			if (listen_host->ssl)
			{
				if (swSSL_create(conn, 0) < 0)
				{
					conn->active = 0;
					close(new_fd);
				}
			}
			else
			{
				conn->ssl = NULL;
			}
		}
#endif
		memcpy(&conn->addr, &client_addr, sizeof(client_addr));
		/*
		 * [!!!] new_connection function must before reactor->add
		 */
		ret = serv->reactor_threads[reactor_id].reactor.add(&(serv->reactor_threads[reactor_id].reactor), new_fd,
				SW_FD_TCP | SW_EVENT_READ);
		if (ret < 0)
		{
			close(new_fd);
			return SW_OK;
		}
		else
		{
			if (serv->onConnect != NULL)
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

static void swServer_onTimer(swTimer *timer, int interval)
{
	swServer *serv = SwooleG.serv;
	serv->onTimer(serv, interval);
}

int swServer_addTimer(swServer *serv, int interval)
{
	if (serv->onTimer == NULL)
	{
		swWarn("onTimer is null. Can not use timer.");
		return SW_ERR;
	}

	//timer no init
	if (SwooleG.timer.fd == 0)
	{
		if (swTimer_create(&SwooleG.timer, interval, SwooleG.use_timer_pipe) < 0)
		{
			return SW_ERR;
		}

		if (swIsMaster())
		{
			serv->connection_list[SW_SERVER_TIMER_FD_INDEX].fd = SwooleG.timer.fd;
		}

		if (SwooleG.use_timer_pipe)
		{
			SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_TIMER, swTimer_event_handler);
			SwooleG.main_reactor->add(SwooleG.main_reactor, SwooleG.timer.fd, SW_FD_TIMER);
		}

		SwooleG.timer.onTimer = swServer_onTimer;
	}
	return swTimer_add(&SwooleG.timer, interval);
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

static int swServer_start_check(swServer *serv)
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
	if (SwooleG.timer.interval > 0 && serv->onTimer == NULL)
	{
		swWarn("onTimer is null");
		return SW_ERR;
	}
	//AsyncTask
	if (SwooleG.task_worker_num > 0)
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
		swWarn("serv->worker_num > %d, Too many processes, the system will be slow", SW_CPU_NUM * SW_MAX_WORKER_NCPU);
		serv->worker_num = SW_CPU_NUM * SW_MAX_WORKER_NCPU;
	}
	if (serv->worker_num < serv->reactor_num)
	{
		serv->reactor_num = serv->worker_num;
	}
	if (serv->worker_num < serv->writer_num)
	{
		serv->writer_num = serv->worker_num;
	}
	if (SwooleG.max_sockets > 0 && serv->max_conn > SwooleG.max_sockets)
	{
	    swWarn("serv->max_conn is exceed the maximum value[%d].", SwooleG.max_sockets);
	    serv->max_conn = SwooleG.max_sockets;
	}
#ifdef SW_USE_OPENSSL
	if (serv->open_ssl)
	{
		if (serv->ssl_cert_file == NULL || serv->ssl_key_file == NULL)
		{
			swWarn("SSL error, require ssl_cert_file and ssl_key_file.");
			return SW_ERR;
		}
	}
#endif
	return SW_OK;
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
		swWarn("Reactor create failed");
		return SW_ERR;
	}
	ret = swReactorThread_start(serv, main_reactor);
	if (ret < 0)
	{
		swWarn("ReactorThread start failed");
		return SW_ERR;
	}
	SwooleG.main_reactor = main_reactor;
	main_reactor->id = serv->reactor_num; //设为一个特别的ID
	main_reactor->ptr = serv;
	main_reactor->setHandle(main_reactor, SW_FD_LISTEN, swServer_master_onAccept);
	main_reactor->setHandle(main_reactor, (SW_FD_USER+2), swServer_master_onClose);

	main_reactor->onFinish = swServer_master_onReactorFinish;
	main_reactor->onTimeout = swServer_master_onReactorTimeout;

#ifdef HAVE_SIGNALFD
	if (SwooleG.use_signalfd)
	{
		swSignalfd_setup(main_reactor);
	}
#endif

	main_reactor->add(main_reactor, serv->main_pipe.getFd(&serv->main_pipe, 0), (SW_FD_USER+2));
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
	swServer_update_time();

	return main_reactor->wait(main_reactor, &tmo);
}

int swServer_start(swServer *serv)
{
	swFactory *factory = &serv->factory;
	int ret;

	ret = swServer_start_check(serv);
	if (ret < 0)
	{
		return SW_ERR;
	}

#if SW_WORKER_IPC_MODE == 2
	serv->ipc_mode = SW_IPC_MSGQUEUE;
#endif

	if (serv->message_queue_key == 0)
	{
		char path_buf[128];
		char *path_ptr = getcwd(path_buf, 128);
		serv->message_queue_key = ftok(path_ptr, 1);
	}

    if (serv->ipc_mode == SW_IPC_MSGQUEUE)
    {
        SwooleG.use_timerfd = 0;
        SwooleG.use_signalfd = 0;
        SwooleG.use_timer_pipe = 0;
    }

#ifdef SW_USE_OPENSSL
    if (serv->open_ssl)
    {
        if (swSSL_init(serv->ssl_cert_file, serv->ssl_key_file) < 0)
        {
            return SW_ERR;
        }
    }
#endif

	//run as daemon
	if (serv->daemonize > 0)
	{
		/**
		 * redirect STDOUT to log file
		 */
		if (SwooleG.log_fd > STDOUT_FILENO)
		{
			if (dup2(SwooleG.log_fd, STDOUT_FILENO) < 0)
			{
				swWarn("dup2() failed. Error: %s[%d]", strerror(errno), errno);
			}
		}
		/**
		 * redirect STDOUT_FILENO/STDERR_FILENO to /dev/null
		 */
		else
		{
			int null_fd = open("/dev/null", O_WRONLY);
			if (null_fd > 0)
			{
				if (dup2(null_fd, STDOUT_FILENO) < 0)
				{
					swWarn("dup2(STDOUT_FILENO) failed. Error: %s[%d]", strerror(errno), errno);
				}
				if (dup2(null_fd, STDERR_FILENO) < 0)
				{
					swWarn("dup2(STDERR_FILENO) failed. Error: %s[%d]", strerror(errno), errno);
				}
			}
			else
			{
				swWarn("open(/dev/null) failed. Error: %s[%d]", strerror(errno), errno);
			}
		}

		if (daemon(0, 1) < 0)
		{
			return SW_ERR;
		}
	}

	//master pid
	SwooleGS->master_pid = getpid();
	SwooleGS->start = 1;
	SwooleGS->now = SwooleStats->start_time = time(NULL);

	serv->reactor_pipe_num = serv->worker_num / serv->reactor_num;

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

	serv->workers = SwooleG.memory_pool->alloc(SwooleG.memory_pool, serv->worker_num * sizeof(swWorker));
	if (serv->workers == NULL)
	{
		swWarn("[Master] malloc[object->workers] failed");
		return SW_ERR;
	}

	/*
	 * For swoole_server->taskwait, create notify pipe and result shared memory.
	 */
	if (SwooleG.task_worker_num > 0 && serv->worker_num > 0)
	{
		int i;
		SwooleG.task_result = sw_shm_calloc(serv->worker_num, sizeof(swEventData));
		SwooleG.task_notify = sw_calloc(serv->worker_num, sizeof(swPipe));
		for(i =0; i< serv->worker_num; i++)
		{
			if (swPipeNotify_auto(&SwooleG.task_notify[i], 1, 0))
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
	swServer_signal_init();

	//标识为主进程
	SwooleG.process_type = SW_PROCESS_MASTER;

	//启动心跳检测
	if (serv->heartbeat_check_interval >= 1 && serv->heartbeat_check_interval <= serv->heartbeat_idle_time)
	{
		swTrace("hb timer start, time: %d live time:%d", serv->heartbeat_check_interval, serv->heartbeat_idle_time);
		swServer_heartbeat_start(serv);
	}

	if (serv->factory_mode == SW_MODE_SINGLE)
	{
		ret = swReactorProcess_start(serv);
	}
	else
	{
		ret = swServer_start_proxy(serv);
	}

	if (ret < 0)
	{
		SwooleGS->start = 0;
	}

	//server stop
	if (serv->onShutdown != NULL)
	{
		serv->onShutdown(serv);
	}
	swServer_free(serv);
	return SW_OK;
}

/**
 * 关闭连接
 */
int swServer_close(swServer *serv, swEvent *event)
{
	if (event->from_id > serv->reactor_num)
	{
		swWarn("Error: From_id > serv->reactor_num.from_id=%d", event->from_id);
		return SW_ERR;
	}
	if( serv->main_pipe.write(&(serv->main_pipe), &(event->fd), sizeof(event->fd)) < 0)
	{
		swWarn("write to main_pipe failed. Error: %s[%d]", strerror(errno), errno);
		return SW_ERR;
	}
	return SW_OK;
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
	serv->reactor_num = SW_REACTOR_NUM;
	serv->reactor_ringbuffer_size = SW_REACTOR_RINGBUFFER_SIZE;

	serv->ipc_mode = SW_IPC_UNSOCK;
	serv->dispatch_mode = SW_DISPATCH_FDMOD;
	serv->ringbuffer_size = SW_QUEUE_SIZE;

	serv->timeout_sec = SW_REACTOR_TIMEO_SEC;
	serv->timeout_usec = SW_REACTOR_TIMEO_USEC; //300ms;

	serv->writer_num = SW_CPU_NUM;
	serv->worker_num = SW_CPU_NUM;
	serv->max_conn = SwooleG.max_sockets;

	serv->max_request = 0;
	serv->task_max_request = SW_MAX_REQUEST;

	serv->udp_sock_buffer_size = SW_UNSOCK_BUFSIZE;

	//tcp keepalive
	serv->tcp_keepcount = SW_TCP_KEEPCOUNT;
	serv->tcp_keepinterval = SW_TCP_KEEPINTERVAL;
	serv->tcp_keepidle = SW_TCP_KEEPIDLE;

	//heartbeat check
	serv->heartbeat_idle_time = SW_HEARTBEAT_IDLE;
	serv->heartbeat_check_interval = SW_HEARTBEAT_CHECK;

	char eof[] = SW_DATA_EOF;
	serv->package_eof_len = sizeof(SW_DATA_EOF) - 1;
	serv->package_length_type = 'N';
	serv->package_length_size = 4;

	serv->buffer_input_size = SW_BUFFER_INPUT_SIZE;
	serv->buffer_output_size = SW_BUFFER_OUTPUT_SIZE;

	memcpy(serv->package_eof, eof, serv->package_eof_len);
}

int swServer_create(swServer *serv)
{
	//EOF最大长度为8字节
	if (serv->package_eof_len > sizeof(serv->package_eof))
	{
		serv->package_eof_len = sizeof(serv->package_eof);
	}

	//初始化日志
	if (serv->log_file[0] != 0)
	{
		swLog_init(serv->log_file);
	}

	//保存指针到全局变量中去
	//TODO 未来全部使用此方式访问swServer/swFactory对象
	SwooleG.serv = serv;
	SwooleG.factory = &serv->factory;

	//单进程单线程模式
	if (serv->factory_mode == SW_MODE_SINGLE)
	{
		return swReactorProcess_create(serv);
	}
	else
	{
		return swReactorThread_create(serv);
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

	/**
	 * Shutdown heartbeat thread
	 */
	if (SwooleG.heartbeat_pidt)
	{
//		pthread_cancel(SwooleG.heartbeat_pidt, SIGTERM);
		pthread_join(SwooleG.heartbeat_pidt, NULL);
	}
	/**
	 * Wait until all the end of the thread
	 */
	swReactorThread_free(serv);

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
	if (SwooleG.task_worker_num > 0)
	{
		swProcessPool_shutdown(&SwooleG.task_workers);
	}

#ifdef SW_USE_OPENSSL
	if (serv->open_ssl)
	{
		swSSL_free();
		free(serv->ssl_cert_file);
		free(serv->ssl_key_file);
	}
#endif

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
	if (serv->log_file[0] != 0)
	{
		swLog_free();
	}
	swoole_clean();
	return SW_OK;
}

/**
 * only tcp
 */
int swServer_onFinish(swFactory *factory, swSendData *resp)
{
	return swWrite(resp->info.fd, resp->data, resp->info.len);
}

int swServer_udp_send(swServer *serv, swSendData *resp)
{
	socklen_t len;
	struct sockaddr_in addr_in;
	int sock = resp->info.from_fd;

	addr_in.sin_family = AF_INET;
	addr_in.sin_port = htons((unsigned short) resp->info.from_id); //from_id is port
	addr_in.sin_addr.s_addr = resp->info.fd; //from_id is port
	len = sizeof(addr_in);

	return swSendto(sock, resp->data, resp->info.len, 0, (struct sockaddr*) &addr_in, len);
}

int swServer_tcp_send(swServer *serv, int fd, void *data, int length)
{
	swSendData _send;
	swFactory *factory = &(serv->factory);

#ifndef SW_WORKER_SEND_CHUNK
	/**
	 * More than the output buffer
	 */
	if (length >= serv->buffer_output_size)
	{
		swWarn("More than the output buffer size[%d], please use the sendfile.", serv->buffer_output_size);
		return SW_ERR;
	}
	else
	{
		_send.info.fd = fd;
		_send.info.type = SW_EVENT_TCP;
		_send.data = data;

		if (length >= SW_BUFFER_SIZE)
		{
			_send.length = length;
		}
		else
		{
			_send.info.len = length;
			_send.length = 0;
		}
		return factory->finish(factory, &_send);
	}
#else
    char buffer[SW_BUFFER_SIZE];
    int trunk_num = (length / SW_BUFFER_SIZE) + 1;
    int send_n = 0, i, ret;

    swConnection *conn = swServer_connection_get(serv, fd);
    if (conn == NULL || conn->active == 0)
    {
        swWarn("Connection[%d] has been closed.", fd);
        return SW_ERR;
    }

    for (i = 0; i < trunk_num; i++)
    {
        //last chunk
        if (i == (trunk_num - 1))
        {
            send_n = length % SW_BUFFER_SIZE;
            if (send_n == 0)
                break;
        }
        else
        {
            send_n = SW_BUFFER_SIZE;
        }
        memcpy(buffer, data + SW_BUFFER_SIZE * i, send_n);
        _send.info.len = send_n;
        ret = factory->finish(factory, &_send);

#ifdef SW_WORKER_SENDTO_YIELD
        if ((i % SW_WORKER_SENDTO_YIELD) == (SW_WORKER_SENDTO_YIELD - 1))
        {
            swYield();
        }
#endif
    }
    return ret;
#endif
	return SW_OK;
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
		ret = swServer_udp_send(serv, resp);
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

void swServer_signal_init(void)
{
	swSignal_add(SIGHUP, NULL);
	swSignal_add(SIGPIPE, NULL);
	swSignal_add(SIGUSR1, swServer_signal_hanlder);
	swSignal_add(SIGUSR2, swServer_signal_hanlder);
	swSignal_add(SIGTERM, swServer_signal_hanlder);
	swSignal_add(SIGALRM, swTimer_signal_handler);
	//for test
	swSignal_add(SIGVTALRM, swServer_signal_hanlder);
	swServer_set_minfd(SwooleG.serv, SwooleG.signal_fd);
}

int swServer_addListener(swServer *serv, int type, char *host, int port)
{
	swListenList_node *listen_host = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swListenList_node));

	listen_host->type = type;
	listen_host->port = port;
	listen_host->sock = 0;
	listen_host->ssl = 0;

	bzero(listen_host->host, SW_HOST_MAXSIZE);
	strncpy(listen_host->host, host, SW_HOST_MAXSIZE);
	LL_APPEND(serv->listen_list, listen_host);

	//UDP需要提前创建好
	if (type == SW_SOCK_UDP || type == SW_SOCK_UDP6 || type == SW_SOCK_UNIX_DGRAM)
	{
		int sock = swSocket_listen(type, listen_host->host, port, serv->backlog);
		if (sock < 0)
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
		if (type & SW_SOCK_SSL)
		{
			type = type & (~SW_SOCK_SSL);
			listen_host->type = type;
			listen_host->ssl = 1;
		}
		if (type != SW_SOCK_UNIX_STREAM && port <= 0)
		{
			swError("listen port must greater than 0.");
			return SW_ERR;
		}
		serv->have_tcp_sock = 1;
	}
	return SW_OK;
}

/**
 * listen the TCP server socket
 * UDP ignore
 */
int swServer_listen(swServer *serv, swReactor *reactor)
{
	int sock=-1;

	swListenList_node *listen_host;

	LL_FOREACH(serv->listen_list, listen_host)
	{
		//UDP
		if (listen_host->type == SW_SOCK_UDP || listen_host->type == SW_SOCK_UDP6 || listen_host->type == SW_SOCK_UNIX_DGRAM)
		{
			continue;
		}

		//TCP
		sock = swSocket_listen(listen_host->type, listen_host->host, listen_host->port, serv->backlog);
		if (sock < 0)
		{
			LL_DELETE(serv->listen_list, listen_host);
			return SW_ERR;
		}

		if (reactor!=NULL)
		{
			reactor->add(reactor, sock, SW_FD_LISTEN);
		}

#ifdef TCP_DEFER_ACCEPT
		int sockopt;
		if (serv->tcp_defer_accept > 0)
		{
			sockopt = serv->tcp_defer_accept;
			setsockopt(sock, IPPROTO_TCP, TCP_DEFER_ACCEPT, &sockopt, sizeof(sockopt));
		}
#endif
		listen_host->sock = sock;
		//将server socket也放置到connection_list中
		serv->connection_list[sock].fd = sock;
		serv->connection_list[sock].addr.sin_port = listen_host->port;
		//save listen_host object
		serv->connection_list[sock].object = listen_host;
	}
	//将最后一个fd作为minfd和maxfd
	if (sock >= 0)
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

static void swServer_signal_hanlder(int sig)
{
	switch (sig)
	{
	case SIGTERM:
		SwooleG.running = 0;
		break;
	case SIGALRM:
		swTimer_signal_handler(SIGALRM);
		break;
	/**
	 * for test
	 */
	case SIGVTALRM:
		swWarn("SIGVTALRM coming");
		break;
	/**
	 * proxy the restart signal
	 */
	case SIGUSR1:
	case SIGUSR2:
		kill(SwooleGS->manager_pid, SIGUSR1);
		break;
	default:
		break;
	}
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
	if (pthread_create(&heartbeat_pidt, NULL, (void * (*)(void *)) swServer_heartbeat_check, (void *) heartbeat_param) < 0)
	{
		swWarn("pthread_create[hbcheck] fail");
	}
	SwooleG.heartbeat_pidt = heartbeat_pidt;
	pthread_detach(SwooleG.heartbeat_pidt);
}

static void swServer_heartbeat_check(swThreadParam *heartbeat_param)
{
	swEvent notify_ev;
	swServer *serv;
	swFactory *factory;
	swConnection *conn;

	int fd;
	int serv_max_fd;
	int serv_min_fd;
	int checktime;

	notify_ev.len = 0;
	notify_ev.type = SW_CLOSE_PASSIVE;

	swSignal_none();

	while (SwooleG.running)
	{
		serv = heartbeat_param->object;
		factory = &serv->factory;

		serv_max_fd = swServer_get_maxfd(serv);
		serv_min_fd = swServer_get_minfd(serv);

		checktime = (int) time(NULL) - serv->heartbeat_idle_time;

		//遍历到最大fd
		for (fd = serv_min_fd; fd <= serv_max_fd; fd++)
		{
			swTrace("check fd=%d", fd);
			conn = swServer_connection_get(serv, fd);
			if (conn != NULL && 1 == conn->active && conn->last_time < checktime)
			{
				notify_ev.fd = fd;
				factory->end(&serv->factory, &notify_ev);
			}
		}
		sleep(serv->heartbeat_check_interval);
	}
	pthread_exit(0);
}


/**
 * close connection
 */
void swServer_connection_close(swServer *serv, int fd, int notify)
{
	swConnection *conn = swServer_connection_get(serv, fd);
	swReactor *reactor;
	swEvent notify_ev;

	if (conn == NULL)
	{
		swWarn("[Reactor]connection not found. fd=%d|max_fd=%d", fd, swServer_get_maxfd(serv));
		return;
	}

	conn->active = 0;
	/**
	 * Close count
	 */
	sw_atomic_fetch_add(&SwooleStats->close_count, 1);
	sw_atomic_fetch_sub(&SwooleStats->connection_num, 1);

	int reactor_id = conn->from_id;

	swCloseQueue *queue = &serv->reactor_threads[reactor_id].close_queue;

	//将关闭的fd放入队列
	queue->events[queue->num] = fd;
	//增加计数
	queue->num ++;

	reactor = &(serv->reactor_threads[reactor_id].reactor);
	swTrace("Close Event.fd=%d|from=%d", fd, reactor_id);

	//释放缓存区占用的内存
	if (serv->open_eof_check == 1)
	{
		if (conn->in_buffer != NULL)
		{
			swBuffer_free(conn->in_buffer);
			conn->in_buffer = NULL;
		}
	}
	else if (serv->open_length_check == 1)
	{
		if (conn->object != NULL)
		{
			swString_free(conn->object);
		}
	}

	if (conn->out_buffer != NULL)
	{
		swBuffer_free(conn->out_buffer);
		conn->out_buffer = NULL;
	}

	if (conn->in_buffer != NULL)
	{
		swBuffer_free(conn->in_buffer);
		conn->in_buffer = NULL;
	}

	//通知到worker进程
	if (serv->onClose != NULL && notify == 1)
	{
		//通知worker进程
		notify_ev.from_id = reactor_id;
		notify_ev.fd = fd;
		notify_ev.type = SW_EVENT_CLOSE;
		SwooleG.factory->notify(SwooleG.factory, &notify_ev);
	}

	//通知主进程
	if (queue->num == SW_CLOSE_QLEN)
	{
		swReactorThread_close_queue(reactor, queue);
	}

	//立即关闭socket，清理缓存区
	if (serv->tcp_socket_linger > 0)
	{
		struct linger linger;
		linger.l_onoff = 1;
		linger.l_linger = 0;

		if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(struct linger)) == -1)
		{
			swWarn("setsockopt(SO_LINGER) failed. Error: %s[%d]", strerror(errno), errno);
		}
	}

#ifdef SW_USE_OPENSSL
	if (conn->ssl)
	{
		swSSL_close(conn);
	}
#endif

	//关闭此连接，必须放在最前面，以保证线程安全
	reactor->del(reactor, fd);
}


/**
 * new connection
 */
swConnection* swServer_connection_new(swServer *serv, swEvent *ev)
{
	int conn_fd = ev->fd;
	swConnection* connection = NULL;

	SwooleStats->accept_count ++;
	sw_atomic_fetch_add(&SwooleStats->connection_num, 1);

	if (conn_fd > swServer_get_maxfd(serv))
	{
		swServer_set_maxfd(serv, conn_fd);

#ifdef SW_CONNECTION_LIST_EXPAND
	//新的fd超过了最大fd

		//需要扩容
		if (conn_fd == serv->connection_list_capacity - 1)
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
	bzero(connection, sizeof(swConnection));

	connection->fd = conn_fd;
	connection->from_id = ev->from_id;
	connection->from_fd = ev->from_fd;
	connection->connect_time = SwooleGS->now;
	connection->last_time = SwooleGS->now;
	connection->active = 1; //使此连接激活,必须在最后，保证线程安全

	return connection;
}
