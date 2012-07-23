#ifndef SW_SERVER_H_
#define SW_SERVER_H_

#define SW_EVENT_CLOSE                  5
#define SW_EVENT_CONNECT                6

typedef struct _swThreadPoll
{
	pthread_t ptid; //线程ID
	swReactor reactor;
} swThreadPoll;

typedef struct swServer_s swServer;
struct swServer_s
{
	char *host;
	int port;
	int backlog;
	int factory_mode;
	int poll_thread_num;
	int writer_num;
	int worker_num;
	int max_conn;
	int timeout_sec;
	int timeout_usec;
	int daemonize;

	int sock;
	int event_fd;
	int timer_fd;
	int signal_fd;

	int c_pti; //schedule

	swReactor reactor;
	swFactory factory;
	swThreadPoll *threads;
	void *ptr; //reserve
	void *ptr2; //reserve

	void (*onStart)(swServer *serv);
	int (*onReceive)(swFactory *factory, swEventData *data);
	void (*onClose)(swServer *serv, int fd, int from_id);
	void (*onConnect)(swServer *serv, int fd, int from_id);
	void (*onShutdown)(swServer *serv);

};
int swServer_onFinish(swFactory *factory, swSendData *resp);
int swServer_onClose(swReactor *reactor, swEvent *event);
int swServer_onAccept(swReactor *reactor, swEvent *event);

void swServer_init(swServer *serv);
int swServer_start(swServer *serv);
int swServer_create(swServer *serv);
int swServer_free(swServer *serv);
int swServer_close(swServer *factory, swEvent *event);
int swServer_shutdown(swServer *serv);

#endif /* SW_SERVER_H_ */
