/**
 * cmake .
 * make test_server
 * ./bin/test_server
 */
#include "Server.h"

int my_onReceive(swFactory *factory, swEventData *req);
void my_onStart(swServer *serv);
void my_onShutdown(swServer *serv);
void my_onConnect(swServer *serv, int fd, int from_id);
void my_onClose(swServer *serv, int fd, int from_id);
void my_onTimer(swServer *serv, int interval);
void my_onWorkerStart(swServer *serv, int worker_id);
void my_onWorkerStop(swServer *serv, int worker_id);

static int g_receive_count = 0;

/*

 void benchmark_pipe(const int num)
 {
 int pipefd[2], ret;
 char buf[2000];
 pid_t pid;
 int fdin, fdout;

 if (pipe(pipefd) < 0) {
 err_exit("pipe");
 }

 if ((pid = fork()) < 0) {
 err_exit("fork");
 } else if (pid > 0) {

 while ((ret = read(fdin, buf, BUFSIZE)) >= 0) {
 if (ret == 0) {
 break;
 }

 if (write(pipefd[1], buf, ret) != ret) {
 err_exit("paretn write");
 }
 }

 if (ret < 0) {
 err_exit("parent read");
 }
 close(pipefd[1]);
 close(fdin);
 } else {
 close(pipefd[1]);

 if ((fdout = open(dst, O_WRONLY | O_CREAT | O_TRUNC)) < 0) {
 err_exit("child open");
 }

 while ((ret = read(pipefd[0], buf, BUFSIZE)) >= 0) {
 if (ret == 0) {
 break;
 }

 if (write(fdout, buf, ret) != ret) {
 err_exit("child write");
 }
 }

 if (ret < 0) {
 err_exit("child read");
 }
 close(pipefd[0]);
 close(fdout);
 }
 }
 */

//struct mymsg
//{
//	long mtype;
//	char buf[BUFSIZE];
//};
//
//void benchmark_msg(int _num, int worker_num)
//{
//	pid_t pid;
//	int num = _num;
//	int msgid;
//	struct mymsg msg;
//	int ret;
//	struct msqid_ds msqds;
//
//	key_t mskey = ftok(__FILE__, 0);
//	if ((msgid = msgget(mskey, IPC_CREAT | 0666)) <= 0)
//	{
//		err_exit("msgget");
//	}
//
//	int i;
//	for(i=0; i<worker_num; i++)
//	{
//		if ((pid = fork()) < 0)
//		{
//			err_exit("fork");
//		}
//		else if (pid > 0)
//		{
//			continue;
//		}
//		else
//		{
//			int recv = 0;
//			if ((msgid = msgget(mskey, 0)) < 0)
//			{
//				err_exit("child msgget");
//			}
//			double t1 = microtime();
//			while ((ret = msgrcv(msgid, &msg, BUFSIZE, 0, 0)) >= 0)
//			{
//				recv++;
//			}
//			printf("Worker[%d] Finish: recv=%d\n", i, recv);
//			exit(0);
//		}
//	}
//
//	main_loop:
//	memset(msg.buf, 'c', BUFSIZE - 1);
//	msg.buf[BUFSIZE - 1] = 0;
//	msg.mtype = 9;
//
//	while (num >= 0)
//	{
//		if (msgsnd(msgid, &msg, sizeof(msg.buf), 0) < 0)
//		{
//			err_exit("msgsnd");
//		}
//		num--;
//	}
//	if (ret < 0)
//	{
//		err_exit("parent msgsnd");
//	}
//	printf("Send finish\n");
//	int status;
//	for(i=0; i<worker_num; i++)
//	{
//		wait(&status);
//	}
//	msgctl(msgid, IPC_RMID, &msqds);
//}
//void user_signal(int signo)
//{
//    swThreadPool_debug();
//    exit(0);
//}
int main(int argc, char **argv)
{
    int ret;
    swServer serv;
    swServer_init(&serv);  //初始化

    //config
    serv.backlog = 128;
    serv.reactor_num = 4;  //reactor线程数量
    serv.worker_num = 4;  //worker进程数量

    serv.factory_mode = SW_MODE_THREAD;
    //serv.factory_mode = SW_MODE_SINGLE; //SW_MODE_PROCESS/SW_MODE_THREAD/SW_MODE_BASE/SW_MODE_SINGLE
    serv.max_connection = 10000;
    //serv.open_cpu_affinity = 1;
    //serv.open_tcp_nodelay = 1;
    //serv.daemonize = 1;
    serv.open_eof_check = 0;
    memcpy(serv.protocol.package_eof, SW_STRL("\r\n\r\n") - 1);  //开启eof检测，启用buffer区
//	memcpy(serv.log_file, SW_STRL("/tmp/swoole.log")); //日志

    serv.dispatch_mode = 2;
//	serv.open_tcp_keepalive = 1;

#ifdef HAVE_OPENSSL
    //serv.ssl_cert_file = "tests/ssl/ssl.crt";
    //serv.ssl_key_file = "tests/ssl/ssl.key";
    //serv.open_ssl = 1;
#endif

    serv.onStart = my_onStart;
    serv.onShutdown = my_onShutdown;
    serv.onConnect = my_onConnect;
    serv.onReceive = my_onReceive;
    serv.onClose = my_onClose;
    serv.onTimer = my_onTimer;
    serv.onWorkerStart = my_onWorkerStart;
    serv.onWorkerStop = my_onWorkerStop;

//	swSignal_add(SIGINT, user_signal);

    //create Server
    ret = swServer_create(&serv);
    if (ret < 0)
    {
        swTrace("create server fail[error=%d].\n", ret);
        exit(0);
    }
//	swServer_addListen(&serv, SW_SOCK_UDP, "0.0.0.0", 9500);
    swServer_add_listener(&serv, SW_SOCK_TCP, "127.0.0.1", 9501);
    //swServer_addListen(&serv, SW_SOCK_UDP, "127.0.0.1", 9502);
    //swServer_addListen(&serv, SW_SOCK_UDP, "127.0.0.1", 8888);

    //swServer_addTimer(&serv, 2);
    //swServer_addTimer(&serv, 4);

//	g_controller_id = serv.factory.controller(&serv.factory, my_onControlEvent);
    ret = swServer_start(&serv);
    if (ret < 0)
    {
        swTrace("start server fail[error=%d].\n", ret);
        exit(0);
    }
    return 0;
}

void my_onWorkerStart(swServer *serv, int worker_id)
{
    printf("WorkerStart[%d]PID=%d\n", worker_id, getpid());
}

void my_onWorkerStop(swServer *serv, int worker_id)
{
    printf("WorkerStop[%d]PID=%d\n", worker_id, getpid());
}

void my_onTimer(swServer *serv, int interval)
{
    printf("Timer Interval=[%d]\n", interval);
}

int my_onReceive(swFactory *factory, swEventData *req)
{
    int ret;
    char resp_data[SW_BUFFER_SIZE];
    swServer *serv = factory->ptr;

    swSendData resp;
    g_receive_count++;
    memcpy(&resp.info, &req->info, sizeof(resp.info));

    printf("recv %d bytes, data=%s\n", req->info.len, req->data);

    int n = snprintf(resp_data, SW_BUFFER_SIZE, "Server: %*s", req->info.len, req->data);

    resp_data[n] = '\0';

    resp.data = resp_data;
    resp.info.len = n;
    resp.info.type = SW_EVENT_TCP;
    resp.length = 0;

    printf("send %d bytes. data=%s\n", n, resp_data);

    return SW_OK;

    ret = factory->finish(factory, &resp);
    if (ret < 0)
    {
        printf("send to client fail. errno=%d\n", errno);
    }

    if (req->info.from_id >= serv->reactor_num)
    {
        struct in_addr addr;
        addr.s_addr = req->info.fd;

        //printf("onReceive[%d]: ip=%s:%d, Data=%s\n", g_receive_count, inet_ntoa(addr), req->info.from_id, rtrim(req->data, req->info.len));
    }
    else
    {
        swConnection *conn = swWorker_get_connection(serv, req->info.fd);
        swoole_rtrim(req->data, req->info.len);
        printf("onReceive[%d]: ip=%s|port=%d Data=%s|Len=%d\n", g_receive_count, swConnection_get_ip(conn),
                swConnection_get_port(conn), req->data, req->info.len);
    }
//	req->info.type = 99;
//	factory->event(factory, g_controller_id, req);
    return SW_OK;
}

void my_onStart(swServer *serv)
{
    sw_log("Server is running");
}

void my_onShutdown(swServer *serv)
{
    sw_log("Server is shutdown\n");
}

void my_onConnect(swServer *serv, int fd, int from_id)
{
//	ProfilerStart("/tmp/profile.prof");
    //printf("PID=%d\tConnect fd=%d|from_id=%d\n", getpid(), fd, from_id);
}

void my_onClose(swServer *serv, int fd, int from_id)
{
    //printf("PID=%d\tClose fd=%d|from_id=%d\n", getpid(), fd, from_id);
//	ProfilerStop();
}
