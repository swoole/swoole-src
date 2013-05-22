/*
 * Client.h
 *
 *  Created on: 2012-7-22
 *      Author: htf
 */

#ifndef SW_CLIENT_H_
#define SW_CLIENT_H_

#define SW_SOCK_ASYNC    1
#define SW_SOCK_SYNC     0

typedef struct _swClient
{
	int sock;
	int id;
	int type;
	int sock_type;
	int sock_domain;
	int protocol;
	int async;
	float timeout;

	struct sockaddr_in serv_addr;
	struct sockaddr_in remote_addr;

	void (*onConnect)(struct _swClient *cli);
	int (*onReceive)(struct _swClient *cli, swEventData *data);
	void (*onClose)(struct _swClient *cli, int fd, int from_id);

	int (*connect)(struct _swClient *cli, char *host, int port, float timeout, int udp_connect);
	int (*send)(struct _swClient *cli, char *data, int length);
	int (*recv)(struct _swClient *cli, char *data, int len, int waitall);
	int (*close)(struct _swClient *cli);
} swClient;

int swClient_create(swClient *cli, int type, int async);
int swClient_close(swClient *cli);

int swClient_tcp_connect(swClient *cli, char *host, int port, float timeout, int udp_connect);
int swClient_tcp_send(swClient *cli, char *data, int length);
int swClient_tcp_recv(swClient *cli, char *data, int len, int waitall);

int swClient_udp_connect(swClient *cli, char *host, int port, float timeout, int udp_connect);
int swClient_udp_send(swClient *cli, char *data, int length);
int swClient_udp_recv(swClient *cli, char *data, int len, int waitall);

#endif /* SW_CLIENT_H_ */
