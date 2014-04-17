/*
 * Client.h
 *
 *  Created on: 2012-7-22
 *      Author: tianfeng.han
 */

#ifndef SW_CLIENT_H_
#define SW_CLIENT_H_

#include "buffer.h"

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
	int reactor_fdtype;

	uint8_t async;
	uint8_t connected;
	uint8_t keep;
	char *server_str;
	uint8_t server_strlen;
	double timeout;

	struct sockaddr_in serv_addr;
	struct sockaddr_in remote_addr;

	swBuffer *out_buffer;

	void (*onConnect)(struct _swClient *cli);
	int (*onReceive)(struct _swClient *cli, swSendData *data);
	void (*onClose)(struct _swClient *cli, int fd, int from_id);

	int (*connect)(struct _swClient *cli, char *host, int port, double _timeout, int sock_flag);
	int (*send)(struct _swClient *cli, char *data, int length);
	int (*recv)(struct _swClient *cli, char *data, int len, int waitall);
	int (*close)(struct _swClient *cli);
} swClient;

int swClient_create(swClient *cli, int type, int async);
int swClient_close(swClient *cli);

#endif /* SW_CLIENT_H_ */
