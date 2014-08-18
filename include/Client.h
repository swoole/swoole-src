/*
 * Client.h
 *
 *  Created on: 2012-7-22
 *      Author: tianfeng.han
 */

#ifndef SW_CLIENT_H_
#define SW_CLIENT_H_

#include "buffer.h"
#include "Connection.h"

#define SW_SOCK_ASYNC    1
#define SW_SOCK_SYNC     0

typedef struct _swClient
{
	int id;
	int type;
	int sock_type;
	int sock_domain;
	int protocol;
	int reactor_fdtype;

	uint8_t async;
	uint8_t keep;

	uint8_t open_eof_check;
	char *package_eof;
	uint16_t package_eof_len;

	/* one package: length check */
    uint8_t open_length_check;

    char package_length_type;
    uint8_t package_length_size;
    uint16_t package_length_offset;
    uint16_t package_body_offset;
    uint32_t package_max_length;

    uint32_t udp_sock_buffer_size;

	char *server_str;
	void *ptr;

	uint8_t server_strlen;
	double timeout;

	struct sockaddr_in server_addr;
	struct sockaddr_in remote_addr;

	swConnection connection;

	void (*onConnect)(struct _swClient *cli);
	int (*onReceive)(struct _swClient *cli, swSendData *data);
	void (*onClose)(struct _swClient *cli, int fd, int from_id);

	int (*connect)(struct _swClient *cli, char *host, int port, double _timeout, int sock_flag);
	int (*send)(struct _swClient *cli, char *data, int length);
	int (*sendfile)(struct _swClient *cli, char *filename);
	int (*recv)(struct _swClient *cli, char *data, int len, int waitall);
	int (*close)(struct _swClient *cli);

} swClient;

int swClient_create(swClient *cli, int type, int async);
int swDNSResolver_request(char *domain, void (*callback)(void *addrs));

#endif /* SW_CLIENT_H_ */
