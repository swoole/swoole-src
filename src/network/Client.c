#include "swoole.h"
#include "Client.h"

int swClient_create(swClient *cli, int type, int async)
{
	int _domain;
	int _type;
	bzero(cli, sizeof(*cli));
	switch (type)
	{
	case SW_SOCK_TCP:
		_domain = AF_INET;
		_type = SOCK_STREAM;
		break;
	case SW_SOCK_TCP6:
		_domain = AF_INET6;
		_type = SOCK_STREAM;
		break;
	case SW_SOCK_UDP:
		_domain = AF_INET;
		_type = SOCK_DGRAM;
		break;
	case SW_SOCK_UDP6:
		_domain = AF_INET6;
		_type = SOCK_DGRAM;
		break;
	default:
		return SW_ERR;
	}
	cli->sock = socket(_domain, _type, 0);
	if (cli->sock < 0)
	{
		return SW_ERR;
	}
	if (type < SW_SOCK_UDP)
	{
		cli->connect = swClient_tcp_connect;
		cli->recv = swClient_tcp_recv;
		cli->send = swClient_tcp_send;
	}
	else
	{
		cli->connect = swClient_udp_connect;
		cli->recv = swClient_udp_recv;
		cli->send = swClient_udp_send;
	}
	cli->close = swClient_close;
	cli->sock_domain = _domain;
	cli->sock_type = SOCK_DGRAM;
	cli->type = type;
	cli->async = async;
	return SW_OK;
}

int swClient_close(swClient *cli)
{
	int fd = cli->sock;
	cli->sock = 0;
	return close(fd);
}

int swClient_tcp_connect(swClient *cli, char *host, int port, float timeout, int nonblock)
{
	int ret;
	cli->serv_addr.sin_family = cli->sock_domain;
	cli->serv_addr.sin_port = htons(port);
	cli->serv_addr.sin_addr.s_addr = inet_addr(host);

	cli->timeout = timeout;
	swSetTimeout(cli->sock, timeout);
	if(nonblock == 1)
	{
		swSetNonBlock(cli->sock);
	}
	else
	{
		swSetBlock(cli->sock);
	}

	while (1)
	{
		ret = connect(cli->sock, (struct sockaddr *) (&cli->serv_addr), sizeof(cli->serv_addr));
		if (ret < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}
		}
		break;
	}
	return ret;
}

int swClient_tcp_send(swClient *cli, char *data, int length)
{
	int written = 0;
	int n;

	//总超时，for循环中计时
	while (written < length)
	{
		n = send(cli->sock, data, length - written, 0);

		if (n < 0) //反过来
		{
			if (errno == EAGAIN || errno == EINTR)
			{
				continue;
			}
			else
			{
				return SW_ERR;
			}
		}
		written += n;
		data += n;
	}
	return written;
}

int swClient_tcp_recv(swClient *cli, char *data, int len, int waitall)
{
	int flag = 0, ret;
	if (waitall == 1)
	{
		flag = MSG_WAITALL;
	}

	ret = recv(cli->sock, data, len, flag);

	if (ret < 0)
	{
		if (errno == 4)
		{
			ret = recv(cli->sock, data, len, flag);
		}
		else
		{
			return SW_ERR;
		}
	}
	return ret;
}

int swClient_udp_connect(swClient *cli, char *host, int port, float timeout, int udp_connect)
{
	int ret;
	char buf[1024];

	cli->timeout = timeout;
	ret = swSetTimeout(cli->sock, timeout);
	if(ret < 0)
	{
		swWarn("setTimeout fail.errno=%d\n", errno);
		return SW_ERR;
	}

	cli->serv_addr.sin_family = cli->sock_domain;
	cli->serv_addr.sin_port = htons(port);
	cli->serv_addr.sin_addr.s_addr = inet_addr(host);

	if(udp_connect != 1)
	{
		return SW_OK;
	}

	if(connect(cli->sock, (struct sockaddr *) (&cli->serv_addr), sizeof(cli->serv_addr)) == 0)
	{
		//清理connect前的buffer数据遗留
		while(recv(cli->sock, buf, 1024 , MSG_DONTWAIT) > 0);
		return SW_OK;
	}
	else
	{
		return SW_ERR;
	}
}

int swClient_udp_send(swClient *cli, char *data, int len)
{
	int n;
	n = sendto(cli->sock, data, len , 0, (struct sockaddr *) (&cli->serv_addr), sizeof(struct sockaddr));
	if(n < 0 || n < len)
	{

		return SW_ERR;
	}
	else
	{
		return n;
	}
}

int swClient_udp_recv(swClient *cli, char *data, int length, int waitall)
{
	int flag = 0, ret;
	socklen_t len;

	if(waitall == 1)
	{
		flag = MSG_WAITALL;

	}
	len = sizeof(struct sockaddr);
	ret = recvfrom(cli->sock, data, length, flag, (struct sockaddr *) (&cli->remote_addr), &len);
	if(ret < 0)
	{
		if(errno == EINTR)
		{
			ret = recvfrom(cli->sock, data, length, flag, (struct sockaddr *) (&cli->remote_addr), &len);
		}
		else
		{
			return SW_ERR;
		}
	}
	return ret;
}
