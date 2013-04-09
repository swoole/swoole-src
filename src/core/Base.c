#include "swoole.h"

inline int swSocket_create(int type)
{
	int _domain;
	int _type;

	switch (type)
	{
	case SW_SOCK_TCP:
		_domain = PF_INET;
		_type = SOCK_STREAM;
		break;
	case SW_SOCK_TCP6:
		_domain = PF_INET6;
		_type = SOCK_STREAM;
		break;
	case SW_SOCK_UDP:
		_domain = PF_INET;
		_type = SOCK_DGRAM;
		break;
	case SW_SOCK_UDP6:
		_domain = PF_INET6;
		_type = SOCK_DGRAM;
		break;
	default:
		return SW_ERR;
	}
	return socket(_domain, _type, 0);
}

inline void swFloat2timeval(float timeout,long int *sec, long int *usec)
{
	*sec = (int)timeout;
	*usec = (int)((timeout*1000*1000) - ((*sec)*1000*1000));
}

inline int swSocket_listen(int type, char *host, int port, int backlog)
{
	int sock;
	int option;
	int ret;

	struct sockaddr_in addr_in4;
	struct sockaddr_in6 addr_in6;

	sock = swSocket_create(type);
	if (sock < 0)
	{
		swTrace("Create socket fail.type=%d|Errno=%d\n", type, errno);
		return SW_ERR;
	}

	//reuse
	option = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(int));

	//IPv6
	if(type > SW_SOCK_UDP)
	{
		bzero(&addr_in6, sizeof(addr_in6));
		inet_pton(AF_INET6, host, &(addr_in6.sin6_addr));
		addr_in6.sin6_port = htons(port);
		addr_in6.sin6_family = AF_INET6;
		ret = bind(sock, (struct sockaddr *) &addr_in6, sizeof(addr_in6));
	}
	//IPv4
	else
	{
		bzero(&addr_in4, sizeof(addr_in4));
		inet_pton(AF_INET, host, &(addr_in4.sin_addr));
		addr_in4.sin_port = htons(port);
		addr_in4.sin_family = AF_INET;
		ret = bind(sock, (struct sockaddr *) &addr_in4, sizeof(addr_in4));
	}
	//将监听套接字同sockaddr绑定
	if (ret < 0)
	{
		swTrace("bind fail.type=%d|host=%s|port=%d|Errno=%d\n", type, host, port, errno);
		return SW_ERR;
	}
	if(type == SW_SOCK_UDP || type == SW_SOCK_UDP6)
	{
		swSetNonBlock(sock);
		return sock;
	}
	//开始监听套接字
	ret = listen(sock, backlog);
	if (ret < 0)
	{
		swTrace("Listen fail.type=%d|host=%s|port=%d|Errno=%d\n", type, host, port, errno);
		return SW_ERR;
	}
	return sock;
}

int swRead(int fd, char *buf, int count)
{
	int nread, totlen = 0;
	while (1)
	{
		nread = read(fd, buf, count - totlen);
		if (nread == 0)
			return totlen;
		if (nread == -1)
		{
			if (errno == EINTR)
			{
				continue;
			}
			else if (errno == EAGAIN)
			{
				break;
			}
			else
				return -1;
		}
		totlen += nread;
		buf += nread;
	}
	return totlen;
}

int swWrite(int fd, char *buf, int count)
{
	int nwritten, totlen = 0;
	while (totlen != count)
	{
		nwritten = write(fd, buf, count - totlen);
		if (nwritten == 0)
			return totlen;
		if (nwritten == -1)
		{
			if (errno == EINTR)
			{
				continue;
			}
			else if (errno == EAGAIN)
			{
				usleep(1);
				continue;
			}
			else
				return -1;
		}
		totlen += nwritten;
		buf += nwritten;
	}
	return totlen;
}

//将套接字设置为非阻塞方式
void swSetNonBlock(int sock)
{
	int opts;
	opts = fcntl(sock, F_GETFL);
	if (opts < 0)
	{
		perror("fcntl(sock,GETFL)");
		exit(1);
	}

	opts = opts | O_NONBLOCK;
	if (fcntl(sock, F_SETFL, opts) < 0)
	{
		perror("fcntl(sock,SETFL,opts)");
		exit(1);
	}
}

void swSetBlock(int sock)
{
	int opts;
	opts = fcntl(sock, F_GETFL);
	if (opts < 0)
	{
		perror("fcntl(sock,GETFL)");
		exit(1);
	}

	opts = opts & ~O_NONBLOCK;
	if (fcntl(sock, F_SETFL, opts) < 0)
	{
		perror("fcntl(sock,SETFL,opts)");
		exit(1);
	}
}

