#include "swoole.h"

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

