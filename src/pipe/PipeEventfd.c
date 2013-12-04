#include "swoole.h"

#ifdef HAVE_EVENTFD

static int swPipeEventfd_read(swPipe *p, void *data, int length);
static int swPipeEventfd_write(swPipe *p, void *data, int length);
static int swPipeEventfd_getFd(swPipe *p, int isWriteFd);
static int swPipeEventfd_close(swPipe *p);

typedef struct _swPipeEventfd
{
	int event_fd;
} swPipeEventfd;

int swPipeEventfd_create(swPipe *p, int blocking, int semaphore)
{
	int efd;
	int flag = 0;
	swPipeEventfd *object = sw_malloc(sizeof(swPipeEventfd));
	if (object == NULL)
	{
		return -1;
	}
	if(blocking == 0)
	{
		flag = EFD_NONBLOCK;
	}
	if(semaphore == 1)
	{
		flag |= EFD_SEMAPHORE;
	}
	p->blocking = blocking;
	efd = eventfd(0, flag);
	if (efd < 0)
	{
		return -1;
	}
	else
	{
		p->object = object;
		p->read = swPipeEventfd_read;
		p->write = swPipeEventfd_write;
		p->getFd = swPipeEventfd_getFd;
		p->close = swPipeEventfd_close;
		object->event_fd = efd;
	}
	return 0;
}

static int swPipeEventfd_read(swPipe *p, void *data, int length)
{
	int ret;
	swPipeEventfd *this = p->object;
	while (1)
	{
		ret = read(this->event_fd, data, sizeof(uint64_t));
		if (ret < 0 && errno == EINTR)
		{
			continue;
		}
		break;
	}
	return ret;
}

static int swPipeEventfd_write(swPipe *p, void *data, int length)
{
	int ret;
	swPipeEventfd *this = p->object;
	while (1)
	{
		ret = write(this->event_fd, data, sizeof(uint64_t));
		if (ret < 0)
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
		}
		break;
	}
	return ret;
}

static int swPipeEventfd_getFd(swPipe *p, int isWriteFd)
{
	return ((swPipeEventfd *)(p->object))->event_fd;
}

static int swPipeEventfd_close(swPipe *p)
{
	int ret;
	ret = close(((swPipeEventfd *)(p->object))->event_fd);
	sw_free(p->object);
	return ret;
}

#endif
