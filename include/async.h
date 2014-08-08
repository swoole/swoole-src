/*
 * async.h
 *
 *  Created on: 2014-3-21
 *      Author: htf
 */

#ifndef _SW_ASYNC_H_
#define _SW_ASYNC_H_

typedef struct _swAio_event
{
	int fd;
	int type; //read,write
	off_t offset;
	size_t nbytes;
	void *buf;
	void *req;
	int ret;
	int error;
} swAio_event;

enum swAioMode
{
    SW_AIO_BASE = 0,
    SW_AIO_GCC,
    SW_AIO_LINUX,
};

enum
{
	SW_AIO_READ = 0,
	SW_AIO_WRITE = 1,
	SW_AIO_DNS_LOOKUP = 2,
};

#ifndef O_DIRECT
#define O_DIRECT         040000
#endif

extern swPipe swoole_aio_pipe;
extern swReactor *swoole_aio_reactor;

typedef struct
{
    void (*destroy)(void);
    void (*callback)(swAio_event *aio_event);
    int (*read)(int fd, void *outbuf, size_t size, off_t offset);
    int (*write)(int fd, void *inbuf, size_t size, off_t offset);
} swAIO;

extern swAIO SwooleAIO;
extern int swoole_aio_have_init;

void swoole_aio_callback(swAio_event *aio_event);

int swAioBase_init(swReactor *_reactor, int max_aio_events);

#ifdef HAVE_GCC_AIO
int swAioGcc_init(swReactor *_reactor, int max_aio_events);
#endif

#ifdef HAVE_LINUX_AIO
int swAioLinux_init(swReactor *_reactor, int max_aio_events);
#endif

int swoole_aio_dns_lookup(void *hostname, void *ip_addr, size_t size);

#endif /* _SW_ASYNC_H_ */
