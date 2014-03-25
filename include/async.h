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
	int ret;
} swAio_event;

enum
{
	SW_AIO_READ = 0,
	SW_AIO_WRITE = 1,
};

#ifndef O_DIRECT
#define O_DIRECT         040000
#endif

extern swPipe swoole_aio_pipe;
extern int swoole_aio_have_init;
extern swReactor *swoole_aio_reactor;
extern void (*swoole_aio_complete_callback)(swAio_event *aio_event);

void swoole_aio_callback(swAio_event *aio_event);
int swoole_aio_init(swReactor *reactor, int max_aio_events);
void swoole_aio_destroy();
int swoole_aio_read(int fd, void *outbuf, size_t size, off_t offset);
int swoole_aio_write(int fd, void *inbuf, size_t size, off_t offset);
#define swoole_aio_set_callback(callback) swoole_aio_complete_callback = callback

#ifdef HAVE_LINUX_NATIVE_AIO
#include <sys/syscall.h>      /* for __NR_* definitions */
#include <linux/aio_abi.h>    /* for AIO types and constants */
#elif defined(HAVE_EIO)
#else
#include <aio.h>
#endif

#endif /* _SW_ASYNC_H_ */
