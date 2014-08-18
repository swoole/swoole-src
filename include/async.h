/*
 * async.h
 *
 *  Created on: 2014-3-21
 *      Author: htf
 */

#ifndef _SW_ASYNC_H_
#define _SW_ASYNC_H_

#ifndef O_DIRECT
#define O_DIRECT         040000
#endif

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

typedef struct
{
    uint8_t init;
    uint8_t mode;
    uint8_t thread_num;

    swReactor *reactor;

    void (*destroy)(void);
    void (*callback)(swAio_event *aio_event);
    int (*read)(int fd, void *outbuf, size_t size, off_t offset);
    int (*write)(int fd, void *inbuf, size_t size, off_t offset);
} swAIO;

extern swPipe swoole_aio_pipe;
extern swAIO SwooleAIO;

void swAio_callback_test(swAio_event *aio_event);
int swAio_init(void);
int swAioBase_init(int max_aio_events);
int swAio_dns_lookup(void *hostname, void *ip_addr, size_t size);

#ifdef HAVE_GCC_AIO
int swAioGcc_init(int max_aio_events);
#endif

#ifdef HAVE_LINUX_AIO
int swAioLinux_init(int max_aio_events);
#endif

#endif /* _SW_ASYNC_H_ */
