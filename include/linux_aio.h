/*
 * aio.h
 *
 *  Created on: 2014-3-2
 *      Author: htf
 */

#ifndef _SW_AIO_H_
#define _SW_AIO_H_

#include <sys/syscall.h>      /* for __NR_* definitions */
#include <linux/aio_abi.h>    /* for AIO types and constants */

#ifndef O_DIRECT
#define O_DIRECT     040000
#endif

int swoole_aio_init(swReactor *reactor, int max_aio_events);
void swoole_aio_destroy();
int swoole_aio_read(int fd, void *outbuf, size_t size, off_t offset);
int swoole_aio_write(int fd, void *inbuf, size_t size, off_t offset);

extern void (*swoole_aio_complete_callback)(struct io_event *events, int n);
#define swoole_aio_set_callback(callback) swoole_aio_complete_callback = callback

#endif /* _SW_AIO_H_ */
