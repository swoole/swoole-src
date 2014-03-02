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

int swoole_aio_init(swReactor *reactor, int max_aio_events);
void swoole_aio_destroy();
int swoole_aio_read(int fd, void *outbuf, size_t size, off_t offset);
int swoole_aio_write(int fd, void *inbuf, size_t size, off_t offset);

#endif /* _SW_AIO_H_ */
