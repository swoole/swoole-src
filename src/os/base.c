/*
 * base.c
 *
 *  Created on: 2014-3-21
 *      Author: htf
 */
#include "swoole.h"
#include "async.h"

swPipe swoole_aio_pipe;
int swoole_aio_have_init = 0;
swReactor *swoole_aio_reactor;

void (*swoole_aio_complete_callback)(swAio_event *aio_event);

/**
 * for test
 */
void swoole_aio_callback(swAio_event *aio_event)
{
	printf("content=%s\n", (char *)aio_event->buf);
	printf("fd: %d, request_type: %s, offset: %ld, length: %lu\n", aio_event->fd,
			(aio_event == SW_AIO_READ) ? "READ" : "WRITE", aio_event->offset, (uint64_t) aio_event->nbytes);
	SwooleG.running = 0;
}
