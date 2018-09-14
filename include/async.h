/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2018 The Swoole Group                             |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.0 of the Apache license,    |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.apache.org/licenses/LICENSE-2.0.html                      |
 | If you did not receive a copy of the Apache2.0 license and are unable|
 | to obtain it through the world-wide-web, please send a note to       |
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#ifndef _SW_ASYNC_H_
#define _SW_ASYNC_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifndef O_DIRECT
#define O_DIRECT         040000
#endif

enum swAioOpcode
{
    SW_AIO_RAW,
    SW_AIO_READ = 1,
    SW_AIO_WRITE,
    SW_AIO_GETHOSTBYNAME,
    SW_AIO_GETADDRINFO,
    SW_AIO_STREAM_GET_LINE,
    SW_AIO_READ_FILE,
    SW_AIO_WRITE_FILE,
};

enum swAioFlag
{
    SW_AIO_WRITE_FSYNC = 1u << 1,
    SW_AIO_EOF         = 1u << 2,
};

typedef struct _swAio_event
{
    int fd;
    int task_id;
    uint8_t type;
    uint16_t flags;
    off_t offset;
    size_t nbytes;
    void *buf;
    void *req;
    int ret;
    int error;
    void *object;
    void (*handler)(struct _swAio_event *event);
    void (*callback)(struct _swAio_event *event);
} swAio_event;

typedef void (*swAio_handler)(swAio_event *event);

typedef struct
{
    uint8_t init;
    uint8_t thread_num;
    uint32_t task_num;
    uint16_t current_id;
    swLock lock;
} swAsyncIO;

extern swAsyncIO SwooleAIO;

int swAio_init(void);
void swAio_free(void);
int swAio_dispatch(swAio_event *_event);

void swAio_handler_read(swAio_event *event);
void swAio_handler_write(swAio_event *event);
void swAio_handler_gethostbyname(swAio_event *event);
void swAio_handler_getaddrinfo(swAio_event *event);
void swAio_handler_stream_get_line(swAio_event *event);
void swAio_handler_read_file(swAio_event *event);
void swAio_handler_write_file(swAio_event *event);

#ifdef __cplusplus
}
#endif

#endif /* _SW_ASYNC_H_ */
