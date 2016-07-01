/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
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

#ifndef O_DIRECT
#define O_DIRECT         040000
#endif

enum swAioMode
{
    SW_AIO_BASE = 0,
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
    int task_id;
    uint8_t type;
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
    uint32_t task_num;
    uint16_t current_id;

    void (*destroy)(void);
    void (*callback)(swAio_event *aio_event);
    int (*read)(int fd, void *outbuf, size_t size, off_t offset);
    int (*write)(int fd, void *inbuf, size_t size, off_t offset);
} swAsyncIO;

extern swAsyncIO SwooleAIO;
extern swPipe swoole_aio_pipe;

void swAio_callback_test(swAio_event *aio_event);
int swAio_init(void);
void swAio_free(void);
int swAioBase_init(int max_aio_events);
int swAio_dns_lookup(void *hostname, void *ip_addr, size_t size);

#ifdef HAVE_GCC_AIO
int swAioGcc_init(int max_aio_events);
#endif

#ifdef HAVE_LINUX_AIO
int swAioLinux_init(int max_aio_events);
#endif

#endif /* _SW_ASYNC_H_ */
