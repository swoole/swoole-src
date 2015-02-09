/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
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

#ifndef KQUEUE_IDE_HELPER_H_
#define KQUEUE_IDE_HELPER_H_

struct kevent
{
    char *udata;
    int filter;
};

#define EVFILT_READ         1
#define EVFILT_WRITE        2

#define EV_ADD              2
#define EV_DELETE           4
#define EV_CLEAR            8

int kevent(int, void *, int, struct kevent*, int, struct timespec *);
int kqueue(void);
int EV_SET(struct kevent*, int, int, int, int, int, void*);

#endif /* KQUEUE_IDE_HELPER_H_ */
