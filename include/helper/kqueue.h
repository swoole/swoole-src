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
 | Author: Tianfeng Han  <rango@swoole.com>                             |
 +----------------------------------------------------------------------+
 */

#ifndef KQUEUE_IDE_HELPER_H_
#define KQUEUE_IDE_HELPER_H_
#ifdef USE_KQUEUE_IDE_HELPER

#include <stdint.h>

#define EVFILT_READ             (-1)
#define EVFILT_WRITE            (-2)
#define EVFILT_SIGNAL           (-6)

/* kevent system call flags */
#define KEVENT_FLAG_NONE                         0x000000       /* no flag value */
#define KEVENT_FLAG_IMMEDIATE                    0x000001       /* immediate timeout */
#define KEVENT_FLAG_ERROR_EVENTS                 0x000002       /* output events only include change errors */


/* actions */
#define EV_ADD              0x0001      /* add event to kq (implies enable) */
#define EV_DELETE           0x0002      /* delete event from kq */
#define EV_ENABLE           0x0004      /* enable event */
#define EV_DISABLE          0x0008      /* disable event (not reported) */

/* flags */
#define EV_ONESHOT          0x0010      /* only report one occurrence */
#define EV_CLEAR            0x0020      /* clear event state after reporting */
#define EV_RECEIPT          0x0040      /* force immediate event output */
                                        /* ... with or without EV_ERROR */
                                        /* ... use KEVENT_FLAG_ERROR_EVENTS */
                                        /*     on syscalls supporting flags */

#define EV_DISPATCH         0x0080      /* disable event after reporting */
#define EV_UDATA_SPECIFIC   0x0100      /* unique kevent per udata value */

#define EV_DISPATCH2        (EV_DISPATCH | EV_UDATA_SPECIFIC)
/* ... in combination with EV_DELETE */
/* will defer delete until udata-specific */
/* event enabled. EINPROGRESS will be */
/* returned to indicate the deferral */

#define EV_VANISHED         0x0200      /* report that source has vanished  */
                                        /* ... only valid with EV_DISPATCH2 */

#define EV_SYSFLAGS         0xF000      /* reserved by system */
#define EV_FLAG0            0x1000      /* filter-specific flag */
#define EV_FLAG1            0x2000      /* filter-specific flag */

/* returned values */
#define EV_EOF              0x8000      /* EOF detected */
#define EV_ERROR            0x4000      /* error, data contains errno */

/*
 * Filter specific flags for EVFILT_READ
 *
 * The default behavior for EVFILT_READ is to make the "read" determination
 * relative to the current file descriptor read pointer.
 *
 * The EV_POLL flag indicates the determination should be made via poll(2)
 * semantics. These semantics dictate always returning true for regular files,
 * regardless of the amount of unread data in the file.
 *
 * On input, EV_OOBAND specifies that filter should actively return in the
 * presence of OOB on the descriptor. It implies that filter will return
 * if there is OOB data available to read OR when any other condition
 * for the read are met (for example number of bytes regular data becomes >=
 * low-watermark).
 * If EV_OOBAND is not set on input, it implies that the filter should not actively
 * return for out of band data on the descriptor. The filter will then only return
 * when some other condition for read is met (ex: when number of regular data bytes
 * >=low-watermark OR when socket can't receive more data (SS_CANTRCVMORE)).
 *
 * On output, EV_OOBAND indicates the presence of OOB data on the descriptor.
 * If it was not specified as an input parameter, then the data count is the
 * number of bytes before the current OOB marker, else data count is the number
 * of bytes beyond OOB marker.
 */
#define EV_POLL         EV_FLAG0
#define EV_OOBAND       EV_FLAG1

struct kevent {
    uintptr_t       ident;          /* identifier for this event */
    int16_t         filter;         /* filter for event */
    uint16_t        flags;          /* general flags */
    uint32_t        fflags;         /* filter-specific flags */
    intptr_t        data;           /* filter-specific data */
    void            *udata;         /* opaque user data identifier */
};

int kqueue(void);
int kevent(
    int kq,
    const struct kevent *changelist, int nchanges,
    struct kevent *eventlist, int nevents,
    const struct timespec *timeout
);

#define EV_SET(kevp, a, b, c, d, e, f) do {     \
    struct kevent *__kevp__ = (kevp);       \
    __kevp__->ident = (a);                  \
    __kevp__->filter = (b);                 \
    __kevp__->flags = (c);                  \
    __kevp__->fflags = (d);                 \
    __kevp__->data = (e);                   \
    __kevp__->udata = (f);                  \
} while(0)

#endif /* USE_KQUEUE_IDE_HELPER */
#endif /* KQUEUE_IDE_HELPER_H_ */
