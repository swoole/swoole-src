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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "swoole.h"

#ifdef HAVE_SIGNALFD
#include <sys/signalfd.h>
#endif

static void *async_signal_callback[SW_SIGNO_MAX];
static void swSignal_async_handler(int signo);

/**
 * clear all singal
 */
void swSignal_none(void)
{
    sigset_t mask;
    sigfillset(&mask);
    int ret = pthread_sigmask(SIG_BLOCK, &mask, NULL);
    if (ret < 0)
    {
        swWarn("pthread_sigmask() failed. Error: %s[%d]", strerror(ret), ret);
    }
}

/**
 * setup signal
 */
swSignalFunc swSignal_set(int sig, swSignalFunc func, int restart, int mask)
{
	if (func == NULL)
	{
		func =  SIG_IGN;
	}
	struct sigaction act, oact;
	act.sa_handler = func;
	if (mask)
	{
		sigfillset(&act.sa_mask);
	}
	else
	{
		sigemptyset(&act.sa_mask);
	}
	act.sa_flags = 0;
	if (sigaction(sig, &act, &oact) < 0)
	{
		return NULL;
	}
	return oact.sa_handler;
}

void swSignal_add(int signo, swSignalFunc func)
{
#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd)
    {
        swSignalfd_add(signo, func);
    }
    else
#endif
    {
        async_signal_callback[signo] = func;
        swSignal_set(signo, swSignal_async_handler, 1, 0);
    }
}

static void swSignal_async_handler(int signo)
{
    if (SwooleG.main_reactor)
    {
        SwooleG.main_reactor->singal_no = signo;
    }
    else
    {
        swSignal_callback(signo);
    }
}

void swSignal_callback(int signo)
{
    swSignalFunc callback = async_signal_callback[signo];
    callback(signo);
}

#ifdef HAVE_SIGNALFD
#define SW_SIGNAL_INIT_NUM    8

static sigset_t swoole_signalfd_mask;
static int swoole_signalfd = 0;

typedef struct
{
	__sighandler_t callback;
	int signo;
} swSignal_item;

typedef struct
{
	swSignal_item *items;
	uint16_t num;
	uint16_t size;
} swSignal;

static swSignal signalfd_object;

void swSignalfd_init()
{
    sigemptyset(&swoole_signalfd_mask);
    signalfd_object.items = sw_calloc(SW_SIGNAL_INIT_NUM, sizeof(swSignal_item));
    if (signalfd_object.items == NULL)
    {
        swError("malloc for swSignal_item failed.");
    }
    signalfd_object.size = SW_SIGNAL_INIT_NUM;
    signalfd_object.num = 0;
}

void swSignalfd_add(int signo, __sighandler_t callback)
{
    if (signalfd_object.num == signalfd_object.size)
    {
        signalfd_object.items = sw_realloc(signalfd_object.items, sizeof(swSignal_item) * signalfd_object.size * 2);
        if (signalfd_object.items == NULL)
        {
            swError("realloc for swSignal_item failed.");
            return;
        }
        signalfd_object.size = signalfd_object.size * 2;
    }

    sigaddset(&swoole_signalfd_mask, signo);
    signalfd_object.items[signalfd_object.num].callback = callback;
    signalfd_object.items[signalfd_object.num].signo = signo;
    signalfd_object.num++;
}

int swSignalfd_setup(swReactor *reactor)
{
    if (swoole_signalfd == 0)
    {
        swoole_signalfd = signalfd(-1, &swoole_signalfd_mask, SFD_NONBLOCK | SFD_CLOEXEC);
        if (swoole_signalfd < 0)
        {
            swWarn("signalfd() failed. Error: %s[%d]", strerror(errno), errno);
            return SW_ERR;
        }
        SwooleG.signal_fd = swoole_signalfd;
        if (sigprocmask(SIG_BLOCK, &swoole_signalfd_mask, NULL) == -1)
        {
            swWarn("sigprocmask() failed. Error: %s[%d]", strerror(errno), errno);
            return SW_ERR;
        }
        reactor->setHandle(reactor, SW_FD_SIGNAL, swSignalfd_onSignal);
        reactor->add(reactor, swoole_signalfd, SW_FD_SIGNAL);
        return SW_OK;
    }
    else
    {
        swWarn("signalfd has been created");
        return SW_ERR;
    }
}

void swSignalfd_clear()
{
    if (sigprocmask(SIG_UNBLOCK, &swoole_signalfd_mask, NULL) < 0)
    {
        swSysError("sigprocmask(SIG_UNBLOCK) failed.");
    }
    sw_free(signalfd_object.items);
    bzero(&signalfd_object, sizeof(signalfd_object));
    bzero(&swoole_signalfd_mask, sizeof(swoole_signalfd_mask));
}

int swSignalfd_onSignal(swReactor *reactor, swEvent *event)
{
    int n, i;
    struct signalfd_siginfo siginfo;
    n = read(event->fd, &siginfo, sizeof(siginfo));
    if (n < 0)
    {
        swWarn("read from signalfd failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }
    for (i = 0; i < signalfd_object.num; i++)
    {
        if (siginfo.ssi_signo == signalfd_object.items[i].signo && signalfd_object.items[i].callback)
        {
            signalfd_object.items[i].callback(siginfo.ssi_signo);
        }
    }
    return SW_OK;
}

#endif
