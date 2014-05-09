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
		swWarn("pthread_sigmask fail: %s", strerror(ret));
	}
}

/**
 * setup signal
 */
swSignalFunc swSignal_set(int sig, swSignalFunc func, int restart, int mask)
{
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
		if (func == NULL)
		{
			func = SIG_IGN;
		}
		swSignal_set(signo, func, 1, 0);
	}
}

#ifdef HAVE_SIGNALFD
/**
 * signalfd
 */
#include <sys/signalfd.h>

#define SW_SIGNAL_INIT_NUM    8

static int swSignalfd_onSignal(swReactor *reactor, swEvent *event);

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

static swSignal object;

void swSignalfd_init()
{
	sigemptyset(&swoole_signalfd_mask);
	object.items = sw_calloc(SW_SIGNAL_INIT_NUM, sizeof(swSignal_item));
	if (object.items == NULL)
	{
		swError("malloc for swSignal_item failed.");
	}
	object.size = SW_SIGNAL_INIT_NUM;
	object.num = 0;
}

void swSignalfd_add(int signo, __sighandler_t callback)
{
	if (object.num == object.size)
	{
		object.items = sw_realloc(object.items, sizeof(swSignal_item) * object.size * 2);
		if (object.items == NULL)
		{
			swError("realloc for swSignal_item failed.");
			return;
		}
		object.size = object.size * 2;
	}
	sigaddset(&swoole_signalfd_mask, signo);
	object.items[object.num].callback = callback;
	object.items[object.num].signo = signo;
	object.num ++;
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

static int swSignalfd_onSignal(swReactor *reactor, swEvent *event)
{
	int n, i;
	struct signalfd_siginfo siginfo;
	n = read(event->fd, &siginfo, sizeof(siginfo));
	if (n < 0)
	{
		swWarn("read from signalfd failed. Error: %s[%d]", strerror(errno), errno);
		return SW_ERR;
	}
	for(i = 0; i < object.num; i++)
	{
		if (siginfo.ssi_signo == object.items[i].signo && object.items[i].callback)
		{
			object.items[i].callback(siginfo.ssi_signo);
		}
	}
	return SW_OK;
}

#endif
