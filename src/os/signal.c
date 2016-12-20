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

#include "swoole.h"

#ifdef HAVE_SIGNALFD
#include <sys/signalfd.h>
static void swSignalfd_set(int signo, swSignalHander callback);
static void swSignalfd_clear();
static int swSignalfd_onSignal(swReactor *reactor, swEvent *event);

static sigset_t signalfd_mask;
static int signal_fd = 0;
#endif

typedef struct
{
    swSignalHander callback;
    uint16_t signo;
    uint16_t active;
} swSignal;

static swSignal signals[SW_SIGNO_MAX];
static int _lock = 0;

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
swSignalHander swSignal_set(int sig, swSignalHander func, int restart, int mask)
{
    //ignore
    if (func == NULL)
    {
        func = SIG_IGN;
    }
    //clear
    else if ((long) func == -1)
    {
        func = SIG_DFL;
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

void swSignal_add(int signo, swSignalHander func)
{
#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd)
    {
        swSignalfd_set(signo, func);
    }
    else
#endif
    {
        signals[signo].callback = func;
        signals[signo].active = 1;
        signals[signo].signo = signo;
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
        //discard signal
        if (_lock)
        {
            return;
        }
        _lock = 1;
        swSignal_callback(signo);
        _lock = 0;
    }
}

void swSignal_callback(int signo)
{
    if (signo >= SW_SIGNO_MAX)
    {
        swWarn("signal[%d] numberis invalid.", signo);
        return;
    }
    swSignalHander callback = signals[signo].callback;
    if (!callback)
    {
        swWarn("signal[%d] callback is null.", signo);
        return;
    }
    callback(signo);
}

void swSignal_clear(void)
{
#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd)
    {
        swSignalfd_clear();
    }
    else
#endif
    {
        int i;
        for (i = 0; i < SW_SIGNO_MAX; i++)
        {
            if (signals[i].active)
            {
                swSignal_set(signals[i].signo, (swSignalHander) -1, 1, 0);
            }
        }
    }
    bzero(&signals, sizeof(signals));
}

#ifdef HAVE_SIGNALFD
void swSignalfd_init()
{
    sigemptyset(&signalfd_mask);
    bzero(&signals, sizeof(signals));
}

static void swSignalfd_set(int signo, swSignalHander callback)
{
    if (callback == NULL && signals[signo].active)
    {
        sigdelset(&signalfd_mask, signo);
        bzero(&signals[signo], sizeof(swSignal));

        if (signal_fd > 0)
        {
            sigprocmask(SIG_BLOCK, &signalfd_mask, NULL);
        }
    }
    else
    {
        sigaddset(&signalfd_mask, signo);
        signals[signo].callback = callback;
        signals[signo].signo = signo;
        signals[signo].active = 1;
    }
}

int swSignalfd_setup(swReactor *reactor)
{
    if (signal_fd == 0)
    {
        signal_fd = signalfd(-1, &signalfd_mask, SFD_NONBLOCK | SFD_CLOEXEC);
        if (signal_fd < 0)
        {
            swWarn("signalfd() failed. Error: %s[%d]", strerror(errno), errno);
            return SW_ERR;
        }
        SwooleG.signal_fd = signal_fd;
        if (sigprocmask(SIG_BLOCK, &signalfd_mask, NULL) == -1)
        {
            swWarn("sigprocmask() failed. Error: %s[%d]", strerror(errno), errno);
            return SW_ERR;
        }
        reactor->setHandle(reactor, SW_FD_SIGNAL, swSignalfd_onSignal);
        reactor->add(reactor, signal_fd, SW_FD_SIGNAL);
        return SW_OK;
    }
    else
    {
        swWarn("signalfd has been created");
        return SW_ERR;
    }
}

static void swSignalfd_clear()
{
    if (signal_fd)
    {
        if (sigprocmask(SIG_UNBLOCK, &signalfd_mask, NULL) < 0)
        {
            swSysError("sigprocmask(SIG_UNBLOCK) failed.");
        }
        close(signal_fd);
        bzero(&signalfd_mask, sizeof(signalfd_mask));
    }
    signal_fd = 0;
}

static int swSignalfd_onSignal(swReactor *reactor, swEvent *event)
{
    int n;
    struct signalfd_siginfo siginfo;
    n = read(event->fd, &siginfo, sizeof(siginfo));
    if (n < 0)
    {
        swWarn("read from signalfd failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }

    if (signals[siginfo.ssi_signo].active)
    {
        if (signals[siginfo.ssi_signo].callback)
        {
            signals[siginfo.ssi_signo].callback(siginfo.ssi_signo);
        }
        else
        {
            swWarn("signal[%d] callback is null.", siginfo.ssi_signo);
        }
    }

    return SW_OK;
}

#endif
