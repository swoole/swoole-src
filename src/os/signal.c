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

#include "swoole_api.h"

#ifdef HAVE_SIGNALFD
#include <sys/signalfd.h>
static void swSignalfd_set(int signo, swSignalHandler handler);
static void swSignalfd_clear();
static int swSignalfd_onSignal(swReactor *reactor, swEvent *event);

static sigset_t signalfd_mask;
static int signal_fd = 0;
#endif

#ifdef HAVE_KQUEUE
#include <sys/event.h>
static void swKqueueSignal_set(int signo, swSignalHandler handler);
#endif

typedef struct
{
    swSignalHandler handler;
    uint16_t signo;
    uint16_t active;
} swSignal;

static swSignal signals[SW_SIGNO_MAX];
static int _lock = 0;

static void swSignal_async_handler(int signo);

char* swSignal_str(int sig)
{
    static char buf[64];
    snprintf(buf, sizeof(buf), "%s", strsignal(sig));
    if (strchr(buf, ':') == 0)
    {
        size_t len = strlen(buf);
        snprintf(buf + len, sizeof(buf) - len, ": %d", sig);
    }
    return buf;
}

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
        swSysWarn("pthread_sigmask() failed");
    }
}

/**
 * setup signal
 */
swSignalHandler swSignal_set(int sig, swSignalHandler func, int restart, int mask)
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

void swSignal_add(int signo, swSignalHandler handler)
{
#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd)
    {
        swSignalfd_set(signo, handler);
    }
    else
#endif
    {
#ifdef HAVE_KQUEUE
        // SIGCHLD can not be monitored by kqueue, if blocked by SIG_IGN
        // see https://www.freebsd.org/cgi/man.cgi?kqueue
        // if there's no main reactor, signals cannot be monitored either
        if (signo != SIGCHLD && SwooleG.main_reactor)
        {
            swKqueueSignal_set(signo, handler);
        }
        else
#endif
        {
            signals[signo].handler = handler;
            signals[signo].active = 1;
            signals[signo].signo = signo;
            swSignal_set(signo, swSignal_async_handler, 1, 0);
        }
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
        swWarn("signal[%d] numberis invalid", signo);
        return;
    }
    swSignalHandler callback = signals[signo].handler;
    if (!callback)
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_UNREGISTERED_SIGNAL, SW_UNREGISTERED_SIGNAL_FMT, swSignal_str(signo));
        return;
    }
    callback(signo);
}

swSignalHandler swSignal_get_handler(int signo)
{
    if (signo >= SW_SIGNO_MAX)
    {
        swWarn("signal[%d] numberis invalid", signo);
        return NULL;
    }
    else
    {
        return signals[signo].handler;
    }
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
#ifdef HAVE_KQUEUE
                if (signals[i].signo != SIGCHLD && SwooleG.main_reactor)
                {
                    swKqueueSignal_set(signals[i].signo, NULL);
                }
                else
#endif
                {
                    swSignal_set(signals[i].signo, (swSignalHandler) -1, 1, 0);
                }
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

static void swSignalfd_set(int signo, swSignalHandler handler)
{
    if (handler == NULL && signals[signo].active)
    {
        sigdelset(&signalfd_mask, signo);
        bzero(&signals[signo], sizeof(swSignal));
    }
    else
    {
        sigaddset(&signalfd_mask, signo);
        signals[signo].handler = handler;
        signals[signo].signo = signo;
        signals[signo].active = 1;
    }
    if (signal_fd > 0)
    {
        sigprocmask(SIG_SETMASK, &signalfd_mask, NULL);
        signalfd(signal_fd, &signalfd_mask, SFD_NONBLOCK | SFD_CLOEXEC);
    }
}

int swSignalfd_setup(swReactor *reactor)
{
    if (signal_fd == 0)
    {
        signal_fd = signalfd(-1, &signalfd_mask, SFD_NONBLOCK | SFD_CLOEXEC);
        if (signal_fd < 0)
        {
            swSysWarn("signalfd() failed");
            return SW_ERR;
        }
        SwooleG.signal_fd = signal_fd;
        if (sigprocmask(SIG_BLOCK, &signalfd_mask, NULL) == -1)
        {
            swSysWarn("sigprocmask() failed");
            return SW_ERR;
        }
        swReactor_set_handler(reactor, SW_FD_SIGNAL, swSignalfd_onSignal);
        if (swoole_event_add(signal_fd, SW_EVENT_READ, SW_FD_SIGNAL) < 0)
        {
            return SW_ERR;
        }
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
            swSysWarn("sigprocmask(SIG_UNBLOCK) failed");
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
        swSysWarn("read from signalfd failed");
        return SW_OK;
    }
    if (siginfo.ssi_signo >=  SW_SIGNO_MAX)
    {
        swWarn("unknown signal[%d]", siginfo.ssi_signo);
        return SW_OK;
    }
    if (signals[siginfo.ssi_signo].active)
    {
        if (signals[siginfo.ssi_signo].handler)
        {
            signals[siginfo.ssi_signo].handler(siginfo.ssi_signo);
        }
        else
        {
            swoole_error_log(SW_LOG_WARNING, SW_ERROR_UNREGISTERED_SIGNAL, SW_UNREGISTERED_SIGNAL_FMT, swSignal_str(siginfo.ssi_signo));
        }
    }

    return SW_OK;
}
#endif

#ifdef HAVE_KQUEUE
static void swKqueueSignal_set(int signo, swSignalHandler handler)
{
    struct kevent ev;
    swReactor *reactor = SwooleG.main_reactor;
    struct
    {
        int fd;
    } *reactor_obj = reactor->object;
    // clear signal
    if (handler == NULL)
    {
        signal(signo, SIG_DFL);
        bzero(&signals[signo], sizeof(swSignal));
        EV_SET(&ev, signo, EVFILT_SIGNAL, EV_DELETE, 0, 0, NULL);
    }
    // add/update signal
    else
    {
        signal(signo, SIG_IGN);
        signals[signo].handler = handler;
        signals[signo].signo = signo;
        signals[signo].active = 1;
        // save swSignal* as udata
        EV_SET(&ev, signo, EVFILT_SIGNAL, EV_ADD, 0, 0, &signals[signo]);
    }
    int n = kevent(reactor_obj->fd, &ev, 1, NULL, 0, NULL);
    if (n < 0 && sw_unlikely(handler))
    {
        swSysWarn("kevent set signal[%d] error", signo);
    }
}

#endif
