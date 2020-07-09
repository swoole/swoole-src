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
#include "swoole_signal.h"

#include "coroutine.h"
#include "coroutine_system.h"

#ifdef HAVE_SIGNALFD
#include <sys/signalfd.h>
#endif
#ifdef HAVE_KQUEUE
#include <sys/event.h>
#endif

#ifdef HAVE_SIGNALFD
static void swSignalfd_set(int signo, swSignalHandler handler);
static void swSignalfd_clear();
static int swSignalfd_onSignal(swReactor *reactor, swEvent *event);

static sigset_t signalfd_mask;
static int signal_fd = 0;
static swSocket *signal_socket = nullptr;
#endif

#ifdef HAVE_KQUEUE
static void swKqueueSignal_set(int signo, swSignalHandler handler);
#endif

static void swSignal_async_handler(int signo);

static swSignal signals[SW_SIGNO_MAX];
static int _lock = 0;

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
    int ret = pthread_sigmask(SIG_BLOCK, &mask, nullptr);
    if (ret < 0)
    {
        swSysWarn("pthread_sigmask() failed");
    }
}

/**
 * setup signal
 */
swSignalHandler swSignal_set(int signo, swSignalHandler func, int restart, int mask)
{
    //ignore
    if (func == nullptr)
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
    if (sigaction(signo, &act, &oact) < 0)
    {
        return nullptr;
    }
    return oact.sa_handler;
}

void swSignal_set(int signo, swSignalHandler handler)
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
        if (signo != SIGCHLD && sw_reactor())
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
    if (sw_reactor())
    {
        sw_reactor()->singal_no = signo;
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
        return nullptr;
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
                if (signals[i].signo != SIGCHLD && sw_reactor())
                {
                    swKqueueSignal_set(signals[i].signo, nullptr);
                }
                else
#endif
                {
                    swSignal_set(signals[i].signo, (swSignalHandler) -1, 1, 0);
                }
            }
        }
    }
    sw_memset_zero(&signals, sizeof(signals));
}

#ifdef HAVE_SIGNALFD
void swSignalfd_init()
{
    sigemptyset(&signalfd_mask);
    sw_memset_zero(&signals, sizeof(signals));
}

static void swSignalfd_set(int signo, swSignalHandler handler)
{
    if (handler == nullptr && signals[signo].active)
    {
        sigdelset(&signalfd_mask, signo);
        sw_memset_zero(&signals[signo], sizeof(swSignal));
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
        sigprocmask(SIG_SETMASK, &signalfd_mask, nullptr);
        signalfd(signal_fd, &signalfd_mask, SFD_NONBLOCK | SFD_CLOEXEC);
    }
    else if (sw_reactor())
    {
        swSignalfd_setup(sw_reactor());
    }
}

int swSignalfd_setup(swReactor *reactor)
{
    if (signal_fd != 0)
    {
        return SW_OK;
    }

    signal_fd = signalfd(-1, &signalfd_mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (signal_fd < 0)
    {
        swSysWarn("signalfd() failed");
        return SW_ERR;
    }
    signal_socket = swSocket_new(signal_fd, SW_FD_SIGNAL);
    if (signal_socket == nullptr)
    {
        goto _error;
    }
    if (sigprocmask(SIG_BLOCK, &signalfd_mask, nullptr) == -1)
    {
        swSysWarn("sigprocmask() failed");
        goto _error;
    }
    swoole_event_set_handler(SW_FD_SIGNAL, swSignalfd_onSignal);
    if (swoole_event_add(signal_socket, SW_EVENT_READ) < 0)
    {
        goto _error;
    }
    reactor->set_exit_condition(SW_REACTOR_EXIT_CONDITION_SIGNALFD, [](swReactor *reactor, int &event_num) -> bool
    {
        event_num--;
        return true;
    });

    SwooleG.signal_fd = signal_fd;

    return SW_OK;

    _error:
    signal_socket->fd = -1;
    swSocket_free(signal_socket);
    close(signal_fd);
    signal_fd = 0;

    return SW_ERR;
}

static void swSignalfd_clear()
{
    if (signal_fd)
    {
        if (sigprocmask(SIG_UNBLOCK, &signalfd_mask, nullptr) < 0)
        {
            swSysWarn("sigprocmask(SIG_UNBLOCK) failed");
        }
        if (signal_socket)
        {
            swSocket_free(signal_socket);
            signal_socket = nullptr;
        }
        sw_memset_zero(&signalfd_mask, sizeof(signalfd_mask));
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
    swReactor *reactor = sw_reactor();
    struct reactor_object
    {
        int fd;
    };
    struct reactor_object *reactor_obj = (struct reactor_object *) reactor->object;
    // clear signal
    if (handler == nullptr)
    {
        signal(signo, SIG_DFL);
        sw_memset_zero(&signals[signo], sizeof(swSignal));
        EV_SET(&ev, signo, EVFILT_SIGNAL, EV_DELETE, 0, 0, nullptr);
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
    int n = kevent(reactor_obj->fd, &ev, 1, nullptr, 0, nullptr);
    if (n < 0 && sw_unlikely(handler))
    {
        swSysWarn("kevent set signal[%d] error", signo);
    }
}
#endif

namespace swoole { namespace coroutine {

bool System::wait_signal(int signo, double timeout)
{
    static Coroutine* listeners[SW_SIGNO_MAX];
    Coroutine *co = Coroutine::get_current_safe();

    if (SwooleTG.signal_listener_num > 0)
    {
        errno = EBUSY;
        return false;
    }
    if (signo < 0 || signo >= SW_SIGNO_MAX || signo == SIGCHLD)
    {
        errno = EINVAL;
        return false;
    }

    /* resgiter signal */
    listeners[signo] = co;
    // for swSignalfd_setup
    sw_reactor()->check_signalfd = 1;
    // exit condition
    if (!sw_reactor()->isset_exit_condition(SW_REACTOR_EXIT_CONDITION_CO_SIGNAL_LISTENER))
    {
        sw_reactor()->set_exit_condition(SW_REACTOR_EXIT_CONDITION_CO_SIGNAL_LISTENER,
                [](swReactor *reactor, int &event_num) -> bool
                {
                    return SwooleTG.co_signal_listener_num == 0;
                });
    }
    /* always enable signalfd */
    SwooleG.use_signalfd = SwooleG.enable_signalfd = 1;
    swSignal_set(signo, [](int signo) {
        Coroutine *co = listeners[signo];
        if (co)
        {
            listeners[signo] = nullptr;
            co->resume();
        }
    });
    SwooleTG.co_signal_listener_num++;

    swTimer_node* timer = nullptr;
    if (timeout > 0)
    {
        timer = swoole_timer_add(timeout * 1000, 0, [](swTimer *timer, swTimer_node *tnode) {
            Coroutine *co = (Coroutine *) tnode->data;
            co->resume();
        }, co);
    }

    co->yield();

    swSignal_set(signo, nullptr);
    SwooleTG.co_signal_listener_num--;

    if (listeners[signo] != nullptr)
    {
        listeners[signo] = nullptr;
        errno = ETIMEDOUT;
        return false;
    }

    if (timer)
    {
        swoole_timer_del(timer);
    }

    return true;
}

}}
