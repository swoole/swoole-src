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

#include "php_swoole.h"

#ifdef HAVE_PTRACE
#include <stddef.h>
#include <sys/ptrace.h>

#if SIZEOF_LONG == 4
#define PTR_FMT "08"
#elif SIZEOF_LONG == 8
#define PTR_FMT "016"
#endif

#if defined(PT_ATTACH) && !defined(PTRACE_ATTACH)
#if __APPLE__
#define PTRACE_ATTACH PT_ATTACHEXC
#else
#define PTRACE_ATTACH PT_ATTACH
#endif
#endif

#if defined(PT_DETACH) && !defined(PTRACE_DETACH)
#define PTRACE_DETACH PT_DETACH
#endif

#if defined(PT_READ_D) && !defined(PTRACE_PEEKDATA)
#define PTRACE_PEEKDATA PT_READ_D
#endif

#define valid_ptr(p) ((p) && 0 == ((p) & (sizeof(long) - 1)))

static void trace_request(swWorker *worker);
static int trace_dump(swWorker *worker, FILE *slowlog);
static int trace_get_long(pid_t traced_pid, long addr, long *data);
static int trace_get_strz(pid_t traced_pid, char *buf, size_t sz, long addr);

static void trace_request(swWorker *worker)
{
    FILE *slowlog = SwooleG.serv->request_slowlog_file;
    pid_t traced_pid = worker->pid;
    int ret = trace_dump(worker, slowlog);
    if (ret < 0)
    {
        swSysError("failed to trace worker %d, error lint =%d.", worker->pid, -ret);
    }
    if (0 > ptrace(PTRACE_DETACH, traced_pid, (void *) 1, 0))
    {
        swSysError("failed to ptrace(DETACH) worker %d", worker->pid);
    }
    fflush(slowlog);
}

void php_swoole_trace_check(swServer *serv)
{
    uint8_t timeout = serv->request_slowlog_timeout;
    int count = serv->worker_num + SwooleG.task_worker_num;
    int i = serv->trace_event_worker ? 0 : serv->worker_num;
    swWorker *worker;

    for (; i < count; i++)
    {
        worker = swServer_get_worker(serv, i);
        swTraceLog(SW_TRACE_SERVER, "trace request, worker#%d, pid=%d. request_time=%d.", i, worker->pid, worker->request_time);
        if (!(worker->request_time > 0 && worker->traced == 0 && SwooleGS->now - worker->request_time >= timeout))
        {
            continue;
        }
        if (ptrace(PTRACE_ATTACH, worker->pid, 0, 0) < 0)
        {
            swSysError("failed to ptrace(ATTACH, %d) worker#%d,", worker->pid, worker->id);
            continue;
        }
        worker->tracer = trace_request;
        worker->traced = 1;
    }
}

static int trace_get_long(pid_t traced_pid, long addr, long *data)
{
    errno = 0;
    *data = ptrace(PTRACE_PEEKDATA, traced_pid, (void *) addr, 0);
    if (*data < 0)
    {
        return -1;
    }
    return 0;
}

static int trace_get_strz(pid_t traced_pid, char *buf, size_t sz, long addr)
{
    int i;
    long l = addr;
    char *lc = (char *) &l;

    i = l % SIZEOF_LONG;
    l -= i;
    for (addr = l;; addr += SIZEOF_LONG)
    {
        if (0 > trace_get_long(traced_pid, addr, &l))
        {
            return -1;
        }
        for (; i < SIZEOF_LONG; i++)
        {
            --sz;
            if (sz && lc[i])
            {
                *buf++ = lc[i];
                continue;
            }
            *buf = '\0';
            return 0;
        }
        i = 0;
    }
    return 0;
}

size_t trace_print_time(struct timeval *tv, char *timebuf, size_t timebuf_len)
{
    struct tm t;
    size_t len;

    len = strftime(timebuf, timebuf_len, "[%d-%b-%Y %H:%M:%S", localtime_r((const time_t *) &tv->tv_sec, &t));
    len += snprintf(timebuf + len, timebuf_len - len, "] ");
    return len;
}

static int trace_dump(swWorker *worker, FILE *slowlog)
{
    SWOOLE_GET_TSRMLS;

    pid_t traced_pid = worker->pid;
    int callers_limit = 100;
    struct timeval tv;
    static const int buf_size = 1024;
    char buf[buf_size];
    long execute_data;
    long l;

    gettimeofday(&tv, 0);

    trace_print_time(&tv, buf, buf_size);

    fprintf(slowlog, "\n%s [worker#%d] pid %d\n", buf, worker->id, (int) traced_pid);

    if (0 > trace_get_long(traced_pid, (long) &EG(current_execute_data), &l))
    {
        return -__LINE__;
    }

    execute_data = l;

#if PHP_VERSION_ID > 70100
    while (execute_data)
    {
        long function;
        long function_name;
        long file_name;
        long prev;
        uint32_t lineno = 0;

        if (0 > trace_get_long(traced_pid, execute_data + offsetof(zend_execute_data, func), &l))
        {
            return -__LINE__;
        }

        function = l;

        if (valid_ptr(function))
        {
            if (0 > trace_get_long(traced_pid, function + offsetof(zend_function, common.function_name), &l))
            {
                return -1;
            }

            function_name = l;

            if (function_name == 0)
            {
                uint32_t *call_info = (uint32_t *) &l;
                if (0 > trace_get_long(traced_pid, execute_data + offsetof(zend_execute_data, This.u1.type_info), &l))
                {
                    return -__LINE__;
                }

                if (ZEND_CALL_KIND_EX((*call_info) >> ZEND_CALL_INFO_SHIFT) == ZEND_CALL_TOP_CODE)
                {
                    return 0;
                }
                else if (ZEND_CALL_KIND_EX(*(call_info) >> ZEND_CALL_INFO_SHIFT) == ZEND_CALL_NESTED_CODE)
                {
                    memcpy(buf, "[INCLUDE_OR_EVAL]", sizeof("[INCLUDE_OR_EVAL]"));
                }
                else
                {
                    ZEND_ASSERT(0);
                }
            }
            else
            {
                if (0 > trace_get_strz(traced_pid, buf, buf_size, function_name + offsetof(zend_string, val)))
                {
                    return -__LINE__;
                }

            }
        }
        else
        {
            memcpy(buf, "???", sizeof("???"));
        }

        fprintf(slowlog, "[0x%" PTR_FMT "lx] ", execute_data);
        fprintf(slowlog, "%s()", buf);

        *buf = '\0';

        if (0 > trace_get_long(traced_pid, execute_data + offsetof(zend_execute_data, prev_execute_data), &l))
        {
            return -__LINE__;
        }

        execute_data = prev = l;

        while (prev)
        {
            zend_uchar *type;

            if (0 > trace_get_long(traced_pid, prev + offsetof(zend_execute_data, func), &l))
            {
                return -__LINE__;
            }

            function = l;

            if (!valid_ptr(function))
            {
                break;
            }

            type = (zend_uchar *) &l;
            if (0 > trace_get_long(traced_pid, function + offsetof(zend_function, type), &l))
            {
                return -__LINE__;
            }

            if (ZEND_USER_CODE(*type))
            {
                if (0 > trace_get_long(traced_pid, function + offsetof(zend_op_array, filename), &l))
                {
                    return -__LINE__;
                }

                file_name = l;

                if (0 > trace_get_strz(traced_pid, buf, buf_size, file_name + offsetof(zend_string, val)))
                {
                    return -__LINE__;
                }

                if (0 > trace_get_long(traced_pid, prev + offsetof(zend_execute_data, opline), &l))
                {
                    return -__LINE__;
                }

                if (valid_ptr(l))
                {
                    long opline = l;
                    uint32_t *lu = (uint32_t *) &l;

                    if (0 > trace_get_long(traced_pid, opline + offsetof(struct _zend_op, lineno), &l))
                    {
                        return -__LINE__;
                    }

                    lineno = *lu;
                }
                break;
            }

            if (0 > trace_get_long(traced_pid, prev + offsetof(zend_execute_data, prev_execute_data), &l))
            {
                return -__LINE__;
            }

            prev = l;
        }

        fprintf(slowlog, " %s:%u\n", *buf ? buf : "unknown", lineno);

        if (0 == --callers_limit)
        {
            break;
        }
    }
#elif PHP_VERSION_ID > 70000
    while (execute_data)
    {
        long function;
        long function_name;
        long file_name;
        long prev;
        uint lineno = 0;

        if (0 > trace_get_long(traced_pid, execute_data + offsetof(zend_execute_data, func), &l))
        {
            return -1;
        }

        function = l;

        if (valid_ptr(function))
        {
            if (0 > trace_get_long(traced_pid, function + offsetof(zend_function, common.function_name), &l))
            {
                return -1;
            }

            function_name = l;

            if (function_name == 0)
            {
                uint32_t *call_info = (uint32_t *)&l;
                if (0 > trace_get_long(traced_pid, execute_data + offsetof(zend_execute_data, This.u1.type_info), &l))
                {
                    return -1;
                }

                if (ZEND_CALL_KIND_EX((*call_info) >> 24) == ZEND_CALL_TOP_CODE)
                {
                    return 0;
                }
                else if (ZEND_CALL_KIND_EX(*(call_info) >> 24) == ZEND_CALL_NESTED_CODE)
                {
                    memcpy(buf, "[INCLUDE_OR_EVAL]", sizeof("[INCLUDE_OR_EVAL]"));
                }
                else
                {
                    ZEND_ASSERT(0);
                }
            }
            else
            {
                if (0 > trace_get_strz(traced_pid, buf, buf_size, function_name + offsetof(zend_string, val)))
                {
                    return -1;
                }

            }
        }
        else
        {
            memcpy(buf, "???", sizeof("???"));
        }

        fprintf(slowlog, "[0x%" PTR_FMT "lx] ", execute_data);

        fprintf(slowlog, "%s()", buf);

        *buf = '\0';

        if (0 > trace_get_long(traced_pid, execute_data + offsetof(zend_execute_data, prev_execute_data), &l))
        {
            return -1;
        }

        execute_data = prev = l;

        while (prev)
        {
            zend_uchar *type;

            if (0 > trace_get_long(traced_pid, prev + offsetof(zend_execute_data, func), &l))
            {
                return -1;
            }

            function = l;

            if (!valid_ptr(function))
            {
                break;
            }

            type = (zend_uchar *)&l;
            if (0 > trace_get_long(traced_pid, function + offsetof(zend_function, type), &l))
            {
                return -1;
            }

            if (ZEND_USER_CODE(*type))
            {
                if (0 > trace_get_long(traced_pid, function + offsetof(zend_op_array, filename), &l))
                {
                    return -1;
                }

                file_name = l;

                if (0 > trace_get_strz(traced_pid, buf, buf_size, file_name + offsetof(zend_string, val)))
                {
                    return -1;
                }

                if (0 > trace_get_long(traced_pid, prev + offsetof(zend_execute_data, opline), &l))
                {
                    return -1;
                }

                if (valid_ptr(l))
                {
                    long opline = l;
                    uint32_t *lu = (uint32_t *) &l;

                    if (0 > trace_get_long(traced_pid, opline + offsetof(struct _zend_op, lineno), &l))
                    {
                        return -1;
                    }

                    lineno = *lu;
                }
                break;
            }

            if (0 > trace_get_long(traced_pid, prev + offsetof(zend_execute_data, prev_execute_data), &l))
            {
                return -1;
            }

            prev = l;
        }

        fprintf(slowlog, " %s:%u\n", *buf ? buf : "unknown", lineno);

        if (0 == --callers_limit)
        {
            break;
        }
    }
#else
    while (execute_data)
    {
        long function;
        uint lineno = 0;

        fprintf(slowlog, "[0x%" PTR_FMT "lx] ", execute_data);

        if (0 > trace_get_long(traced_pid, execute_data + offsetof(zend_execute_data, function_state.function), &l))
        {
            return -1;
        }

        function = l;

        if (valid_ptr(function))
        {
            if (0 > trace_get_strz(traced_pid, buf, buf_size, function + offsetof(zend_function, common.function_name)))
            {
                return -1;
            }

            fprintf(slowlog, "%s()", buf);
        }
        else
        {
            fprintf(slowlog, "???");
        }

        if (0 > trace_get_long(traced_pid, execute_data + offsetof(zend_execute_data, op_array), &l))
        {
            return -1;
        }

        *buf = '\0';

        if (valid_ptr(l))
        {
            long op_array = l;

            if (0 > trace_get_strz(traced_pid, buf, buf_size, op_array + offsetof(zend_op_array, filename)))
            {
                return -1;
            }
        }

        if (0 > trace_get_long(traced_pid, execute_data + offsetof(zend_execute_data, opline), &l))
        {
            return -1;
        }

        if (valid_ptr(l))
        {
            long opline = l;
            uint *lu = (uint *) &l;

            if (0 > trace_get_long(traced_pid, opline + offsetof(struct _zend_op, lineno), &l))
            {
                return -1;
            }

            lineno = *lu;
        }

        fprintf(slowlog, " %s:%u\n", *buf ? buf : "unknown", lineno);

        if (0 > trace_get_long(traced_pid, execute_data + offsetof(zend_execute_data, prev_execute_data), &l))
        {
            return -1;
        }

        execute_data = l;

        if (0 == --callers_limit)
        {
            break;
        }
    }
#endif

    return 0;
}
#endif
