dnl config.m4 for extension swoole

dnl  +----------------------------------------------------------------------+
dnl  | Swoole                                                               |
dnl  +----------------------------------------------------------------------+
dnl  | This source file is subject to version 2.0 of the Apache license,    |
dnl  | that is bundled with this package in the file LICENSE, and is        |
dnl  | available through the world-wide-web at the following url:           |
dnl  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
dnl  | If you did not receive a copy of the Apache2.0 license and are unable|

dnl  | to obtain it through the world-wide-web, please send a note to       |
dnl  | license@swoole.com so we can mail you a copy immediately.            |
dnl  +----------------------------------------------------------------------+
dnl  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
dnl  +----------------------------------------------------------------------+

PHP_ARG_ENABLE(swoole-debug, whether to enable swoole debug,
[  --enable-swoole-debug   Enable swoole debug], no, no)

PHP_ARG_ENABLE(trace-log, Whether to enable trace log,
[  --enable-trace-log   Enable swoole trace log], no, no)

PHP_ARG_ENABLE(sockets, enable sockets support,
[  --enable-sockets        Do you have sockets extension?], no, no)

PHP_ARG_ENABLE(async_redis, enable async_redis support,
[  --enable-async-redis    Do you have hiredis?], no, no)

PHP_ARG_ENABLE(coroutine-postgresql, enable coroutine postgresql support,
[  --enable-coroutine-postgresql    Do you install postgresql?], no, no)

PHP_ARG_ENABLE(openssl, enable openssl support,
[  --enable-openssl        Use openssl?], no, no)

PHP_ARG_ENABLE(http2, enable http2.0 support,
[  --enable-http2          Use http2.0?], no, no)

PHP_ARG_ENABLE(thread, enable thread support,
[  --enable-thread         Experimental: Use thread?], no, no)

PHP_ARG_ENABLE(hugepage, enable hugepage support,
[  --enable-hugepage       Experimental: Use hugepage?], no, no)

PHP_ARG_ENABLE(swoole, swoole support,
[  --enable-swoole         Enable swoole support], [enable_swoole="yes"])

PHP_ARG_ENABLE(swoole_static, swoole static compile support,
[  --enable-swoole-static    Enable swoole static compile support], no, no)

PHP_ARG_WITH(swoole, swoole support,
[  --with-swoole           With swoole support])

PHP_ARG_WITH(libpq_dir, for libpq support,
[  --with-libpq-dir[=DIR]    Include libpq support (requires libpq >= 9.5)], no, no)

PHP_ARG_WITH(openssl_dir, for OpenSSL support,
[  --with-openssl-dir[=DIR]    Include OpenSSL support (requires OpenSSL >= 0.9.6)], no, no)

PHP_ARG_WITH(jemalloc_dir, for jemalloc support,
[  --with-jemalloc-dir[=DIR]    Include jemalloc support], no, no)

PHP_ARG_ENABLE(mysqlnd, enable mysqlnd support,
[  --enable-mysqlnd       Do you have mysqlnd?], no, no)

PHP_ARG_ENABLE(coroutine, whether to enable coroutine,
[  --enable-coroutine      Enable coroutine (requires PHP >= 5.5)], yes, no)

PHP_ARG_ENABLE(asan, whether to enable asan,
[  --enable-asan      Enable asan], no, no)

PHP_ARG_ENABLE(picohttpparser, enable picohttpparser support,
[  --enable-picohttpparser     Experimental: Do you have picohttpparser?], no, no)

PHP_ARG_WITH(swoole, swoole support,
[  --with-swoole           With swoole support])

PHP_ARG_ENABLE(timewheel, enable timewheel support,
[  --enable-timewheel     Experimental: Enable timewheel heartbeat?], no, no)

AC_DEFUN([SWOOLE_HAVE_PHP_EXT], [
    extname=$1
    haveext=$[PHP_]translit($1,a-z_-,A-Z__)

    AC_MSG_CHECKING([for ext/$extname support])
    if test -x "$PHP_EXECUTABLE"; then
        grepext=`$PHP_EXECUTABLE -m | $EGREP ^$extname\$`
        if test "$grepext" = "$extname"; then
            [PHP_HTTP_HAVE_EXT_]translit($1,a-z_-,A-Z__)=1
            AC_MSG_RESULT([yes])
            $2
        else
            [PHP_HTTP_HAVE_EXT_]translit($1,a-z_-,A-Z__)=
            AC_MSG_RESULT([no])
            $3
        fi
    elif test "$haveext" != "no" && test "x$haveext" != "x"; then
        [PHP_HTTP_HAVE_EXT_]translit($1,a-z_-,A-Z__)=1
        AC_MSG_RESULT([yes])
        $2
    else
        [PHP_HTTP_HAVE_EXT_]translit($1,a-z_-,A-Z__)=
        AC_MSG_RESULT([no])
        $3
    fi
])

AC_DEFUN([AC_SWOOLE_CPU_AFFINITY],
[
    AC_MSG_CHECKING([for cpu affinity])
    AC_TRY_COMPILE(
    [
        #ifdef __FreeBSD__
        #include <sys/types.h>
        #include <sys/cpuset.h>
        typedef cpuset_t cpu_set_t;
        #else
        #include <sched.h>
        #endif
    ], [
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);
    ], [
        AC_DEFINE([HAVE_CPU_AFFINITY], 1, [cpu affinity?])
        AC_MSG_RESULT([yes])
    ], [
        AC_MSG_RESULT([no])
    ])
])

AC_DEFUN([AC_SWOOLE_HAVE_REUSEPORT],
[
    AC_MSG_CHECKING([for socket REUSEPORT])
    AC_TRY_COMPILE(
    [
        #include <sys/socket.h>
    ], [
        int val = 1;
        setsockopt(0, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
    ], [
        AC_DEFINE([HAVE_REUSEPORT], 1, [have SO_REUSEPORT?])
        AC_MSG_RESULT([yes])
    ], [
        AC_MSG_RESULT([no])
    ])
])

AC_DEFUN([AC_SWOOLE_HAVE_FUTEX],
[
    AC_MSG_CHECKING([for futex])
    AC_TRY_COMPILE(
    [
		#include <linux/futex.h>
		#include <syscall.h>
		#include <unistd.h>
    ], [
        int futex_addr;
		int val1;
	    syscall(SYS_futex, &futex_addr, val1, NULL, NULL, 0);
    ], [
        AC_DEFINE([HAVE_FUTEX], 1, [have FUTEX?])
        AC_MSG_RESULT([yes])
    ], [
        AC_MSG_RESULT([no])
    ])
])

AC_DEFUN([AC_SWOOLE_HAVE_LINUX_AIO],
[
    AC_MSG_CHECKING([for linux aio])
    AC_TRY_COMPILE(
    [
		#include <sys/syscall.h>
        #include <linux/aio_abi.h>
		#include <unistd.h>
    ], [
        struct iocb *iocbps[1];
        struct iocb iocbp;
        aio_context_t context;
        iocbps[0] = &iocbp;
        io_submit(context, 1, iocbps);
    ], [
        AC_DEFINE([HAVE_LINUX_AIO], 1, [have LINUX_AIO?])
        AC_MSG_RESULT([yes])
    ], [
        AC_MSG_RESULT([no])
    ])
])

AC_MSG_CHECKING([if compiling with clang])
AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([], [[
        #ifndef __clang__
            not clang
        #endif
    ]])],
    [CLANG=yes], [CLANG=no]
)
AC_MSG_RESULT([$CLANG])

if test "$CLANG" = "yes"; then
    CFLAGS="$CFLAGS -std=gnu89"
fi

if test "$PHP_SWOOLE" != "no"; then

    PHP_ADD_LIBRARY(pthread)
    PHP_SUBST(SWOOLE_SHARED_LIBADD)

    AC_ARG_ENABLE(debug,
        [--enable-debug,  compile with debug symbols],
        [PHP_DEBUG=$enableval],
        [PHP_DEBUG=0]
    )

    if test "$PHP_SWOOLE_DEBUG" != "no"; then
        AC_DEFINE(SW_DEBUG, 1, [do we enable swoole debug])
        PHP_DEBUG=1
    fi

    if test "$PHP_ASAN" != "no"; then
        PHP_DEBUG=1
        CFLAGS="$CFLAGS -fsanitize=address -fno-omit-frame-pointer"
    fi

    if test "$PHP_COROUTINE" != "no"; then
        AC_DEFINE(SW_COROUTINE, 1, [enable ability of coroutine])
    fi

    if test "$PHP_TRACE_LOG" != "no"; then
        AC_DEFINE(SW_LOG_TRACE_OPEN, 1, [enable trace log])
    fi

    if test "$PHP_SOCKETS" = "yes"; then
        AC_DEFINE(SW_SOCKETS, 1, [enable sockets support])
    fi

    if test "$PHP_HTTP2" = "yes"; then
        AC_DEFINE(SW_USE_HTTP2, 1, [enable http2.0 support])
    fi

    if test "$PHP_HUGEPAGE" = "yes"; then
        AC_DEFINE(SW_USE_HUGEPAGE, 1, [enable hugepage support])
    fi

    if test "$PHP_THREAD" = "yes"; then
        AC_DEFINE(SW_USE_THREAD, 1, [enable thread support])
    fi

    if test "$PHP_TIMEWHEEL" = "yes"; then
        AC_DEFINE(SW_USE_TIMEWHEEL, 1, [enable timewheel support])
    fi

    AC_SWOOLE_CPU_AFFINITY
    AC_SWOOLE_HAVE_REUSEPORT
	AC_SWOOLE_HAVE_FUTEX
    AC_SWOOLE_HAVE_LINUX_AIO

    CFLAGS="-Wall -pthread $CFLAGS"
    LDFLAGS="$LDFLAGS -lpthread"

    if test `uname` = "Darwin"; then
        AC_CHECK_LIB(c, clock_gettime, AC_DEFINE(HAVE_CLOCK_GETTIME, 1, [have clock_gettime]))
    else
        AC_CHECK_LIB(rt, clock_gettime, AC_DEFINE(HAVE_CLOCK_GETTIME, 1, [have clock_gettime]))
        PHP_ADD_LIBRARY(rt, 1, SWOOLE_SHARED_LIBADD)
    fi

    if test "$PHP_OPENSSL" != "no" || test "$PHP_OPENSSL_DIR" != "no"; then
        if test "$PHP_OPENSSL_DIR" != "no"; then
            AC_DEFINE(HAVE_OPENSSL, 1, [have openssl])
            PHP_ADD_INCLUDE("${PHP_OPENSSL_DIR}/include")
            PHP_ADD_LIBRARY_WITH_PATH(ssl, "${PHP_OPENSSL_DIR}/${PHP_LIBDIR}")
        else
            AC_CHECK_LIB(ssl, SSL_connect, AC_DEFINE(HAVE_OPENSSL, 1, [have openssl]))
        fi

        AC_DEFINE(SW_USE_OPENSSL, 1, [enable openssl support])
        PHP_ADD_LIBRARY(ssl, 1, SWOOLE_SHARED_LIBADD)
        PHP_ADD_LIBRARY(crypto, 1, SWOOLE_SHARED_LIBADD)
    fi

    if test "$PHP_JEMALLOC_DIR" != "no"; then
        AC_DEFINE(SW_USE_JEMALLOC, 1, [use jemalloc])
        PHP_ADD_INCLUDE("${PHP_JEMALLOC_DIR}/include")
        PHP_ADD_LIBRARY_WITH_PATH(jemalloc, "${PHP_JEMALLOC_DIR}/${PHP_LIBDIR}")
        PHP_ADD_LIBRARY(jemalloc, 1, SWOOLE_SHARED_LIBADD)
    fi

    PHP_ADD_LIBRARY(pthread, 1, SWOOLE_SHARED_LIBADD)

    if test "$PHP_ASYNC_REDIS" = "yes"; then
        AC_DEFINE(SW_USE_REDIS, 1, [enable async-redis support])
        PHP_ADD_LIBRARY(hiredis, 1, SWOOLE_SHARED_LIBADD)
    fi

    if test "$PHP_COROUTINE_POSTGRESQL" = "yes"; then
        if test "$PHP_LIBPQ" != "no" || test "$PHP_LIBPQ_DIR" != "no"; then
            if test "$PHP_LIBPQ_DIR" != "no"; then
                AC_DEFINE(HAVE_LIBPQ, 1, [have libpq])
                AC_MSG_RESULT(libpq include success)
                PHP_ADD_INCLUDE("${PHP_LIBPQ_DIR}/include")
            else
                PGSQL_SEARCH_PATHS="/usr /usr/local /usr/local/pgsql"
                for i in $PGSQL_SEARCH_PATHS; do
                    for j in include include/pgsql include/postgres include/postgresql ""; do
                        if test -r "$i/$j/libpq-fe.h"; then
                            PGSQL_INC_BASE=$i
                            PGSQL_INCLUDE=$i/$j
                            AC_MSG_RESULT(libpq-fe.h found in PGSQL_INCLUDE)
                            PHP_ADD_INCLUDE("${PGSQL_INCLUDE}")
                        fi
                    done
                done
            fi
            AC_DEFINE(SW_USE_POSTGRESQL, 1, [enable coroutine-postgresql support])
            PHP_ADD_LIBRARY(pq, 1, SWOOLE_SHARED_LIBADD)
        fi
        if test -z "$PGSQL_INCLUDE"; then
           AC_MSG_ERROR(Cannot find libpq-fe.h. Please confirm the libpq or specify correct PostgreSQL(libpq) installation path)
        fi
    fi

    if test "$PHP_HTTP2" = "yes"; then
        PHP_ADD_LIBRARY(nghttp2, 1, SWOOLE_SHARED_LIBADD)
    fi

    if test "$PHP_MYSQLND" = "yes"; then
        PHP_ADD_EXTENSION_DEP(mysqli, mysqlnd)
        AC_DEFINE(SW_USE_MYSQLND, 1, [use mysqlnd])
    fi

    AC_CHECK_LIB(c, accept4, AC_DEFINE(HAVE_ACCEPT4, 1, [have accept4]))
    AC_CHECK_LIB(c, signalfd, AC_DEFINE(HAVE_SIGNALFD, 1, [have signalfd]))
    AC_CHECK_LIB(c, timerfd_create, AC_DEFINE(HAVE_TIMERFD, 1, [have timerfd]))
    AC_CHECK_LIB(c, eventfd, AC_DEFINE(HAVE_EVENTFD, 1, [have eventfd]))
    AC_CHECK_LIB(c, epoll_create, AC_DEFINE(HAVE_EPOLL, 1, [have epoll]))
    AC_CHECK_LIB(c, poll, AC_DEFINE(HAVE_POLL, 1, [have poll]))
    AC_CHECK_LIB(c, sendfile, AC_DEFINE(HAVE_SENDFILE, 1, [have sendfile]))
    AC_CHECK_LIB(c, kqueue, AC_DEFINE(HAVE_KQUEUE, 1, [have kqueue]))
    AC_CHECK_LIB(c, backtrace, AC_DEFINE(HAVE_EXECINFO, 1, [have execinfo]))
    AC_CHECK_LIB(c, daemon, AC_DEFINE(HAVE_DAEMON, 1, [have daemon]))
    AC_CHECK_LIB(c, mkostemp, AC_DEFINE(HAVE_MKOSTEMP, 1, [have mkostemp]))
    AC_CHECK_LIB(c, inotify_init, AC_DEFINE(HAVE_INOTIFY, 1, [have inotify]))
    AC_CHECK_LIB(c, malloc_trim, AC_DEFINE(HAVE_MALLOC_TRIM, 1, [have malloc_trim]))
    AC_CHECK_LIB(c, inotify_init1, AC_DEFINE(HAVE_INOTIFY_INIT1, 1, [have inotify_init1]))
    AC_CHECK_LIB(c, gethostbyname2_r, AC_DEFINE(HAVE_GETHOSTBYNAME2_R, 1, [have gethostbyname2_r]))
    AC_CHECK_LIB(c, ptrace, AC_DEFINE(HAVE_PTRACE, 1, [have ptrace]))
    AC_CHECK_LIB(pthread, pthread_rwlock_init, AC_DEFINE(HAVE_RWLOCK, 1, [have pthread_rwlock_init]))
    AC_CHECK_LIB(pthread, pthread_spin_lock, AC_DEFINE(HAVE_SPINLOCK, 1, [have pthread_spin_lock]))
    AC_CHECK_LIB(pthread, pthread_mutex_timedlock, AC_DEFINE(HAVE_MUTEX_TIMEDLOCK, 1, [have pthread_mutex_timedlock]))
    AC_CHECK_LIB(pthread, pthread_barrier_init, AC_DEFINE(HAVE_PTHREAD_BARRIER, 1, [have pthread_barrier_init]))
    AC_CHECK_LIB(pcre, pcre_compile, AC_DEFINE(HAVE_PCRE, 1, [have pcre]))
    AC_CHECK_LIB(hiredis, redisConnect, AC_DEFINE(HAVE_HIREDIS, 1, [have hiredis]))
    AC_CHECK_LIB(pq, PQconnectdb, AC_DEFINE(HAVE_POSTGRESQL, 1, [have postgresql]))
    AC_CHECK_LIB(nghttp2, nghttp2_hd_inflate_new, AC_DEFINE(HAVE_NGHTTP2, 1, [have nghttp2]))

    AC_CHECK_LIB(z, gzgets, [
        AC_DEFINE(SW_HAVE_ZLIB, 1, [have zlib])
        PHP_ADD_LIBRARY(z, 1, SWOOLE_SHARED_LIBADD)
    ])

    swoole_source_file="swoole.c \
        swoole_server.c \
        swoole_server_port.c \
        swoole_atomic.c \
        swoole_lock.c \
        swoole_client.c \
        swoole_client_coro.c \
        swoole_coroutine.c \
        swoole_coroutine_util.c \
        swoole_event.c \
        swoole_timer.c \
        swoole_async.c \
        swoole_process.c \
        swoole_process_pool.c \
        swoole_serialize.c \
        swoole_buffer.c \
        swoole_table.c \
        swoole_http_server.c \
        swoole_http_v2_server.c \
        swoole_http_v2_client.c \
        swoole_http_v2_client_coro.c \
        swoole_websocket_server.c \
        swoole_http_client.c \
        swoole_http_client_coro.c \
        swoole_mysql.c \
        swoole_mysql_coro.c \
        swoole_postgresql_coro.c \
        swoole_redis.c \
        swoole_redis_coro.c \
        swoole_redis_server.c \
        swoole_mmap.c \
        swoole_channel.c \
        swoole_channel_coro.c \
        swoole_ringqueue.c \
        swoole_msgqueue.c \
        swoole_trace.c \
        src/core/base.c \
        src/core/log.c \
        src/core/hashmap.c \
        src/core/RingQueue.c \
        src/core/Channel.c \
        src/core/string.c \
        src/core/array.c \
        src/core/socket.c \
        src/core/list.c \
        src/core/heap.c \
        src/memory/ShareMemory.c \
        src/memory/MemoryGlobal.c \
        src/memory/RingBuffer.c \
        src/memory/FixedPool.c \
        src/memory/Malloc.c \
        src/memory/Table.c \
        src/memory/Buffer.c \
        src/factory/Factory.c \
        src/factory/FactoryThread.c \
        src/factory/FactoryProcess.c \
        src/reactor/ReactorBase.c \
        src/reactor/ReactorSelect.c \
        src/reactor/ReactorPoll.c \
        src/reactor/ReactorEpoll.c \
        src/reactor/ReactorKqueue.c \
        src/pipe/PipeBase.c \
        src/pipe/PipeEventfd.c \
        src/pipe/PipeUnsock.c \
        src/lock/Semaphore.c \
        src/lock/Mutex.c \
        src/lock/RWLock.c \
        src/lock/SpinLock.c \
        src/lock/FileLock.c \
        src/lock/Cond.c \
        src/network/Server.c \
        src/network/TaskWorker.c \
        src/network/Client.c \
        src/network/Connection.c \
        src/network/ProcessPool.c \
        src/network/ThreadPool.c \
        src/network/ReactorThread.c \
        src/network/ReactorProcess.c \
        src/network/Manager.c \
        src/network/Worker.c \
        src/network/Timer.c \
        src/network/Port.c \
        src/network/DNS.c \
        src/network/TimeWheel.c \
        src/network/Stream.c \
        src/os/base.c \
        src/os/linux_aio.c \
        src/os/msg_queue.c \
        src/os/sendfile.c \
        src/os/signal.c \
        src/os/timer.c \
        src/protocol/Base.c \
        src/protocol/SSL.c \
        src/protocol/Http.c \
        src/protocol/Http2.c \
        src/protocol/WebSocket.c \
        src/protocol/Mqtt.c \
        src/protocol/Socks5.c \
        src/protocol/MimeTypes.c \
        src/protocol/Redis.c \
        src/protocol/Base64.c"

	if test "$PHP_SWOOLE_STATIC" = "no"; then
		swoole_source_file="$swoole_source_file thirdparty/php_http_parser.c"
	else
		CFLAGS="$CFLAGS -DSW_STATIC_COMPILATION"
	fi

	swoole_source_file="$swoole_source_file thirdparty/multipart_parser.c"

    if test "$PHP_PICOHTTPPARSER" = "yes"; then
        AC_DEFINE(SW_USE_PICOHTTPPARSER, 1, [enable picohttpparser support])
        swoole_source_file="$swoole_source_file thirdparty/picohttpparser/picohttpparser.c"
    fi

    PHP_NEW_EXTENSION(swoole, $swoole_source_file, $ext_shared)

    PHP_ADD_INCLUDE([$ext_srcdir])
    PHP_ADD_INCLUDE([$ext_srcdir/include])

    PHP_INSTALL_HEADERS([ext/swoole], [*.h include/*.h])

    if test "$PHP_PICOHTTPPARSER" = "yes"; then
        PHP_ADD_INCLUDE([$ext_srcdir/thirdparty/picohttpparser])
        PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/picohttpparser)
    fi

    PHP_ADD_BUILD_DIR($ext_builddir/src/core)
    PHP_ADD_BUILD_DIR($ext_builddir/src/memory)
    PHP_ADD_BUILD_DIR($ext_builddir/src/factory)
    PHP_ADD_BUILD_DIR($ext_builddir/src/reactor)
    PHP_ADD_BUILD_DIR($ext_builddir/src/pipe)
    PHP_ADD_BUILD_DIR($ext_builddir/src/lock)
    PHP_ADD_BUILD_DIR($ext_builddir/src/os)
    PHP_ADD_BUILD_DIR($ext_builddir/src/network)
    PHP_ADD_BUILD_DIR($ext_builddir/src/protocol)
    PHP_ADD_BUILD_DIR($ext_builddir/thirdparty)
fi
