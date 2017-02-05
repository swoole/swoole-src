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

PHP_ARG_ENABLE(sockets, enable sockets support,
[  --enable-sockets        Do you have sockets extension?], no, no)

PHP_ARG_ENABLE(ringbuffer, enable ringbuffer shared memory pool support,
[  --enable-ringbuffer     Use ringbuffer memory pool?], no, no)

PHP_ARG_ENABLE(async_redis, enable async_redis support,
[  --enable-async-redis    Do you have hiredis?], no, no)

PHP_ARG_ENABLE(openssl, enable openssl support,
[  --enable-openssl        Use openssl?], no, no)

PHP_ARG_ENABLE(http2, enable http2.0 support,
[  --enable-http2          Use http2.0?], no, no)

PHP_ARG_ENABLE(thread, enable thread support,
[  --enable-thread         Use thread?], no, no)

PHP_ARG_ENABLE(jemalloc, enable jemalloc support,
[  --enable-jemalloc       Use jemalloc?], no, no)

PHP_ARG_ENABLE(tcmalloc, enable tcmalloc support,
[  --enable-tcmalloc       Use tcmalloc?], no, no)

PHP_ARG_ENABLE(hugepage, enable hugepage support,
[  --enable-hugepage       Use hugepage?], no, no)

PHP_ARG_ENABLE(swoole, swoole support,
[  --enable-swoole         Enable swoole support], [enable_swoole="yes"])

PHP_ARG_WITH(swoole, swoole support,
[  --with-swoole           With swoole support])

PHP_ARG_WITH(openssl_dir, for OpenSSL support,
[  --with-openssl-dir[=DIR]    Include OpenSSL support (requires OpenSSL >= 0.9.6)], no, no)

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
        #include <sched.h>
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
    fi

    if test "$PHP_SOCKETS" = "yes"; then
        AC_DEFINE(SW_SOCKETS, 1, [enable sockets support])
    fi

    if test "$PHP_RINGBUFFER" = "yes"; then
        AC_DEFINE(SW_USE_RINGBUFFER, 1, [enable ringbuffer support])
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

    AC_SWOOLE_CPU_AFFINITY
    AC_SWOOLE_HAVE_REUSEPORT

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
            PHP_ADD_INCLUDE("${PHP_OPENSSL_DIR}/include")
            PHP_ADD_LIBRARY_WITH_PATH(ssl, "${PHP_OPENSSL_DIR}/lib")
        fi

        AC_DEFINE(SW_USE_OPENSSL, 1, [enable openssl support])
        PHP_ADD_LIBRARY(ssl, 1, SWOOLE_SHARED_LIBADD)
        PHP_ADD_LIBRARY(crypto, 1, SWOOLE_SHARED_LIBADD)
    fi

    PHP_ADD_LIBRARY(pthread, 1, SWOOLE_SHARED_LIBADD)

    if test "$PHP_ASYNC_REDIS" = "yes"; then
        AC_DEFINE(SW_USE_REDIS, 1, [enable async-redis support])
        PHP_ADD_LIBRARY(hiredis, 1, SWOOLE_SHARED_LIBADD)
    fi

    if test "$PHP_HTTP2" = "yes"; then
        PHP_ADD_LIBRARY(nghttp2, 1, SWOOLE_SHARED_LIBADD)
    fi

    if test "$PHP_JEMALLOC" = "yes"; then
        PHP_ADD_LIBRARY(jemalloc, 1, SWOOLE_SHARED_LIBADD)
        AC_DEFINE(SW_USE_JEMALLOC, 1, [use jemalloc])
    elif test "$PHP_TCMALLOC" = "yes"; then
        PHP_ADD_LIBRARY(tcmalloc, 1, SWOOLE_SHARED_LIBADD)
        AC_DEFINE(SW_USE_TCMALLOC, 1, [use tcmalloc])
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
    AC_CHECK_LIB(c, inotify_init1, AC_DEFINE(HAVE_INOTIFY_INIT1, 1, [have inotify_init1]))
    AC_CHECK_LIB(pthread, pthread_rwlock_init, AC_DEFINE(HAVE_RWLOCK, 1, [have pthread_rwlock_init]))
    AC_CHECK_LIB(pthread, pthread_spin_lock, AC_DEFINE(HAVE_SPINLOCK, 1, [have pthread_spin_lock]))
    AC_CHECK_LIB(pthread, pthread_mutex_timedlock, AC_DEFINE(HAVE_MUTEX_TIMEDLOCK, 1, [have pthread_mutex_timedlock]))
    AC_CHECK_LIB(pthread, pthread_barrier_init, AC_DEFINE(HAVE_PTHREAD_BARRIER, 1, [have pthread_barrier_init]))
    AC_CHECK_LIB(ssl, SSL_library_init, AC_DEFINE(HAVE_OPENSSL, 1, [have openssl]))
    AC_CHECK_LIB(pcre, pcre_compile, AC_DEFINE(HAVE_PCRE, 1, [have pcre]))
    AC_CHECK_LIB(hiredis, redisConnect, AC_DEFINE(HAVE_HIREDIS, 1, [have hiredis]))
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
        swoole_event.c \
        swoole_timer.c \
        swoole_async.c \
        swoole_process.c \
        swoole_buffer.c \
        swoole_table.c \
        swoole_http_server.c \
        swoole_http_v2_server.c \
        swoole_websocket_server.c \
        swoole_http_client.c \
        swoole_mysql.c \
        swoole_redis.c \
        swoole_redis_server.c \
        swoole_module.c \
        swoole_mmap.c \
        swoole_channel.c \
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
        src/os/base.c \
        src/os/dl.c \
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

    swoole_source_file="$swoole_source_file thirdparty/php_http_parser.c"
    swoole_source_file="$swoole_source_file thirdparty/multipart_parser.c"

    PHP_NEW_EXTENSION(swoole, $swoole_source_file, $ext_shared)

    PHP_ADD_INCLUDE([$ext_srcdir])
    PHP_ADD_INCLUDE([$ext_srcdir/include])

    PHP_ADD_BUILD_DIR($ext_builddir/src/core)
    PHP_ADD_BUILD_DIR($ext_builddir/src/memory)
    PHP_ADD_BUILD_DIR($ext_builddir/src/factory)
    PHP_ADD_BUILD_DIR($ext_builddir/src/reactor)
    PHP_ADD_BUILD_DIR($ext_builddir/src/pipe)
    PHP_ADD_BUILD_DIR($ext_builddir/src/queue)
    PHP_ADD_BUILD_DIR($ext_builddir/src/lock)
    PHP_ADD_BUILD_DIR($ext_builddir/src/os)
    PHP_ADD_BUILD_DIR($ext_builddir/src/network)
    PHP_ADD_BUILD_DIR($ext_builddir/src/protocol)
    PHP_ADD_BUILD_DIR($ext_builddir/thirdparty)
fi
