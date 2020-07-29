dnl $Id$
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
dnl  | Author: Twosee  <twose@qq.com>                                       |
dnl  +----------------------------------------------------------------------+

PHP_ARG_ENABLE(debug-log, enable debug log,
[  --enable-debug-log        Enable swoole debug log], no, no)

PHP_ARG_ENABLE(trace-log, enable trace log,
[  --enable-trace-log        Enable swoole trace log], no, no)

PHP_ARG_ENABLE(sockets, enable sockets support,
[  --enable-sockets          Do you have sockets extension?], no, no)

PHP_ARG_ENABLE(openssl, enable openssl support,
[  --enable-openssl          Use openssl], no, no)

PHP_ARG_ENABLE(http2, enable http2.0 support,
[  --enable-http2            Use http2.0], no, no)

PHP_ARG_ENABLE(swoole, swoole support,
[  --enable-swoole           Enable swoole support], [enable_swoole="yes"])

PHP_ARG_ENABLE(mysqlnd, enable mysqlnd support,
[  --enable-mysqlnd          Enable mysqlnd], no, no)

PHP_ARG_WITH(openssl_dir, dir of openssl,
[  --with-openssl-dir[=DIR]    Include OpenSSL support (requires OpenSSL >= 0.9.6)], no, no)

PHP_ARG_WITH(jemalloc_dir, dir of jemalloc,
[  --with-jemalloc-dir[=DIR]   Include jemalloc support], no, no)

PHP_ARG_ENABLE(asan, enable asan,
[  --enable-asan             Enable asan], no, no)

PHP_ARG_ENABLE(gcov, enable gcov,
[  --enable-gcov             Enable gcov], no, no)

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
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
        #ifdef __FreeBSD__
        #include <sys/types.h>
        #include <sys/cpuset.h>
        typedef cpuset_t cpu_set_t;
        #else
        #include <sched.h>
        #endif
    ]], [[
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);
    ]])],[
        AC_DEFINE([HAVE_CPU_AFFINITY], 1, [cpu affinity?])
        AC_MSG_RESULT([yes])
    ],[
        AC_MSG_RESULT([no])
    ])
])

AC_DEFUN([AC_SWOOLE_HAVE_REUSEPORT],
[
    AC_MSG_CHECKING([for socket REUSEPORT])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
        #include <sys/socket.h>
    ]], [[
        int val = 1;
        setsockopt(0, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
    ]])],[
        AC_DEFINE([HAVE_REUSEPORT], 1, [have SO_REUSEPORT?])
        AC_MSG_RESULT([yes])
    ],[
        AC_MSG_RESULT([no])
    ])
])

AC_DEFUN([AC_SWOOLE_HAVE_FUTEX],
[
    AC_MSG_CHECKING([for futex])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
        #include <linux/futex.h>
        #include <syscall.h>
        #include <unistd.h>
    ]], [[
        int futex_addr;
        int val1;
        syscall(SYS_futex, &futex_addr, val1, NULL, NULL, 0);
    ]])],[
        AC_DEFINE([HAVE_FUTEX], 1, [have FUTEX?])
        AC_MSG_RESULT([yes])
    ],[
        AC_MSG_RESULT([no])
    ])
])

AC_DEFUN([AC_SWOOLE_HAVE_UCONTEXT],
[
    AC_MSG_CHECKING([for ucontext])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
        #include <stdio.h>
        #include <ucontext.h>
        #include <unistd.h>
    ]], [[
        ucontext_t context;
        getcontext(&context);
    ]])],[
        AC_DEFINE([HAVE_UCONTEXT], 1, [have ucontext?])
        AC_MSG_RESULT([yes])
    ],[
        AC_MSG_RESULT([no])
    ])
])

AC_DEFUN([AC_SWOOLE_HAVE_VALGRIND],
[
    AC_MSG_CHECKING([for valgrind])
    AC_LANG([C++])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
        #include <valgrind/valgrind.h>
    ]], [[

    ]])],[
        AC_DEFINE([HAVE_VALGRIND], 1, [have valgrind?])
        AC_MSG_RESULT([yes])
    ],[
        AC_MSG_RESULT([no])
    ])
])

AC_DEFUN([AC_SWOOLE_CHECK_SOCKETS], [
    dnl Check for struct cmsghdr
    AC_CACHE_CHECK([for struct cmsghdr], ac_cv_cmsghdr,
    [
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>]], [[struct cmsghdr s; s]])], [ac_cv_cmsghdr=yes], [ac_cv_cmsghdr=no])
    ])

    if test "$ac_cv_cmsghdr" = yes; then
        AC_DEFINE(HAVE_CMSGHDR,1,[Whether you have struct cmsghdr])
    fi

    AC_CHECK_FUNCS([hstrerror socketpair if_nametoindex if_indextoname])
    AC_CHECK_HEADERS([netdb.h netinet/tcp.h sys/un.h sys/sockio.h])
    AC_DEFINE([HAVE_SOCKETS], 1, [ ])

    dnl Check for fied ss_family in sockaddr_storage (missing in AIX until 5.3)
    AC_CACHE_CHECK([for field ss_family in struct sockaddr_storage], ac_cv_ss_family,
    [
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
    ]], [[struct sockaddr_storage sa_store; sa_store.ss_family = AF_INET6;]])],
        [ac_cv_ss_family=yes], [ac_cv_ss_family=no])
    ])

    if test "$ac_cv_ss_family" = yes; then
        AC_DEFINE(HAVE_SA_SS_FAMILY,1,[Whether you have sockaddr_storage.ss_family])
    fi

    dnl Check for AI_V4MAPPED flag
    AC_CACHE_CHECK([if getaddrinfo supports AI_V4MAPPED],[ac_cv_gai_ai_v4mapped],
    [
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <netdb.h>
    ]], [[int flag = AI_V4MAPPED;]])],
        [ac_cv_gai_ai_v4mapped=yes], [ac_cv_gai_ai_v4mapped=no])
    ])

    if test "$ac_cv_gai_ai_v4mapped" = yes; then
        AC_DEFINE(HAVE_AI_V4MAPPED,1,[Whether you have AI_V4MAPPED])
    fi

    dnl Check for AI_ALL flag
    AC_CACHE_CHECK([if getaddrinfo supports AI_ALL],[ac_cv_gai_ai_all],
    [
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <netdb.h>
    ]], [[int flag = AI_ALL;]])],
        [ac_cv_gai_ai_all=yes], [ac_cv_gai_ai_all=no])
    ])

    if test "$ac_cv_gai_ai_all" = yes; then
        AC_DEFINE(HAVE_AI_ALL,1,[Whether you have AI_ALL])
    fi

    dnl Check for AI_IDN flag
    AC_CACHE_CHECK([if getaddrinfo supports AI_IDN],[ac_cv_gai_ai_idn],
    [
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <netdb.h>
    ]], [[int flag = AI_IDN;]])],
            [ac_cv_gai_ai_idn=yes], [ac_cv_gai_ai_idn=no])
    ])

    if test "$ac_cv_gai_ai_idn" = yes; then
        AC_DEFINE(HAVE_AI_IDN,1,[Whether you have AI_IDN])
    fi
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

AC_CANONICAL_HOST

if test "$PHP_SWOOLE" != "no"; then

    AC_CHECK_LIB(c, accept4, AC_DEFINE(HAVE_ACCEPT4, 1, [have accept4]))
    AC_CHECK_LIB(c, signalfd, AC_DEFINE(HAVE_SIGNALFD, 1, [have signalfd]))
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

    AC_CHECK_LIB(z, gzgets, [
        AC_DEFINE(SW_HAVE_COMPRESSION, 1, [have compression])
        AC_DEFINE(SW_HAVE_ZLIB, 1, [have zlib])
        PHP_ADD_LIBRARY(z, 1, SWOOLE_SHARED_LIBADD)
    ])

    AC_CHECK_LIB(brotlienc, BrotliEncoderCreateInstance, [
        AC_CHECK_LIB(brotlidec, BrotliDecoderCreateInstance, [
            AC_DEFINE(SW_HAVE_COMPRESSION, 1, [have compression])
            AC_DEFINE(SW_HAVE_BROTLI, 1, [have brotli encoder])
            PHP_ADD_LIBRARY(brotlienc, 1, SWOOLE_SHARED_LIBADD)
            PHP_ADD_LIBRARY(brotlidec, 1, SWOOLE_SHARED_LIBADD)
        ])
    ])

    PHP_ADD_LIBRARY(pthread)
    PHP_SUBST(SWOOLE_SHARED_LIBADD)

    AC_ARG_ENABLE(debug,
        [  --enable-debug,         compile with debug symbols],
        [PHP_DEBUG=$enableval],
        [PHP_DEBUG=0]
    )

    if test "$PHP_DEBUG_LOG" != "no"; then
        AC_DEFINE(SW_DEBUG, 1, [do we enable swoole debug])
        PHP_DEBUG=1
    fi

    if test "$PHP_ASAN" != "no"; then
        PHP_DEBUG=1
        CFLAGS="$CFLAGS -fsanitize=address -fno-omit-frame-pointer"
        CXXFLAGS="$CXXFLAGS -fsanitize=address -fno-omit-frame-pointer"
    fi
    
    if test "$PHP_GCOV" != "no"; then
        PHP_DEBUG=1
        CFLAGS="$CFLAGS -fprofile-arcs -ftest-coverage"
        CXXFLAGS="$CXXFLAGS -fprofile-arcs -ftest-coverage"
    fi

    if test "$PHP_TRACE_LOG" != "no"; then
        AC_DEFINE(SW_LOG_TRACE_OPEN, 1, [enable trace log])
    fi

    if test "$PHP_SOCKETS" = "yes"; then
        AC_MSG_CHECKING([for php_sockets.h])

        AS_IF([test -f $abs_srcdir/ext/sockets/php_sockets.h], [AC_MSG_RESULT([ok, found in $abs_srcdir])],
            [test -f $phpincludedir/ext/sockets/php_sockets.h], [AC_MSG_RESULT([ok, found in $phpincludedir])],
            [AC_MSG_ERROR([cannot find php_sockets.h. Please check if sockets extension is installed.])
        ])

        AC_DEFINE(SW_SOCKETS, 1, [enable sockets support])

        dnl Some systems build and package PHP socket extension separately
        dnl and php_config.h does not have HAVE_SOCKETS defined.
        AC_DEFINE(HAVE_SOCKETS, 1, [whether sockets extension is enabled])

        PHP_ADD_EXTENSION_DEP(swoole, sockets, true)
    fi

    if test "$PHP_THREAD" = "yes"; then
        AC_DEFINE(SW_USE_THREAD, 1, [enable thread support])
    fi

    AC_SWOOLE_CPU_AFFINITY
    AC_SWOOLE_HAVE_REUSEPORT
    AC_SWOOLE_HAVE_FUTEX
    AC_SWOOLE_HAVE_UCONTEXT
    AC_SWOOLE_HAVE_VALGRIND
    AC_SWOOLE_CHECK_SOCKETS

    AS_CASE([$host_os],
      [darwin*], [SW_OS="MAC"],
      [cygwin*], [SW_OS="CYGWIN"],
      [mingw*], [SW_OS="MINGW"],
      [linux*], [SW_OS="LINUX"],
      []
    )

    CFLAGS="-Wall -pthread $CFLAGS"
    LDFLAGS="$LDFLAGS -lpthread"

    if test "$SW_OS" = "MAC"; then
        AC_CHECK_LIB(c, clock_gettime, AC_DEFINE(HAVE_CLOCK_GETTIME, 1, [have clock_gettime]))
    else
        AC_CHECK_LIB(rt, clock_gettime, AC_DEFINE(HAVE_CLOCK_GETTIME, 1, [have clock_gettime]))
        PHP_ADD_LIBRARY(rt, 1, SWOOLE_SHARED_LIBADD)
    fi
    if test "$SW_OS" = "LINUX"; then
        LDFLAGS="$LDFLAGS -z now"
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

    if test "$PHP_HTTP2" = "yes"; then
        AC_DEFINE(SW_USE_HTTP2, 1, [enable HTTP2 support])
    fi

    if test "$PHP_MYSQLND" = "yes"; then
        PHP_ADD_EXTENSION_DEP(mysqli, mysqlnd)
        AC_DEFINE(SW_USE_MYSQLND, 1, [use mysqlnd])
    fi

    swoole_source_file=" \
        php_swoole_cxx.cc \
        src/core/array.c \
        src/core/base.c \
        src/core/channel.c \
        src/core/error.cc \
        src/core/hashmap.c \
        src/core/heap.c \
        src/core/list.c \
        src/core/log.c \
        src/core/rbtree.c \
        src/core/ring_queue.c \
        src/core/socket.c \
        src/core/string.c \
        src/coroutine/base.cc \
        src/coroutine/channel.cc \
        src/coroutine/context.cc \
        src/coroutine/file_lock.cc \
        src/coroutine/hook.cc \
        src/coroutine/socket.cc \
        src/coroutine/system.cc \
        src/coroutine/thread_context.cc \
        src/coroutine/ucontext.cc \
        src/lock/atomic.c \
        src/lock/cond.c \
        src/lock/file_lock.c \
        src/lock/mutex.c \
        src/lock/rw_lock.c \
        src/lock/semaphore.c \
        src/lock/spin_lock.c \
        src/memory/buffer.c \
        src/memory/fixed_pool.c \
        src/memory/global_memory.c \
        src/memory/malloc.c \
        src/memory/ring_buffer.c \
        src/memory/shared_memory.c \
        src/memory/table.c \
        src/network/client.c \
        src/network/connection.c \
        src/network/dns.cc \
        src/network/process_pool.c \
        src/network/stream.c \
        src/network/thread_pool.c \
        src/network/timer.c \
        src/os/async_thread.cc \
        src/os/base.c \
        src/os/msg_queue.c \
        src/os/sendfile.c \
        src/os/signal.c \
        src/os/timer.c \
        src/os/wait.cc \
        src/pipe/base.c \
        src/pipe/eventfd.c \
        src/pipe/unix_socket.c \
        src/protocol/base.cc \
        src/protocol/base64.c \
        src/protocol/http.c \
        src/protocol/http2.c \
        src/protocol/mime_types.cc \
        src/protocol/mqtt.c \
        src/protocol/redis.c \
        src/protocol/sha1.c \
        src/protocol/socks5.c \
        src/protocol/ssl.c \
        src/protocol/websocket.c \
        src/reactor/base.cc \
        src/reactor/epoll.cc \
        src/reactor/kqueue.c \
        src/reactor/poll.c \
        src/reactor/select.c \
        src/server/base.c \
        src/server/manager.cc \
        src/server/master.cc \
        src/server/port.cc \
        src/server/process.cc \
        src/server/reactor_process.cc \
        src/server/reactor_thread.cc \
        src/server/static_handler.cc \
        src/server/task_worker.cc \
        src/server/worker.cc \
        src/wrapper/event.cc \
        src/wrapper/server.cc \
        src/wrapper/timer.cc \
        swoole.cc \
        swoole_async_coro.cc \
        swoole_atomic.cc \
        swoole_buffer.c \
        swoole_channel_coro.cc \
        swoole_client.cc \
        swoole_client_coro.cc \
        swoole_coroutine.cc \
        swoole_coroutine_scheduler.cc \
        swoole_coroutine_system.cc \
        swoole_event.cc \
        swoole_http2_client_coro.cc \
        swoole_http2_server.cc \
        swoole_http_client_coro.cc \
        swoole_http_request.cc \
        swoole_http_response.cc \
        swoole_http_server.cc \
        swoole_http_server_coro.cc \
        swoole_lock.cc \
        swoole_mysql_coro.cc \
        swoole_mysql_proto.cc \
        swoole_process.cc \
        swoole_process_pool.cc \
        swoole_redis_coro.cc \
        swoole_redis_server.cc \
        swoole_runtime.cc \
        swoole_server.cc \
        swoole_server_port.cc \
        swoole_socket_coro.cc \
        swoole_table.cc \
        swoole_timer.cc \
        swoole_websocket_server.cc"

    swoole_source_file="$swoole_source_file \
        thirdparty/php/sockets/multicast.cc \
        thirdparty/php/sockets/sendrecvmsg.cc \
        thirdparty/php/sockets/conversions.cc \
        thirdparty/php/sockets/sockaddr_conv.cc \
        thirdparty/php/standard/proc_open.cc"

    swoole_source_file="$swoole_source_file \
        thirdparty/swoole_http_parser.c \
	    thirdparty/multipart_parser.c"

    swoole_source_file="$swoole_source_file \
        thirdparty/hiredis/async.c \
        thirdparty/hiredis/hiredis.c \
        thirdparty/hiredis/net.c \
        thirdparty/hiredis/read.c \
        thirdparty/hiredis/sds.c"

    swoole_source_file="$swoole_source_file \
        thirdparty/nghttp2/nghttp2_hd.c \
        thirdparty/nghttp2/nghttp2_rcbuf.c \
        thirdparty/nghttp2/nghttp2_helper.c \
        thirdparty/nghttp2/nghttp2_buf.c \
        thirdparty/nghttp2/nghttp2_mem.c \
        thirdparty/nghttp2/nghttp2_hd_huffman.c \
        thirdparty/nghttp2/nghttp2_hd_huffman_data.c"

    SW_ASM_DIR="thirdparty/boost/asm/"
    SW_USE_ASM_CONTEXT="yes"

    AS_CASE([$host_cpu],
      [x86_64*], [SW_CPU="x86_64"],
      [x86*], [SW_CPU="x86"],
      [i?86*], [SW_CPU="x86"],
      [arm*], [SW_CPU="arm"],
      [aarch64*], [SW_CPU="arm64"],
      [arm64*], [SW_CPU="arm64"],
      [mips*], [SW_CPU="mips32"],
      [
        SW_USE_ASM_CONTEXT="no"
      ]
    )

    if test "$SW_OS" = "MAC"; then
        if test "$SW_CPU" = "arm"; then
            SW_CONTEXT_ASM_FILE="arm_aapcs_macho_gas.S"
        elif test "$SW_CPU" = "arm64"; then
            SW_CONTEXT_ASM_FILE="arm64_aapcs_macho_gas.S"
        else
            SW_CONTEXT_ASM_FILE="combined_sysv_macho_gas.S"
        fi
    elif test "$SW_CPU" = "x86_64"; then
        if test "$SW_OS" = "LINUX"; then
            SW_CONTEXT_ASM_FILE="x86_64_sysv_elf_gas.S"
        else
            SW_USE_ASM_CONTEXT="no"
        fi
    elif test "$SW_CPU" = "x86"; then
        if test "$SW_OS" = "LINUX"; then
            SW_CONTEXT_ASM_FILE="i386_sysv_elf_gas.S"
        else
            SW_USE_ASM_CONTEXT="no"
        fi
    elif test "$SW_CPU" = "arm"; then
        if test "$SW_OS" = "LINUX"; then
            SW_CONTEXT_ASM_FILE="arm_aapcs_elf_gas.S"
        else
            SW_USE_ASM_CONTEXT="no"
        fi
    elif test "$SW_CPU" = "arm64"; then
        if test "$SW_OS" = "LINUX"; then
            SW_CONTEXT_ASM_FILE="arm64_aapcs_elf_gas.S"
        else
            SW_USE_ASM_CONTEXT="no"
        fi
     elif test "$SW_CPU" = "ppc32"; then
        if test "$SW_OS" = "LINUX"; then
            SW_CONTEXT_ASM_FILE="ppc32_sysv_elf_gas.S"
        else
            SW_USE_ASM_CONTEXT="no"
        fi
    elif test "$SW_CPU" = "ppc64"; then
        if test "$SW_OS" = "LINUX"; then
            SW_CONTEXT_ASM_FILE="ppc64_sysv_elf_gas.S"
        else
            SW_USE_ASM_CONTEXT="no"
        fi
    elif test "$SW_CPU" = "mips32"; then
        if test "$SW_OS" = "LINUX"; then
           SW_CONTEXT_ASM_FILE="mips32_o32_elf_gas.S"
        else
            SW_USE_ASM_CONTEXT="no"
        fi
    else
        SW_USE_ASM_CONTEXT="no"
    fi

    if test "$SW_USE_ASM_CONTEXT" = "yes"; then
        swoole_source_file="$swoole_source_file \
            ${SW_ASM_DIR}make_${SW_CONTEXT_ASM_FILE} \
            ${SW_ASM_DIR}jump_${SW_CONTEXT_ASM_FILE} "
        AC_DEFINE(SW_USE_ASM_CONTEXT, 1, [use boost asm context])
    fi

    PHP_NEW_EXTENSION(swoole, $swoole_source_file, $ext_shared,,, cxx)

    PHP_ADD_INCLUDE([$ext_srcdir])
    PHP_ADD_INCLUDE([$ext_srcdir/include])
    PHP_ADD_INCLUDE([$ext_srcdir/thirdparty/hiredis])

    PHP_INSTALL_HEADERS([ext/swoole], [*.h config.h include/*.h thirdparty/*.h thirdparty/hiredis/*.h])

    PHP_REQUIRE_CXX()

    CXXFLAGS="$CXXFLAGS -Wall -Wno-unused-function -Wno-deprecated -Wno-deprecated-declarations"

    if test "$SW_OS" = "CYGWIN" || test "$SW_OS" = "MINGW"; then
        CXXFLAGS="$CXXFLAGS -std=gnu++11"
    else
        CXXFLAGS="$CXXFLAGS -std=c++11"
    fi

    PHP_ADD_BUILD_DIR($ext_builddir/src/core)
    PHP_ADD_BUILD_DIR($ext_builddir/src/memory)
    PHP_ADD_BUILD_DIR($ext_builddir/src/reactor)
    PHP_ADD_BUILD_DIR($ext_builddir/src/pipe)
    PHP_ADD_BUILD_DIR($ext_builddir/src/lock)
    PHP_ADD_BUILD_DIR($ext_builddir/src/os)
    PHP_ADD_BUILD_DIR($ext_builddir/src/network)
    PHP_ADD_BUILD_DIR($ext_builddir/src/server)
    PHP_ADD_BUILD_DIR($ext_builddir/src/protocol)
    PHP_ADD_BUILD_DIR($ext_builddir/src/coroutine)
    PHP_ADD_BUILD_DIR($ext_builddir/src/wrapper)
    PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/boost)
    PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/boost/asm)
    PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/hiredis)
    PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/nghttp2)
    PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/php/sockets)
    PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/php/standard)
fi
