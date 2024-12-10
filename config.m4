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
dnl  | Author: Tianfeng Han  <rango@swoole.com>                             |
dnl  | Author: Twosee  <twose@qq.com>                                       |
dnl  +----------------------------------------------------------------------+

PHP_ARG_ENABLE([debug-log],
  [enable debug log],
  [AS_HELP_STRING([--enable-debug-log],
    [Enable swoole debug log])], [no], [no])

PHP_ARG_ENABLE([trace-log],
  [enable trace log],
  [AS_HELP_STRING([--enable-trace-log],
    [Enable swoole trace log])], [no], [no])

PHP_ARG_ENABLE([sockets],
  [enable sockets support],
  [AS_HELP_STRING([--enable-sockets],
    [Do you have sockets extension?])], [no], [no])

PHP_ARG_ENABLE([openssl],
  [enable openssl support],
  [AS_HELP_STRING([--enable-openssl],
    [Use openssl])], [no], [no])

PHP_ARG_ENABLE([swoole],
  [swoole support],
  [AS_HELP_STRING([--enable-swoole],
    [Enable swoole support])], [enable_swoole="yes"])

PHP_ARG_ENABLE([mysqlnd],
  [enable mysqlnd support],
  [AS_HELP_STRING([--enable-mysqlnd],
    [Enable mysqlnd])], [no], [no])

PHP_ARG_ENABLE([cares],
  [enable c-ares support],
  [AS_HELP_STRING([--enable-cares],
    [Enable cares])], [no], [no])

PHP_ARG_ENABLE([iouring],
  [enable io-uring support],
  [AS_HELP_STRING([--enable-iouring],
    [Enable io-uring])], [no], [no])

PHP_ARG_WITH([openssl_dir],
  [dir of openssl],
  [AS_HELP_STRING([[--with-openssl-dir[=DIR]]],
    [Include OpenSSL support (requires OpenSSL >= 1.0.2)])], [no], [no])

PHP_ARG_ENABLE([brotli],
  [enable brotli support],
  [AS_HELP_STRING([[--enable-brotli]],
    [Use brotli])], [auto], [no])

PHP_ARG_WITH([brotli_dir],
  [dir of brotli],
  [AS_HELP_STRING([[--with-brotli-dir[=DIR]]],
    [Include Brotli support])], [no], [no])

PHP_ARG_ENABLE([zstd],
  [enable zstd support],
  [AS_HELP_STRING([[--enable-zstd]],
    [Use zstd])], [no], [no])

PHP_ARG_WITH([nghttp2_dir],
  [dir of nghttp2],
  [AS_HELP_STRING([[--with-nghttp2-dir[=DIR]]],
    [Include nghttp2 support])], [no], [no])

PHP_ARG_ENABLE([asan],
  [enable asan],
  [AS_HELP_STRING([--enable-asan],
    [Enable asan])], [no], [no])

PHP_ARG_ENABLE([swoole-coverage],
  [whether to enable swoole coverage support],
  [AS_HELP_STRING([--enable-swoole-coverage],
    [Enable swoole coverage support])], [no], [no])

PHP_ARG_ENABLE([swoole-dev],
  [whether to enable Swoole developer build flags],
  [AS_HELP_STRING([--enable-swoole-dev],
    [Enable developer flags])], [no], [no])

PHP_ARG_ENABLE([swoole-curl],
  [whether to enable Swoole CURL build flags],
  [AS_HELP_STRING([--enable-swoole-curl],
    [Enable cURL support])], [no], [no])

PHP_ARG_ENABLE([swoole-pgsql],
  [whether to enable postgresql build flags],
  [AS_HELP_STRING([--enable-swoole-pgsql],
    [Enable postgresql support])], [no], [no])

PHP_ARG_ENABLE([thread-context],
  [whether to enable thread context],
  [AS_HELP_STRING([--enable-thread-context],
    [Use thread context])], [no], [no])

PHP_ARG_ENABLE([swoole-thread],
  [whether to enable swoole thread support],
  [AS_HELP_STRING([--enable-swoole-thread],
    [Enable swoole thread support])], [no], [no])

PHP_ARG_ENABLE([swoole-coro-time],
  [whether to enable coroutine execution time ],
  [AS_HELP_STRING([--enable-swoole-coro-time],
    [Calculating coroutine execution time])], [no], [no])

define([PDO_ODBC_HELP_TEXT],[[
  The include and lib dirs are looked for under 'dir'. The 'flavour' can be one
  of: ibm-db2, iODBC, unixODBC, generic. If ',dir' part is omitted, default for
  the flavour you have selected will be used. e.g.: --with-swoole-odbc=unixODBC
  will check for unixODBC under /usr/local. You may attempt to use an otherwise
  unsupported driver using the 'generic' flavour. The syntax for generic ODBC
  support is: --with-swoole-odbc=generic,dir,libname,ldflags,cflags. When built as
  'shared' the extension filename is always pdo_odbc.so]])

PHP_ARG_WITH([swoole-odbc],
  ["for ODBC v3 support for PDO"],
  [AS_HELP_STRING([--with-swoole-odbc=flavour,dir],
    ["PDO: Support for 'flavour' ODBC driver."]PDO_ODBC_HELP_TEXT)], [no], [no])

AC_DEFUN([PDO_ODBC_CHECK_HEADER],[
  AC_MSG_CHECKING([for $1 in $PDO_ODBC_INCDIR])
  if test -f "$PDO_ODBC_INCDIR/$1"; then
    php_pdo_have_header=yes
    AC_DEFINE_UNQUOTED(AS_TR_CPP([HAVE_$1]), [1],
      [Define to 1 if you have the <$1> header file.])
    AC_MSG_RESULT(yes)
  else
    AC_MSG_RESULT(no)
  fi
])

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
        #define _XOPEN_SOURCE
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
    AC_LANG_PUSH([C++])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
        #include <valgrind/valgrind.h>
    ]], [[

    ]])],[
        AC_DEFINE([HAVE_VALGRIND], 1, [have valgrind?])
        AC_MSG_RESULT([yes])
    ],[
        AC_MSG_RESULT([no])
    ])
    AC_LANG_POP([C++])
])

AC_DEFUN([AC_SWOOLE_HAVE_BOOST_STACKTRACE],
[
    AC_MSG_CHECKING([for valgrind])
    AC_LANG_PUSH([C++])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
        #include <boost/stacktrace.hpp>
    ]], [[

    ]])],[
        AC_DEFINE([HAVE_BOOST_STACKTRACE], 1, [have boost-stacktrace?])
        AC_MSG_RESULT([yes])
    ],[
        AC_MSG_RESULT([no])
    ])
    AC_LANG_POP([C++])
])

AC_DEFUN([AC_SWOOLE_CHECK_SOCKETS], [
    AC_CHECK_FUNCS([hstrerror socketpair if_nametoindex if_indextoname])
    AC_CHECK_HEADERS([netdb.h netinet/tcp.h sys/un.h sys/sockio.h])
    AC_DEFINE([HAVE_SOCKETS], 1, [ ])

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

dnl AC_PROG_CC_C99 is obsolete with autoconf >= 2.70 yet necessary for <= 2.69.
m4_version_prereq([2.70],,[AC_PROG_CC_C99])

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
    AC_CHECK_LIB(c, getrandom, AC_DEFINE(HAVE_GETRANDOM, 1, [have getrandom]))
    AC_CHECK_LIB(c, arc4random, AC_DEFINE(HAVE_ARC4RANDOM, 1, [have arc4random]))
    AC_CHECK_LIB(c, CCRandomGenerateBytes, AC_DEFINE(HAVE_CCRANDOMGENERATEBYTES, 1, [have_ccrandomgeneratebytes]))
    AC_CHECK_LIB(pthread, pthread_rwlock_init, AC_DEFINE(HAVE_RWLOCK, 1, [have pthread_rwlock_init]))
    AC_CHECK_LIB(pthread, pthread_spin_lock, AC_DEFINE(HAVE_SPINLOCK, 1, [have pthread_spin_lock]))
    AC_CHECK_LIB(pthread, pthread_mutex_timedlock, AC_DEFINE(HAVE_MUTEX_TIMEDLOCK, 1, [have pthread_mutex_timedlock]))
    AC_CHECK_LIB(pthread, pthread_barrier_init, AC_DEFINE(HAVE_PTHREAD_BARRIER, 1, [have pthread_barrier_init]))
    AC_CHECK_LIB(pthread, pthread_mutexattr_setpshared, AC_DEFINE(HAVE_PTHREAD_MUTEXATTR_SETPSHARED, 1, [have pthread_mutexattr_setpshared]))
    AC_CHECK_LIB(pthread, pthread_mutexattr_setrobust, AC_DEFINE(HAVE_PTHREAD_MUTEXATTR_SETROBUST, 1, [have pthread_mutexattr_setrobust]))
    AC_CHECK_LIB(pthread, pthread_mutex_consistent, AC_DEFINE(HAVE_PTHREAD_MUTEX_CONSISTENT, 1, [have pthread_mutex_consistent]))
    AC_CHECK_LIB(pcre, pcre_compile, AC_DEFINE(HAVE_PCRE, 1, [have pcre]))

    if test "$PHP_SWOOLE_DEV" = "yes"; then
        AX_CHECK_COMPILE_FLAG(-Wbool-conversion,                _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Wbool-conversion")
        AX_CHECK_COMPILE_FLAG(-Wignored-qualifiers,             _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Wignored-qualifiers")
        AX_CHECK_COMPILE_FLAG(-Wduplicate-enum,                 _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Wduplicate-enum")
        AX_CHECK_COMPILE_FLAG(-Wempty-body,                     _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Wempty-body")
        AX_CHECK_COMPILE_FLAG(-Wenum-compare,                   _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Wenum-compare")
        AX_CHECK_COMPILE_FLAG(-Wextra,                          _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Wextra")
        AX_CHECK_COMPILE_FLAG(-Wformat-security,                _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Wformat-security")
        AX_CHECK_COMPILE_FLAG(-Wheader-guard,                   _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Wheader-guard")
        AX_CHECK_COMPILE_FLAG(-Wincompatible-pointer-types-discards-qualifiers, _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Wincompatible-pointer-types-discards-qualifiers")
        AX_CHECK_COMPILE_FLAG(-Winit-self,                      _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Winit-self")
        AX_CHECK_COMPILE_FLAG(-Wlogical-not-parentheses,        _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Wlogical-not-parentheses")
        AX_CHECK_COMPILE_FLAG(-Wlogical-op-parentheses,         _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Wlogical-op-parentheses")
        AX_CHECK_COMPILE_FLAG(-Wloop-analysis,                  _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Wloop-analysis")
        AX_CHECK_COMPILE_FLAG(-Wuninitialized,                  _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Wuninitialized")
        AX_CHECK_COMPILE_FLAG(-Wno-missing-field-initializers,  _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Wno-missing-field-initializers")
        AX_CHECK_COMPILE_FLAG(-Wno-sign-compare,                _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Wno-sign-compare")
        AX_CHECK_COMPILE_FLAG(-Wno-unused-const-variable,       _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Wno-unused-const-variable")
        AX_CHECK_COMPILE_FLAG(-Wno-unused-parameter,            _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Wno-unused-parameter")
        AX_CHECK_COMPILE_FLAG(-Wno-variadic-macros,             _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Wno-variadic-macros")
        AX_CHECK_COMPILE_FLAG(-Wparentheses,                    _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Wparentheses")
        AX_CHECK_COMPILE_FLAG(-Wpointer-bool-conversion,        _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Wpointer-bool-conversion")
        AX_CHECK_COMPILE_FLAG(-Wsizeof-array-argument,          _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Wsizeof-array-argument")
        AX_CHECK_COMPILE_FLAG(-Wwrite-strings,                  _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -Wwrite-strings")
        AX_CHECK_COMPILE_FLAG(-fdiagnostics-show-option,        _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -fdiagnostics-show-option")
        AX_CHECK_COMPILE_FLAG(-fno-omit-frame-pointer,          _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -fno-omit-frame-pointer")
        AX_CHECK_COMPILE_FLAG(-fno-optimize-sibling-calls,      _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -fno-optimize-sibling-calls")
        AX_CHECK_COMPILE_FLAG(-fsanitize-address,               _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -fsanitize-address")
        AX_CHECK_COMPILE_FLAG(-fstack-protector,                _MAINTAINER_CFLAGS="$_MAINTAINER_CFLAGS -fstack-protector")

        EXTRA_CFLAGS="$_MAINTAINER_CFLAGS"
        CFLAGS="-g -O0 -Wall $CFLAGS"
        CXXFLAGS="-g -O0 -Wall $CXXFLAGS"
    fi

    if test "$PHP_SWOOLE_CURL" = "yes"; then
        PKG_CHECK_MODULES([CURL], [libcurl >= 7.56.0])
        PHP_EVAL_LIBLINE($CURL_LIBS, SWOOLE_SHARED_LIBADD)
        PHP_EVAL_INCLINE($CURL_CFLAGS)
        AC_DEFINE(SW_USE_CURL, 1, [do we enable cURL native client])
    fi

    if test "$PHP_SWOOLE_CORO_TIME" = "yes"; then
        AC_DEFINE(SW_CORO_TIME, 1, [do we enable to calculate coroutine execution time])
    fi

    dnl pgsql begin

    if test "$PHP_SWOOLE_PGSQL" != "no"; then
        dnl TODO macros below can be reused to find curl things
        dnl prepare pkg-config

        if test -z "$PKG_CONFIG"; then
            AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
        fi
        AC_MSG_CHECKING(for libpq)
        if test "x${LIBPQ_LIBS+set}" = "xset" || test "x${LIBPQ_CFLAGS+set}" = "xset"; then
            AC_MSG_RESULT([using LIBPQ_CFLAGS and LIBPQ_LIBS])
        elif test -x "$PKG_CONFIG" ; then
            dnl find pkg using pkg-config cli tool
            libpq_pkg_config_path="$PHP_SWOOLE_PGSQL/lib/pkgconfig"
            if test "xyes" = "x$PHP_SWOOLE_PGSQL" ; then
                libpq_pkg_config_path=/lib/pkgconfig
            fi
            if test "x" != "x$PKG_CONFIG_PATH"; then
                libpq_pkg_config_path="$libpq_pkg_config_path:$PKG_CONFIG_PATH"
            fi

            libpq_version_full=`env PKG_CONFIG_PATH=${libpq_pkg_config_path} $PKG_CONFIG --modversion libpq`
            AC_MSG_RESULT(${libpq_version_full})
            LIBPQ_CFLAGS="`env PKG_CONFIG_PATH=${libpq_pkg_config_path} $PKG_CONFIG --cflags libpq`"
            LIBPQ_LIBS="`env PKG_CONFIG_PATH=${libpq_pkg_config_path} $PKG_CONFIG --libs libpq`"
        fi

        _libpq_saved_cflags="$CFLAGS"
        CFLAGS="$CFLAGS $LIBPQ_CFLAGS"
        AC_CHECK_HEADER(libpq-fe.h, [], [
            dnl this is too long, wht so chaos?
            cat >&2 <<EOF
libpq headers was not found.
set LIBPQ_CFLAGS and LIBPQ_LIBS environment or
install following package to obtain them:
    libpq-dev (for debian and its varients)
    postgresql-devel (for rhel varients)
    libpq-devel (for newer fedora)
    postgresql-libs (for arch and its varients)
    postgresql-dev (for alpine)
    postgresql (for homebrew)
EOF
            AC_MSG_ERROR([postgresql support needs libpq headers to build])
        ])
        CFLAGS="$_libpq_saved_cflags"

        _libpq_saved_libs=$LIBS
        LIBS="$LIBS $LIBPQ_LIBS"
        AC_CHECK_LIB(pq, PQlibVersion, [ ], [
            cat >&2 <<EOF
libpq libraries was not found.
set LIBPQ_CFLAGS and LIBPQ_LIBS environment or
install following package to obtain them:
    libpq-dev (for debian and its varients)
    postgresql-devel (for rhel varients)
    libpq-devel (for newer fedora)
    postgresql-libs (for arch and its varients)
    postgresql-dev (for alpine)
    postgresql (for homebrew)
EOF
            AC_MSG_ERROR([postgresql support needs libpq libraries to build])
        ])
        LIBS="$_libpq_saved_libs"

        dnl FIXME: this should be SWOOLE_CFLAGS="$SWOOLE_CFLAGS $LIBPQ_CFLAGS"
        dnl or SWOOLE_PGSQL_CFLAGS="$SWOOLE_CFLAGS $LIBPQ_CFLAGS" and SWOOLE_PGSQL_CFLAGS only applies to ext-src/swoole_postgresql_coro.cc
        EXTRA_CFLAGS="$EXTRA_CFLAGS $LIBPQ_CFLAGS"
        PHP_EVAL_LIBLINE($LIBPQ_LIBS, SWOOLE_SHARED_LIBADD)

        AC_DEFINE(SW_USE_PGSQL, 1, [do we enable postgresql coro support])
    fi

    dnl pgsql end

    dnl odbc begin

    if test "$PHP_SWOOLE_ODBC" != "no"; then
      PHP_CHECK_PDO_INCLUDES

      AC_MSG_CHECKING([for selected PDO ODBC flavour])

      pdo_odbc_flavour="`echo $PHP_SWOOLE_ODBC | cut -d, -f1`"
      pdo_odbc_dir="`echo $PHP_SWOOLE_ODBC | cut -d, -f2`"

      if test "$pdo_odbc_dir" = "$PHP_SWOOLE_ODBC" ; then
        pdo_odbc_dir=
      fi

      case $pdo_odbc_flavour in
        ibm-db2)
            pdo_odbc_def_libdir=/home/db2inst1/sqllib/lib
            pdo_odbc_def_incdir=/home/db2inst1/sqllib/include
            pdo_odbc_def_lib=db2
            ;;

        iODBC|iodbc)
            pdo_odbc_def_libdir=/usr/local/$PHP_LIBDIR
            pdo_odbc_def_incdir=/usr/local/include
            pdo_odbc_def_lib=iodbc
            ;;

        unixODBC|unixodbc)
            pdo_odbc_def_libdir=/usr/local/$PHP_LIBDIR
            pdo_odbc_def_incdir=/usr/local/include
            pdo_odbc_def_lib=odbc
            ;;

        ODBCRouter|odbcrouter)
            pdo_odbc_def_libdir=/usr/$PHP_LIBDIR
            pdo_odbc_def_incdir=/usr/include
            pdo_odbc_def_lib=odbcsdk
            ;;

        generic)
            pdo_odbc_def_lib="`echo $PHP_SWOOLE_ODBC | cut -d, -f3`"
            pdo_odbc_def_ldflags="`echo $PHP_SWOOLE_ODBC | cut -d, -f4`"
            pdo_odbc_def_cflags="`echo $PHP_SWOOLE_ODBC | cut -d, -f5`"
            pdo_odbc_flavour="generic-$pdo_odbc_def_lib"
            ;;

          *)
            AC_MSG_ERROR([Unknown ODBC flavour $pdo_odbc_flavour]PDO_ODBC_HELP_TEXT)
            ;;
      esac

      if test -n "$pdo_odbc_dir"; then
        PDO_ODBC_INCDIR="$pdo_odbc_dir/include"
        PDO_ODBC_LIBDIR="$pdo_odbc_dir/$PHP_LIBDIR"
      else
        PDO_ODBC_INCDIR="$pdo_odbc_def_incdir"
        PDO_ODBC_LIBDIR="$pdo_odbc_def_libdir"
      fi

      AC_MSG_RESULT([$pdo_odbc_flavour
              libs       $PDO_ODBC_LIBDIR,
              headers    $PDO_ODBC_INCDIR])

      if test ! -d "$PDO_ODBC_LIBDIR" ; then
        AC_MSG_WARN([library dir $PDO_ODBC_LIBDIR does not exist])
      fi

      PDO_ODBC_CHECK_HEADER(odbc.h)
      PDO_ODBC_CHECK_HEADER(odbcsdk.h)
      PDO_ODBC_CHECK_HEADER(iodbc.h)
      PDO_ODBC_CHECK_HEADER(sqlunix.h)
      PDO_ODBC_CHECK_HEADER(sqltypes.h)
      PDO_ODBC_CHECK_HEADER(sqlucode.h)
      PDO_ODBC_CHECK_HEADER(sql.h)
      PDO_ODBC_CHECK_HEADER(isql.h)
      PDO_ODBC_CHECK_HEADER(sqlext.h)
      PDO_ODBC_CHECK_HEADER(isqlext.h)
      PDO_ODBC_CHECK_HEADER(udbcext.h)
      PDO_ODBC_CHECK_HEADER(sqlcli1.h)
      PDO_ODBC_CHECK_HEADER(LibraryManager.h)
      PDO_ODBC_CHECK_HEADER(cli0core.h)
      PDO_ODBC_CHECK_HEADER(cli0ext.h)
      PDO_ODBC_CHECK_HEADER(cli0cli.h)
      PDO_ODBC_CHECK_HEADER(cli0defs.h)
      PDO_ODBC_CHECK_HEADER(cli0env.h)

      if test "$php_pdo_have_header" != "yes"; then
        AC_MSG_ERROR([Cannot find header file(s) for pdo_odbc])
      fi

      PDO_ODBC_INCLUDE="$pdo_odbc_def_cflags -I$PDO_ODBC_INCDIR -DPDO_ODBC_TYPE=\\\"$pdo_odbc_flavour\\\""
      PDO_ODBC_LDFLAGS="$pdo_odbc_def_ldflags -L$PDO_ODBC_LIBDIR -l$pdo_odbc_def_lib"

      PHP_EVAL_LIBLINE([$PDO_ODBC_LDFLAGS], [SWOOLE_SHARED_LIBADD])

      EXTRA_CFLAGS="$EXTRA_CFLAGS -I$pdo_cv_inc_path $PDO_ODBC_INCLUDE"

      dnl Check first for an ODBC 1.0 function to assert that the libraries work
      PHP_CHECK_LIBRARY($pdo_odbc_def_lib, SQLBindCol,
      [
        dnl And now check for an ODBC 3.0 function to assert that they are *good*
        dnl libraries.
        PHP_CHECK_LIBRARY($pdo_odbc_def_lib, SQLAllocHandle,
        [], [
          AC_MSG_ERROR([
    Your ODBC library does not appear to be ODBC 3 compatible.
    You should consider using iODBC or unixODBC instead, and loading your
    libraries as a driver in that environment; it will emulate the
    functions required for PDO support.
    ])], $PDO_ODBC_LDFLAGS)
      ],[
        AC_MSG_ERROR([Your ODBC library does not exist or there was an error. Check config.log for more information])
      ], $PDO_ODBC_LDFLAGS)

        AC_DEFINE(SW_USE_ODBC, 1, [do we enable swoole-odbc coro support])
    fi

    dnl odbc end

    dnl SWOOLE_ORACLE start
    if test -z "$SED"; then
        SWOOLE_PDO_OCI_SED="sed";
    else
        SWOOLE_PDO_OCI_SED="$SED";
    fi

    SWOOLE_PDO_OCI_TAIL1=`echo a | tail -n1 2>/dev/null`
    if test "$SWOOLE_PDO_OCI_TAIL1" = "a"; then
        SWOOLE_PDO_OCI_TAIL1="tail -n1"
    else
        SWOOLE_PDO_OCI_TAIL1="tail -1"
    fi

    AC_DEFUN([AC_PDO_OCI_VERSION],[
        AC_MSG_CHECKING([Oracle version])
        PDO_OCI_LCS_BASE=$PDO_OCI_LIB_DIR/libclntsh.$SHLIB_SUFFIX_NAME
        dnl Oracle 10g, 11g, 12c etc
        PDO_OCI_LCS=`ls $PDO_OCI_LCS_BASE.*.1 2> /dev/null | $SWOOLE_PDO_OCI_TAIL1`
        if test -f "$PDO_OCI_LCS"; then
            dnl Oracle 10g, 11g 12c etc. The x.2 version libraries are named x.1 for
            dnl drop in compatibility
            PDO_OCI_VERSION=`echo $PDO_OCI_LCS | $SWOOLE_PDO_OCI_SED -e 's/.*\.\(.*\)\.1$/\1.1/'`
        elif test -f $PDO_OCI_LCS_BASE.9.0; then
            dnl There is no case for Oracle 9.2. Oracle 9.2 libraries have a 9.0 suffix
            dnl for drop-in compatibility with Oracle 9.0
            PDO_OCI_VERSION=9.0
        else
            AC_MSG_ERROR(Oracle libclntsh.$SHLIB_SUFFIX_NAME client library not found or its version is lower than 9)
        fi
        AC_MSG_RESULT($PDO_OCI_VERSION)
    ])

    AC_DEFUN([AC_PDO_OCI_CHECK_LIB_DIR],[
        AC_CHECK_SIZEOF([long])
        AC_MSG_CHECKING([if we're at 64-bit platform])
        AS_IF([test "$ac_cv_sizeof_long" -eq 4],[
            AC_MSG_RESULT([no])
            TMP_PDO_OCI_LIB_DIR="$PDO_OCI_DIR/lib32"
        ],[
            AC_MSG_RESULT([yes])
            TMP_PDO_OCI_LIB_DIR="$PDO_OCI_DIR/lib"
        ])

        AC_MSG_CHECKING([OCI8 libraries dir])
        if test -d "$PDO_OCI_DIR/lib" && test ! -d "$PDO_OCI_DIR/lib32"; then
            PDO_OCI_LIB_DIR="$PDO_OCI_DIR/lib"
        elif test ! -d "$PDO_OCI_DIR/lib" && test -d "$PDO_OCI_DIR/lib32"; then
            PDO_OCI_LIB_DIR="$PDO_OCI_DIR/lib32"
        elif test -d "$PDO_OCI_DIR/lib" && test -d "$PDO_OCI_DIR/lib32"; then
            PDO_OCI_LIB_DIR=$TMP_PDO_OCI_LIB_DIR
        else
            AC_MSG_ERROR([Oracle required OCI8 libraries not found])
        fi
        AC_MSG_RESULT($PDO_OCI_LIB_DIR)
    ])

    PHP_ARG_WITH([swoole-oracle],
        [whether to enable oracle build flags],
        [AS_HELP_STRING([[--with-swoole-oracle[=DIR]]],
            [PDO: Oracle OCI support. DIR defaults to $ORACLE_HOME. Use
            --with-swoole-oracle=instantclient,/path/to/instant/client/lib for an Oracle
            Instant Client installation.])], [no], [no])

    if test "$PHP_SWOOLE_ORACLE" != "no"; then
        if test "$PHP_PDO" = "no" && test "$ext_shared" = "no"; then
            AC_MSG_ERROR([PDO is not enabled! Add --enable-pdo to your configure line.])
        fi

        AC_MSG_CHECKING([Oracle Install-Dir])
        if test "$PHP_SWOOLE_ORACLE" = "yes" || test -z "$PHP_SWOOLE_ORACLE"; then
            PDO_OCI_DIR=$ORACLE_HOME
        else
            PDO_OCI_DIR=$PHP_SWOOLE_ORACLE
        fi
        AC_MSG_RESULT($PHP_SWOOLE_ORACLE)

        AC_MSG_CHECKING([if that is sane])
        if test -z "$PDO_OCI_DIR"; then
            AC_MSG_ERROR([You need to tell me where to find your Oracle Instant Client SDK, or set ORACLE_HOME.])
        else
            AC_MSG_RESULT([yes])
        fi

        if test "instantclient" = "`echo $PDO_OCI_DIR | cut -d, -f1`" ; then
            AC_CHECK_SIZEOF([long])
            AC_MSG_CHECKING([if we're at 64-bit platform])
            AS_IF([test "$ac_cv_sizeof_long" -eq 4],[
                AC_MSG_RESULT([no])
                PDO_OCI_CLIENT_DIR="client"
            ],[
                AC_MSG_RESULT([yes])
                PDO_OCI_CLIENT_DIR="client64"
            ])

            PDO_OCI_LIB_DIR="`echo $PDO_OCI_DIR | cut -d, -f2`"
            AC_PDO_OCI_VERSION($PDO_OCI_LIB_DIR)

            AC_MSG_CHECKING([for oci.h])
            dnl Header directory for Instant Client SDK RPM install
            OCISDKRPMINC=`echo "$PDO_OCI_LIB_DIR" | $SWOOLE_PDO_OCI_SED -e 's!^\(.*\)/lib/oracle/\(.*\)/\('${PDO_OCI_CLIENT_DIR}'\)/lib[/]*$!\1/include/oracle/\2/\3!'`

            dnl Header directory for manual installation
            OCISDKMANINC=`echo "$PDO_OCI_LIB_DIR" | $SWOOLE_PDO_OCI_SED -e 's!^\(.*\)/lib[/]*$!\1/include!'`

            dnl Header directory for Instant Client SDK zip file install
            OCISDKZIPINC=$PDO_OCI_LIB_DIR/sdk/include

            if test -f "$OCISDKRPMINC/oci.h" ; then
                PHP_ADD_INCLUDE($OCISDKRPMINC)
                AC_MSG_RESULT($OCISDKRPMINC)
            elif test -f "$OCISDKMANINC/oci.h" ; then
                PHP_ADD_INCLUDE($OCISDKMANINC)
                AC_MSG_RESULT($OCISDKMANINC)
            elif test -f "$OCISDKZIPINC/oci.h" ; then
                PHP_ADD_INCLUDE($OCISDKZIPINC)
                AC_MSG_RESULT($OCISDKZIPINC)
            else
                AC_MSG_ERROR([I'm too dumb to figure out where the include dir is in your Instant Client install])
            fi
        else
            AC_PDO_OCI_CHECK_LIB_DIR($PDO_OCI_DIR)

            if test -d "$PDO_OCI_DIR/rdbms/public"; then
                PHP_ADD_INCLUDE($PDO_OCI_DIR/rdbms/public)
                PDO_OCI_INCLUDES="$PDO_OCI_INCLUDES -I$PDO_OCI_DIR/rdbms/public"
            fi
            if test -d "$PDO_OCI_DIR/rdbms/demo"; then
                PHP_ADD_INCLUDE($PDO_OCI_DIR/rdbms/demo)
                PDO_OCI_INCLUDES="$PDO_OCI_INCLUDES -I$PDO_OCI_DIR/rdbms/demo"
            fi
            if test -d "$PDO_OCI_DIR/network/public"; then
                PHP_ADD_INCLUDE($PDO_OCI_DIR/network/public)
                PDO_OCI_INCLUDES="$PDO_OCI_INCLUDES -I$PDO_OCI_DIR/network/public"
            fi
            if test -d "$PDO_OCI_DIR/plsql/public"; then
                PHP_ADD_INCLUDE($PDO_OCI_DIR/plsql/public)
                PDO_OCI_INCLUDES="$PDO_OCI_INCLUDES -I$PDO_OCI_DIR/plsql/public"
            fi
            if test -d "$PDO_OCI_DIR/include"; then
                PHP_ADD_INCLUDE($PDO_OCI_DIR/include)
                PDO_OCI_INCLUDES="$PDO_OCI_INCLUDES -I$PDO_OCI_DIR/include"
            fi

            if test -f "$PDO_OCI_LIB_DIR/sysliblist"; then
                PHP_EVAL_LIBLINE(`cat $PDO_OCI_LIB_DIR/sysliblist`, SWOOLE_SHARED_LIBADD)
            elif test -f "$PDO_OCI_DIR/rdbms/lib/sysliblist"; then
                PHP_EVAL_LIBLINE(`cat $PDO_OCI_DIR/rdbms/lib/sysliblist`, SWOOLE_SHARED_LIBADD)
            fi
            AC_PDO_OCI_VERSION($PDO_OCI_LIB_DIR)
        fi

        case $PDO_OCI_VERSION in
            7.3|8.0|8.1)
                AC_MSG_ERROR([Oracle client libraries < 9 are not supported])
                ;;
        esac

        PHP_ADD_LIBRARY(clntsh, 1, SWOOLE_SHARED_LIBADD)
        PHP_ADD_LIBPATH($PDO_OCI_LIB_DIR, SWOOLE_SHARED_LIBADD)

        PHP_CHECK_LIBRARY(clntsh, OCIEnvCreate,
        [
            AC_DEFINE(HAVE_OCIENVCREATE,1,[ ])
        ], [], [
            -L$PDO_OCI_LIB_DIR $SWOOLE_SHARED_LIBADD
        ])

        PHP_CHECK_LIBRARY(clntsh, OCIEnvNlsCreate,
        [
            AC_DEFINE(HAVE_OCIENVNLSCREATE,1,[ ])
        ], [], [
            -L$PDO_OCI_LIB_DIR $SWOOLE_SHARED_LIBADD
        ])

        dnl Scrollable cursors?
        PHP_CHECK_LIBRARY(clntsh, OCIStmtFetch2,
        [
            AC_DEFINE(HAVE_OCISTMTFETCH2,1,[ ])
        ], [], [
            -L$PDO_OCI_LIB_DIR $SWOOLE_SHARED_LIBADD
        ])

        dnl Can handle bytes vs. characters?
        PHP_CHECK_LIBRARY(clntsh, OCILobRead2,
        [
           AC_DEFINE(HAVE_OCILOBREAD2,1,[ ])
        ], [], [
           -L$PDO_OCI_LIB_DIR $SWOOLE_SHARED_LIBADD
        ])

        EXTRA_CFLAGS="$EXTRA_CFLAGS -I$pdo_cv_inc_path $PDO_OCI_INCLUDE"
        PHP_CHECK_PDO_INCLUDES
        AC_DEFINE_UNQUOTED(SWOOLE_PDO_OCI_CLIENT_VERSION, "$PDO_OCI_VERSION", [ ])
        AC_DEFINE(SW_USE_ORACLE, 1, [do we enable oracle coro support])
    fi
    dnl SWOOLE_ORACLE stop

    dnl sqlite start
    PHP_ARG_ENABLE([swoole-sqlite],
        [for sqlite 3 support for PDO],
        [AS_HELP_STRING([--enable-swoole-sqlite],
            [PDO: sqlite 3 support.])], [no], [no])

    if test "$PHP_SWOOLE_SQLITE" != "no"; then

        if test "$PHP_PDO" = "no" && test "$ext_shared" = "no"; then
            AC_MSG_ERROR([PDO is not enabled! Add --enable-pdo to your configure line.])
        fi

        PHP_CHECK_PDO_INCLUDES

        PKG_CHECK_MODULES([SQLITE], [sqlite3 >= 3.7.7])

        PHP_EVAL_INCLINE($SQLITE_CFLAGS)
        PHP_EVAL_LIBLINE($SQLITE_LIBS, SWOOLE_SHARED_LIBADD)
        AC_DEFINE(HAVE_SW_PDO_SQLITELIB, 1, [Define to 1 if you have the pdo_sqlite extension enabled.])

        PHP_CHECK_LIBRARY(sqlite3, sqlite3_close_v2, [
            AC_DEFINE(HAVE_SW_SQLITE3_CLOSE_V2, 1, [have sqlite3_close_v2])
        ], [], [$SWOOLE_SHARED_LIBADD])

        PHP_CHECK_LIBRARY(sqlite3, sqlite3_column_table_name, [
            AC_DEFINE(HAVE_SW_SQLITE3_COLUMN_TABLE_NAME, 1, [have sqlite3_column_table_name])
        ], [], [$SWOOLE_SHARED_LIBADD])

        AC_DEFINE(SW_USE_SQLITE, 1, [do we enable sqlite coro support])
    fi
    dnl sqlite stop

    AC_CHECK_LIB(z, gzgets, [
        AC_DEFINE(SW_HAVE_ZLIB, 1, [have zlib])
        PHP_ADD_LIBRARY(z, 1, SWOOLE_SHARED_LIBADD)
    ])

    if test "$PHP_BROTLI_DIR" != "no"; then
        AC_DEFINE(SW_HAVE_BROTLI, 1, [have brotli])
        PHP_ADD_INCLUDE("${PHP_BROTLI_DIR}/include")
        PHP_ADD_LIBRARY_WITH_PATH(brotlienc, "${PHP_BROTLI_DIR}/${PHP_LIBDIR}")
        PHP_ADD_LIBRARY_WITH_PATH(brotlidec, "${PHP_BROTLI_DIR}/${PHP_LIBDIR}")
    elif test "$PHP_BROTLI" = "yes"; then
        PKG_CHECK_MODULES([BROTLIENC], [libbrotlienc])
        PKG_CHECK_MODULES([BROTLIDEC], [libbrotlidec])
        AC_DEFINE(SW_HAVE_BROTLI, 1, [have brotli])
        PHP_EVAL_LIBLINE($BROTLIENC_LIBS, SWOOLE_SHARED_LIBADD)
        PHP_EVAL_INCLINE($BROTLIENC_CFLAGS)
        PHP_EVAL_LIBLINE($BROTLIDEC_LIBS, SWOOLE_SHARED_LIBADD)
        PHP_EVAL_INCLINE($BROTLIDEC_CFLAGS)
    elif test "$PHP_BROTLI" = "auto"; then
        PKG_CHECK_MODULES([BROTLIENC], [libbrotlienc], [found_brotlienc=yes], [found_brotlienc=no])
        if test "$found_brotlienc" = "yes"; then
            AC_DEFINE(SW_HAVE_BROTLI, 1, [have brotli])
            PHP_EVAL_LIBLINE($BROTLIENC_LIBS, SWOOLE_SHARED_LIBADD)
            PHP_EVAL_INCLINE($BROTLIENC_CFLAGS)
        fi

        PKG_CHECK_MODULES([BROTLIDEC], [libbrotlidec], [found_brotlidec=yes], [found_brotlidec=no])
        if test "$found_brotlidec" = "yes"; then
            AC_DEFINE(SW_HAVE_BROTLI, 1, [have brotli])
            PHP_EVAL_LIBLINE($BROTLIDEC_LIBS, SWOOLE_SHARED_LIBADD)
            PHP_EVAL_INCLINE($BROTLIDEC_CFLAGS)
        fi
    fi

    if test "$PHP_ZSTD" = "yes"; then
        PKG_CHECK_MODULES([ZSTD], [libzstd >= 1.4.0])
        AC_DEFINE(SW_HAVE_ZSTD, 1, [have zstd])
        PHP_EVAL_LIBLINE($ZSTD_LIBS, SWOOLE_SHARED_LIBADD)
        PHP_EVAL_INCLINE($ZSTD_CFLAGS)
    fi

    PHP_ADD_LIBRARY(pthread)
    PHP_SUBST(SWOOLE_SHARED_LIBADD)

    AC_ARG_ENABLE(debug,
        [  --enable-debug          Compile with debug symbols],
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

    if test "$PHP_TRACE_LOG" != "no"; then
        AC_DEFINE(SW_LOG_TRACE_OPEN, 1, [enable trace log])
    fi

    if test "$PHP_SWOOLE_THREAD" != "no"; then
        AC_DEFINE(SW_THREAD, 1, [enable swoole thread support])
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

    if test "$PHP_CARES" = "yes"; then
        PKG_CHECK_MODULES([CARES], [libcares])
        PHP_EVAL_LIBLINE($CARES_LIBS, SWOOLE_SHARED_LIBADD)
        PHP_EVAL_INCLINE($CARES_CFLAGS)
        AC_DEFINE(SW_USE_CARES, 1, [do we enable c-ares support])
        AC_DEFINE(HAVE_CARES, 1, [have c-ares])
    fi

    AC_SWOOLE_CPU_AFFINITY
    AC_SWOOLE_HAVE_REUSEPORT
    AC_SWOOLE_HAVE_FUTEX
    AC_SWOOLE_HAVE_UCONTEXT
    AC_SWOOLE_HAVE_VALGRIND
    AC_SWOOLE_CHECK_SOCKETS
    AC_SWOOLE_HAVE_BOOST_STACKTRACE

    AS_CASE([$host_os],
      [darwin*], [SW_OS="MAC"],
      [cygwin*], [SW_OS="CYGWIN"],
      [mingw*], [SW_OS="MINGW"],
      [linux*], [SW_OS="LINUX"],
      [*bsd*], [SW_OS="BSD"],
      []
    )

    CFLAGS="-Wall -pthread $CFLAGS"
    LDFLAGS="$LDFLAGS -lpthread"

    dnl Check should we link to librt

    if test "$PHP_IOURING" = "yes" && test "$SW_OS" = "LINUX"; then
        PKG_CHECK_MODULES([URING], [liburing >= 2.5])
        PHP_EVAL_LIBLINE($URING_LIBS, SWOOLE_SHARED_LIBADD)
        PHP_EVAL_INCLINE($URING_CFLAGS)
        AC_DEFINE(SW_USE_IOURING, 1, [have io_uring])

        LINUX_VERSION=`uname -r | cut -d '-' -f 1`
        LINUX_MAJOR_VERSION=`echo $LINUX_VERSION | cut -d '.' -f 1`
        LINUX_MINOR_VERSION=`echo $LINUX_VERSION | cut -d '.' -f 2`

        _PKG_CONFIG(URING_VERSION, [modversion], [liburing])
        IOURING_MAJOR_VERSION=`echo $pkg_cv_URING_VERSION | cut -d '.' -f 1`
        IOURING_MINOR_VERSION=`echo $pkg_cv_URING_VERSION | cut -d '.' -f 2`

        AC_MSG_CHECKING([checking for io_uring futex feature])
        if test $IOURING_MAJOR_VERSION -gt 2 || (test $IOURING_MAJOR_VERSION -eq 2 && test $IOURING_MINOR_VERSION -ge 6); then
            if test $LINUX_MAJOR_VERSION -gt 6 || (test $LINUX_MAJOR_VERSION -eq 6 && test $LINUX_MINOR_VERSION -ge 7); then
                AC_MSG_RESULT(yes)
                AC_DEFINE(HAVE_IOURING_FUTEX, 1, [have io_uring futex feature])
            else
                AC_MSG_RESULT([no, Linux $LINUX_VERSION is too old])
            fi
        else
            AC_MSG_RESULT([no, liburing $IOURING_MAJOR_VERSION.$IOURING_MINOR_VERSION is too old])
        fi
    fi

    if test "$SW_OS" = "LINUX"; then
        GLIBC_VERSION=$(getconf GNU_LIBC_VERSION | awk '{print $2}')
        AC_MSG_NOTICE([glibc version: $GLIBC_VERSION])

        GLIBC_MAJOR_VERSION=$(getconf GNU_LIBC_VERSION | awk '{print $2}' | cut -d '.' -f 1)
        GLIBC_MINOR_VERSION=$(getconf GNU_LIBC_VERSION | awk '{print $2}' | cut -d '.' -f 2)

        if test $GLIBC_MAJOR_VERSION -lt 2 || (test $GLIBC_MAJOR_VERSION -eq 2 && test $GLIBC_MINOR_VERSION -lt 17); then
            OS_SHOULD_HAVE_LIBRT=1
        else
            AC_MSG_NOTICE([link with -lrt (only for glibc version before 2.17)])
            OS_SHOULD_HAVE_LIBRT=0
        fi
    elif test "$SW_OS" = "MAC"; then
        OS_SHOULD_HAVE_LIBRT=0
    else
        AS_CASE([$host_os],
          [openbsd*], [OS_SHOULD_HAVE_LIBRT=0]
          [OS_SHOULD_HAVE_LIBRT=1]
        )
    fi

    if test "x$OS_SHOULD_HAVE_LIBRT" = "x1"; then
        AC_MSG_NOTICE([Librt is required on $host_os.])
        dnl Check for the existence of librt
        AC_CHECK_LIB([rt], [clock_gettime], [], [
            AC_MSG_ERROR([We have to link to librt on your os, but librt not found.])
        ])
        PHP_ADD_LIBRARY(rt, 1, SWOOLE_SHARED_LIBADD)
    else
        AC_MSG_NOTICE([$host_os doesn't have librt -- don't link to librt.])
    fi

    if test "$SW_OS" = "LINUX"; then
        LDFLAGS="$LDFLAGS -z now"
    fi

    if test "$PHP_OPENSSL" != "no" || test "$PHP_OPENSSL_DIR" != "no"; then
        if test "$PHP_OPENSSL_DIR" != "no"; then
            PHP_ADD_INCLUDE("${PHP_OPENSSL_DIR}/include")
            PHP_ADD_LIBRARY_WITH_PATH(ssl, "${PHP_OPENSSL_DIR}/${PHP_LIBDIR}")

            PHP_ADD_LIBRARY(ssl, 1, SWOOLE_SHARED_LIBADD)
            PHP_ADD_LIBRARY(crypto, 1, SWOOLE_SHARED_LIBADD)
        else
            PKG_CHECK_MODULES([SSL], [libssl])
            PHP_EVAL_LIBLINE($SSL_LIBS, SWOOLE_SHARED_LIBADD)
            PHP_EVAL_INCLINE($SSL_CFLAGS)

            PKG_CHECK_MODULES([CRYPTO], [libcrypto])
            PHP_EVAL_LIBLINE($CRYPTO_LIBS, SWOOLE_SHARED_LIBADD)
            PHP_EVAL_INCLINE($CRYPTO_CFLAGS)
        fi

        AC_DEFINE(SW_USE_OPENSSL, 1, [enable openssl support])
    fi

    if test "$PHP_NGHTTP2_DIR" != "no"; then
        PHP_ADD_INCLUDE("${PHP_NGHTTP2_DIR}/include")
        PHP_ADD_LIBRARY_WITH_PATH(nghttp2, "${PHP_NGHTTP2_DIR}/${PHP_LIBDIR}")
        PHP_ADD_LIBRARY(nghttp2, 1, SWOOLE_SHARED_LIBADD)
    fi

    PHP_ADD_LIBRARY(pthread, 1, SWOOLE_SHARED_LIBADD)

    if test "$PHP_MYSQLND" = "yes"; then
        PHP_ADD_EXTENSION_DEP(mysqli, mysqlnd)
        AC_DEFINE(SW_USE_MYSQLND, 1, [use mysqlnd])
    fi

    AC_MSG_CHECKING([for sources])
    if test -f "$abs_srcdir/ext-src/php_swoole.cc"; then
        swoole_source_dir=$abs_srcdir
    elif test -f "ext-src/php_swoole.cc"; then
        swoole_source_dir=$(pwd)
    else
        swoole_source_dir="ext/swoole"
    fi
    AC_MSG_RESULT([$swoole_source_dir])

    ext_src_files=$(cd $swoole_source_dir && find ext-src/ -name *.cc)
    lib_src_files=$(cd $swoole_source_dir && find src/ -name *.cc)

    swoole_source_file="${ext_src_files} ${lib_src_files}"

    swoole_source_file="$swoole_source_file \
        thirdparty/php/curl/interface.cc \
        thirdparty/php/curl/multi.cc \
        thirdparty/php84/curl/interface.cc \
        thirdparty/php84/curl/multi.cc \
        thirdparty/php/sockets/multicast.cc \
        thirdparty/php/sockets/sendrecvmsg.cc \
        thirdparty/php/sockets/conversions.cc \
        thirdparty/php/sockets/sockaddr_conv.cc \
        thirdparty/php/standard/var_decoder.cc \
        thirdparty/php/standard/proc_open.cc"

    swoole_source_file="$swoole_source_file \
        thirdparty/swoole_http_parser.c \
        thirdparty/multipart_parser.c"

    if test "$PHP_NGHTTP2_DIR" = "no"; then
        swoole_source_file="$swoole_source_file \
            thirdparty/nghttp2/nghttp2_hd.c \
            thirdparty/nghttp2/nghttp2_rcbuf.c \
            thirdparty/nghttp2/nghttp2_helper.c \
            thirdparty/nghttp2/nghttp2_buf.c \
            thirdparty/nghttp2/nghttp2_mem.c \
            thirdparty/nghttp2/nghttp2_hd_huffman.c \
            thirdparty/nghttp2/nghttp2_hd_huffman_data.c"
    fi

    if test -z "$PHP_VERSION"; then
        if test -z "$PHP_CONFIG"; then
            AC_MSG_ERROR([php-config not found])
        fi
        PHP_VERSION=`$PHP_CONFIG --version`
    fi

    PHP_VERSION_ID=`echo "${PHP_VERSION}" | $AWK 'BEGIN { FS = "."; } { printf "%d", ([$]1 * 10 + [$]2); }'`

    if test "$PHP_VERSION_ID" = "82"; then
        PHP_THIRDPARTY_DIR="thirdparty/php81"
    else
        PHP_THIRDPARTY_DIR="thirdparty/php${PHP_VERSION_ID}"
    fi

    if test "$PHP_SWOOLE_PGSQL" != "no"; then
        swoole_source_file="$swoole_source_file \
            ${PHP_THIRDPARTY_DIR}/pdo_pgsql/pgsql_driver.c \
            ${PHP_THIRDPARTY_DIR}/pdo_pgsql/pgsql_statement.c"
        if test "$PHP_VERSION_ID" -ge "84"; then
            swoole_source_file="$swoole_source_file \
                ${PHP_THIRDPARTY_DIR}/pdo_pgsql/pgsql_sql_parser.c"
        fi
    fi

    if test "$PHP_SWOOLE_ORACLE" != "no"; then
        swoole_source_file="$swoole_source_file \
            ${PHP_THIRDPARTY_DIR}/pdo_oci/oci_driver.c \
            ${PHP_THIRDPARTY_DIR}/pdo_oci/oci_statement.c"
    fi

    if test "$PHP_SWOOLE_ODBC" != "no"; then
        swoole_source_file="$swoole_source_file \
            ${PHP_THIRDPARTY_DIR}/pdo_odbc/odbc_driver.c \
            ${PHP_THIRDPARTY_DIR}/pdo_odbc/odbc_stmt.c"
    fi

    if test "$PHP_SWOOLE_SQLITE" != "no"; then
        swoole_source_file="$swoole_source_file \
            ${PHP_THIRDPARTY_DIR}/pdo_sqlite/sqlite_driver.c \
            ${PHP_THIRDPARTY_DIR}/pdo_sqlite/sqlite_statement.c"
        if test "$PHP_VERSION_ID" -ge "84"; then
            swoole_source_file="$swoole_source_file \
                ${PHP_THIRDPARTY_DIR}/pdo_sqlite/sqlite_sql_parser.c"
        fi
    fi

    SW_ASM_DIR="thirdparty/boost/asm/"
    SW_USE_ASM_CONTEXT="yes"

    AS_CASE([$host_cpu],
      [x86_64*], [SW_CPU="x86_64"],
      [amd64*], [SW_CPU="x86_64"],
      [x86*], [SW_CPU="x86"],
      [i?86*], [SW_CPU="x86"],
      [arm64*], [SW_CPU="arm64"],
      [aarch64*], [SW_CPU="arm64"],
      [arm*], [SW_CPU="arm32"],
      [mips64*], [SW_CPU="mips64"],
      [mips*], [SW_CPU="mips32"],
      [riscv64*], [SW_CPU="riscv64"],
      [loongarch64*], [SW_CPU="loongarch64"],
      [
        SW_USE_ASM_CONTEXT="no"
      ]
    )

    if test "$SW_OS" = "MAC"; then
        SW_CONTEXT_ASM_FILE="combined_sysv_macho_gas.S"
    elif test "$SW_CPU" = "x86_64"; then
        if test "$SW_OS" = "LINUX" || test "$SW_OS" = "BSD"; then
            SW_CONTEXT_ASM_FILE="x86_64_sysv_elf_gas.S"
        else
            SW_USE_ASM_CONTEXT="no"
        fi
    elif test "$SW_CPU" = "x86"; then
        if test "$SW_OS" = "LINUX" || test "$SW_OS" = "BSD"; then
            SW_CONTEXT_ASM_FILE="i386_sysv_elf_gas.S"
        else
            SW_USE_ASM_CONTEXT="no"
        fi
    elif test "$SW_CPU" = "arm32"; then
        if test "$SW_OS" = "LINUX" || test "$SW_OS" = "BSD"; then
            SW_CONTEXT_ASM_FILE="arm_aapcs_elf_gas.S"
        else
            SW_USE_ASM_CONTEXT="no"
        fi
    elif test "$SW_CPU" = "arm64"; then
        if test "$SW_OS" = "LINUX" || test "$SW_OS" = "BSD"; then
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
        if test "$SW_OS" = "LINUX" || test "$SW_OS" = "BSD"; then
            SW_CONTEXT_ASM_FILE="ppc64_sysv_elf_gas.S"
        else
            SW_USE_ASM_CONTEXT="no"
        fi
    elif test "$SW_CPU" = "mips64"; then
        if test "$SW_OS" = "LINUX"; then
           SW_CONTEXT_ASM_FILE="mips64_n64_elf_gas.S"
        else
            SW_USE_ASM_CONTEXT="no"
        fi
    elif test "$SW_CPU" = "mips32"; then
        if test "$SW_OS" = "LINUX"; then
           SW_CONTEXT_ASM_FILE="mips32_o32_elf_gas.S"
        else
            SW_USE_ASM_CONTEXT="no"
        fi
    elif test "$SW_CPU" = "riscv64"; then
        if test "$SW_OS" = "LINUX"; then
           SW_CONTEXT_ASM_FILE="riscv64_sysv_elf_gas.S"
        else
            SW_USE_ASM_CONTEXT="no"
        fi
    elif test "$SW_CPU" = "loongarch64"; then
        if test "$SW_OS" = "LINUX"; then
           SW_CONTEXT_ASM_FILE="loongarch64_sysv_elf_gas.S"
        else
            SW_USE_ASM_CONTEXT="no"
        fi
    else
        SW_USE_ASM_CONTEXT="no"
    fi

    if test "$PHP_THREAD_CONTEXT" != "no"; then
        AC_DEFINE(SW_USE_THREAD_CONTEXT, 1, [do we enable thread context])
        SW_USE_ASM_CONTEXT="no"
    fi

    if test "$SW_USE_ASM_CONTEXT" = "yes"; then
        swoole_source_file="$swoole_source_file \
            ${SW_ASM_DIR}make_${SW_CONTEXT_ASM_FILE} \
            ${SW_ASM_DIR}jump_${SW_CONTEXT_ASM_FILE} "
        AC_DEFINE(SW_USE_ASM_CONTEXT, 1, [use boost asm context])
    fi

    EXTRA_CFLAGS="$EXTRA_CFLAGS -DENABLE_PHP_SWOOLE"

    PHP_NEW_EXTENSION(swoole, $swoole_source_file, $ext_shared,, "$EXTRA_CFLAGS", cxx)

    PHP_ADD_INCLUDE([$ext_srcdir])
    PHP_ADD_INCLUDE([$ext_srcdir/include])
    PHP_ADD_INCLUDE([$ext_srcdir/ext-src])
    PHP_ADD_INCLUDE([$ext_srcdir/thirdparty])

    AC_MSG_CHECKING([swoole coverage])
    if test "$PHP_SWOOLE_COVERAGE" != "no"; then
        AC_MSG_RESULT([enabled])

        PHP_ADD_MAKEFILE_FRAGMENT
    else
        AC_MSG_RESULT([disabled])
    fi

    PHP_INSTALL_HEADERS([ext/swoole], [ext-src/*.h config.h php_swoole.h \
        include/*.h \
        stubs/*.h \
        thirdparty/*.h \
        thirdparty/nghttp2/*.h])

    PHP_REQUIRE_CXX()

    CXXFLAGS="$CXXFLAGS -Wall -Wno-unused-function -Wno-deprecated -Wno-deprecated-declarations"

    if test "$SW_OS" = "CYGWIN" || test "$SW_OS" = "MINGW"; then
        CXXFLAGS="$CXXFLAGS -std=gnu++11"
    else
        CXXFLAGS="$CXXFLAGS -std=c++11"
    fi

    if test "$SW_CPU" = "arm"; then
        PHP_ADD_LIBRARY(atomic, 1, SWOOLE_SHARED_LIBADD)
    fi

    PHP_ADD_BUILD_DIR($ext_builddir/ext-src)
    PHP_ADD_BUILD_DIR($ext_builddir/src/core)
    PHP_ADD_BUILD_DIR($ext_builddir/src/memory)
    PHP_ADD_BUILD_DIR($ext_builddir/src/reactor)
    PHP_ADD_BUILD_DIR($ext_builddir/src/lock)
    PHP_ADD_BUILD_DIR($ext_builddir/src/os)
    PHP_ADD_BUILD_DIR($ext_builddir/src/network)
    PHP_ADD_BUILD_DIR($ext_builddir/src/server)
    PHP_ADD_BUILD_DIR($ext_builddir/src/protocol)
    PHP_ADD_BUILD_DIR($ext_builddir/src/coroutine)
    PHP_ADD_BUILD_DIR($ext_builddir/src/wrapper)
    PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/boost)
    PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/boost/asm)
    PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/php/sockets)
    PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/php/standard)
    PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/php/curl)
    PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/php84/curl)
    if test "$PHP_NGHTTP2_DIR" = "no"; then
        PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/nghttp2)
    fi
    if test "$PHP_SWOOLE_PGSQL" != "no"; then
        PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/php81/pdo_pgsql)
        PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/php83/pdo_pgsql)
        PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/php84/pdo_pgsql)
    fi
    if test "$PHP_SWOOLE_ODBC" != "no"; then
        PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/php81/pdo_odbc)
        PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/php83/pdo_odbc)
        PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/php84/pdo_odbc)
    fi
    if test "$PHP_SWOOLE_ORACLE" != "no"; then
        PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/php81/pdo_oci)
        PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/php83/pdo_oci)
        PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/php84/pdo_oci)
    fi
    if test "$PHP_SWOOLE_SQLITE" != "no"; then
        PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/php81/pdo_sqlite)
        PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/php83/pdo_sqlite)
        PHP_ADD_BUILD_DIR($ext_builddir/thirdparty/php84/pdo_sqlite)
    fi
fi
