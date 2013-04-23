dnl $Id$
dnl config.m4 for extension swoole

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

PHP_ARG_WITH(swoole, for swoole support,
[  --with-swoole             Include swoole support])

dnl Otherwise use enable:

dnl PHP_ARG_ENABLE(swoole, whether to enable swoole support,
dnl Make sure that the comment is aligned:
dnl [  --enable-swoole           Enable swoole support])

if test "$PHP_SWOOLE" != "no"; then
  PHP_ADD_INCLUDE($SWOOLE_DIR/include)
  AC_ARG_ENABLE(debug, 
    [--enable-debug,  compile with debug symbols],
    [PHP_DEBUG = $enableval],
    [PHP_DEBUG = 0]
  )
  PHP_NEW_EXTENSION(swoole, swoole.c \
    src/core/Base.c \
	src/core/RingQueue.c \
    src/factory/Factory.c \
    src/factory/FactoryThread.c \
    src/factory/FactoryProcess.c \
    src/reactor/ReactorBase.c \
    src/reactor/ReactorSelect.c \
	src/reactor/ReactorPoll.c \
    src/reactor/ReactorEpoll.c \
	src/pipe/PipeBase.c \
	src/pipe/PipeEventfd.c \
	src/pipe/PipeUnsock.c \
	src/pipe/PipeMsg.c \
    src/network/Server.c \
  , $ext_shared)
fi
