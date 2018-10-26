PROJECT(libswoole)

ENABLE_LANGUAGE(ASM)
SET(SWOOLE_VERSION 4.2.4)
SET(SWOOLE_CLFLAGS pthread rt dl ssl crypt crypto nghttp2)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

SET(CMAKE_BUILD_TYPE Debug)

file(GLOB_RECURSE SRC_LIST FOLLOW_SYMLINKS src/*.c src/*.cc thirdparty/boost/asm/jump_x86_64_sysv_elf_gas.S thirdparty/boost/asm/make_x86_64_sysv_elf_gas.S)
file(GLOB_RECURSE HEAD_FILES FOLLOW_SYMLINKS include/*.h)

SET(LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/lib)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

#message(STATUS "source=${SRC_LIST}")
#message(STATUS "header=${HEAD_FILES}")

add_definitions(-DHAVE_CONFIG_H)

INCLUDE_DIRECTORIES(BEFORE ./include ./include/wrapper ./ /usr/local/php/include /usr/local/php/include/Zend /usr/local/php/include/main)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

#shared library
add_library(shared SHARED ${SRC_LIST})
set_target_properties(shared PROPERTIES OUTPUT_NAME "swoole" VERSION ${SWOOLE_VERSION})
target_link_libraries(shared ${SWOOLE_CLFLAGS})

#static library
# set_target_properties(static PROPERTIES OUTPUT_NAME "swoole" VERSION ${SWOOLE_VERSION})
# add_library(static STATIC ${SRC_LIST})
# target_link_libraries(static ${SWOOLE_CLFLAGS})

LINK_DIRECTORIES(${LIBRARY_OUTPUT_PATH})

# swoole source
set(SOURCE_FILES
    core-tests/include/tests.h
    examples/server.c
    examples/ssl/client.c
    examples/test_server.c
    include/array.h
    include/asm_context.h
    include/async.h
    include/atomic.h
    include/base64.h
    include/buffer.h
    include/channel.h
    include/client.h
    include/connection.h
    include/context.h
    include/coroutine.h
    include/error.h
    include/file_hook.h
    include/hash.h
    include/hashmap.h
    include/heap.h
    include/helper/kqueue.h
    include/http.h
    include/http2.h
    include/list.h
    include/mqtt.h
    include/rbtree.h
    include/redis.h
    include/ring_queue.h
    include/server.h
    include/sha1.h
    include/socket.h
    include/socket_hook.h
    include/socks5.h
    include/swoole.h
    include/table.h
    include/unix.h
    include/uthash.h
    include/websocket.h
    include/win.h
    php7_wrapper.h
    php_swoole.h
    src/core/array.c
    src/core/base.c
    src/core/channel.c
    src/core/error.cc
    src/core/hashmap.c
    src/core/heap.c
    src/core/list.c
    src/core/log.c
    src/core/rbtree.c
    src/core/ring_queue.c
    src/core/socket.c
    src/core/string.c
    src/coroutine/base.cc
    src/coroutine/boost.cc
    src/coroutine/channel.cc
    src/coroutine/context.cc
    src/coroutine/hook.cc
    src/coroutine/socket.cc
    src/coroutine/ucontext.cc
    src/factory/base.c
    src/factory/process.c
    src/lock/atomic.c
    src/lock/cond.c
    src/lock/file_lock.c
    src/lock/mutex.c
    src/lock/rw_lock.c
    src/lock/semaphore.c
    src/lock/spin_lock.c
    src/memory/buffer.c
    src/memory/fixed_pool.c
    src/memory/global_memory.c
    src/memory/malloc.c
    src/memory/ring_buffer.c
    src/memory/shared_memory.c
    src/memory/table.c
    src/network/client.c
    src/network/connection.c
    src/network/dns.c
    src/network/manager.c
    src/network/port.c
    src/network/process_pool.c
    src/network/reactor_process.c
    src/network/reactor_thread.c
    src/network/server.c
    src/network/stream.c
    src/network/task_worker.c
    src/network/thread_pool.c
    src/network/timer.c
    src/network/worker.c
    src/os/base.c
    src/os/msg_queue.c
    src/os/sendfile.c
    src/os/signal.c
    src/os/timer.c
    src/pipe/base.c
    src/pipe/eventfd.c
    src/pipe/unix_socket.c
    src/protocol/base.c
    src/protocol/base64.c
    src/protocol/http.c
    src/protocol/http2.c
    src/protocol/mime_types.cc
    src/protocol/mqtt.c
    src/protocol/redis.c
    src/protocol/sha1.c
    src/protocol/socks5.c
    src/protocol/ssl.c
    src/protocol/websocket.c
    src/reactor/base.c
    src/reactor/epoll.c
    src/reactor/kqueue.c
    src/reactor/poll.c
    src/reactor/select.c
    swoole.c
    swoole_async.c
    swoole_atomic.c
    swoole_buffer.c
    swoole_channel.c
    swoole_channel_coro.cc
    swoole_client.c
    swoole_client_coro.cc
    swoole_config.h
    swoole_coroutine.cc
    swoole_coroutine.h
    swoole_coroutine_util.c
    swoole_event.c
    swoole_http.h
    swoole_http_client.c
    swoole_http_client.h
    swoole_http_client_coro.cc
    swoole_http_server.c
    swoole_http_v2_client.c
    swoole_http_v2_client.h
    swoole_http_v2_client_coro.c
    swoole_http_v2_server.cc
    swoole_lock.c
    swoole_memory_pool.c
    swoole_mmap.c
    swoole_msgqueue.c
    swoole_mysql.c
    swoole_mysql.h
    swoole_mysql_coro.cc
    swoole_postgresql_coro.c
    swoole_postgresql_coro.h
    swoole_process.c
    swoole_process_pool.c
    swoole_redis.c
    swoole_redis_coro.c
    swoole_redis_server.c
    swoole_ringqueue.c
    swoole_runtime.cc
    swoole_serialize.c
    swoole_serialize.h
    swoole_server.c
    swoole_server_port.c
    swoole_socket_coro.cc
    swoole_table.c
    swoole_timer.c
    swoole_trace.c
    swoole_websocket_server.c
    thirdparty/multipart_parser.c
    thirdparty/multipart_parser.h
    thirdparty/php_streams_int.h
    thirdparty/plain_wrapper.c
    thirdparty/swoole_http_parser.c
    thirdparty/swoole_http_parser.h
)
add_executable(swoole ${SOURCE_FILES})

#install
INSTALL(CODE "MESSAGE(\"Are you run command using root user?\")")
INSTALL(TARGETS shared LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)
INSTALL(FILES ${HEAD_FILES} DESTINATION include/swoole)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/swoole_config.h DESTINATION include/swoole)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/config.h DESTINATION include/swoole)

# php source
set(PHP_SOURCE /usr/local/php-src)
include_directories(${PHP_SOURCE}/main)
include_directories(${PHP_SOURCE}/Zend)
include_directories(${PHP_SOURCE}/sapi)
include_directories(${PHP_SOURCE}/pear)
include_directories(${PHP_SOURCE}/TSRM)
include_directories(${PHP_SOURCE})