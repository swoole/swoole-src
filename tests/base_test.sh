#!/usr/bin/env bash
./start.sh \
$@ \
swoole_atomic \
swoole_buffer \
swoole_event \
swoole_function \
swoole_global \
swoole_lock \
swoole_memory_pool \
swoole_process \
swoole_process_pool \
swoole_table \
\
swoole_coroutine \
swoole_coroutine_util \
swoole_coroutine_channel \
swoole_client_coro \
swoole_http_client_coro \
swoole_http2_client_coro \
swoole_http_server \
swoole_mysql_coro \
swoole_redis_coro \
swoole_redis_server \
swoole_socket_coro \
swoole_runtime
