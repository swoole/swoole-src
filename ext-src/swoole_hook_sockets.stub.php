<?php

function swoole_native_socket_create_listen(int $port, int $backlog = 128): Swoole\Coroutine\Socket |false {}

function swoole_native_socket_accept(Swoole\Coroutine\Socket $socket): Swoole\Coroutine\Socket |false {}

function swoole_native_socket_set_nonblock(Swoole\Coroutine\Socket $socket): bool {}

function swoole_native_socket_set_block(Swoole\Coroutine\Socket $socket): bool {}

function swoole_native_socket_listen(Swoole\Coroutine\Socket $socket, int $backlog = 0): bool {}

function swoole_native_socket_close(Swoole\Coroutine\Socket $socket): void {}

function swoole_native_socket_write(Swoole\Coroutine\Socket $socket, string $data, ?int $length = null): int|false {}

function swoole_native_socket_read(Swoole\Coroutine\Socket $socket, int $length, int $mode = PHP_BINARY_READ): string|false {}

/**
 * @param string $address
 * @param int $port
 */
function swoole_native_socket_getsockname(Swoole\Coroutine\Socket $socket, &$address, &$port = null): bool {}

/**
 * @param string $address
 * @param int $port
 */
function swoole_native_socket_getpeername(Swoole\Coroutine\Socket $socket, &$address, &$port = null): bool {}

function swoole_native_socket_create(int $domain, int $type, int $protocol): Swoole\Coroutine\Socket |false {}

function swoole_native_socket_connect(Swoole\Coroutine\Socket $socket, string $address, ?int $port = null): bool {}

function swoole_native_socket_strerror(int $error_code): string {}

function swoole_native_socket_bind(Swoole\Coroutine\Socket $socket, string $address, int $port = 0): bool {}

/** @param string|null $data */
function swoole_native_socket_recv(Swoole\Coroutine\Socket $socket, &$data, int $length, int $flags): int|false {}

function swoole_native_socket_send(Swoole\Coroutine\Socket $socket, string $data, int $length, int $flags): int|false {}

/**
 * @param string $data
 * @param string $address
 * @param int $port
 */
function swoole_native_socket_recvfrom(Swoole\Coroutine\Socket $socket, &$data, int $length, int $flags, &$address, &$port = null): int|false {}

function swoole_native_socket_sendto(Swoole\Coroutine\Socket $socket, string $data, int $length, int $flags, string $address, ?int $port = null): int|false {}

function swoole_native_socket_get_option(Swoole\Coroutine\Socket $socket, int $level, int $option): array|int|false {}

/** @alias socket_get_option */
function swoole_native_socket_getopt(Swoole\Coroutine\Socket $socket, int $level, int $option): array|int|false {}

/** @param array|string|int $value */
function swoole_native_socket_set_option(Swoole\Coroutine\Socket $socket, int $level, int $option, $value): bool {}

/**
 * @param array|string|int $value
 * @alias socket_set_option
 */
function swoole_native_socket_setopt(Swoole\Coroutine\Socket $socket, int $level, int $option, $value): bool {}

#ifdef HAVE_SOCKETPAIR
/** @param array $pair */
function swoole_native_socket_create_pair(int $domain, int $type, int $protocol, &$pair): ?bool {}
#endif

#ifdef HAVE_SHUTDOWN
function swoole_native_socket_shutdown(Swoole\Coroutine\Socket $socket, int $mode = 2): bool {}
#endif

function swoole_native_socket_last_error(?Swoole\Coroutine\Socket $socket = null): int {}

function swoole_native_socket_clear_error(?Swoole\Coroutine\Socket $socket = null): void {}









