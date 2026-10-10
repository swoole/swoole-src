<?php

function run_socket_hook_comparison(callable $test): void
{
    $originalFlags = Swoole\Runtime::getHookFlags();
    try {
        foreach ([0, SWOOLE_HOOK_SOCKETS] as $flags) {
            Swoole\Runtime::enableCoroutine($flags);
            Swoole\Coroutine\run(function () use ($test, $flags) {
                $domain = PHP_OS_FAMILY === 'Windows' ? AF_INET : AF_UNIX;
                if (!socket_create_pair($domain, SOCK_STREAM, 0, $pair)) {
                    throw new RuntimeException('Cannot create socket pair');
                }
                if (($pair[0] instanceof Swoole\Coroutine\Socket) !== ($flags !== 0)) {
                    throw new RuntimeException('Wrong sockets implementation');
                }
                try {
                    foreach ($pair as $socket) {
                        socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 1, 'usec' => 0]);
                    }
                    $test($pair[0], $pair[1]);
                } finally {
                    foreach ($pair as $socket) {
                        socket_close($socket);
                    }
                }
            });
        }
    } finally {
        Swoole\Runtime::enableCoroutine($originalFlags);
    }
}
