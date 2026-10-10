--TEST--
swoole_socket_coro: exporting SSL sockets and imported SSL streams is rejected
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
skip_if_extension_not_exist('openssl');
?>
--FILE--
<?php
use Swoole\Coroutine\Socket;

Swoole\Runtime::enableCoroutine(0);
Swoole\Coroutine\run(function () {
    $socket = new Socket(AF_INET, SOCK_STREAM, 0);
    $socket->setProtocol(['open_ssl' => true]);
    $warnings = 0;
    set_error_handler(function ($level, $message) use (&$warnings) {
        if (!str_contains($message, 'cannot export an SSL socket')) {
            throw new RuntimeException($message);
        }
        $warnings++;
        return true;
    });
    try {
        if ($socket->export() !== false || $socket->errCode !== SOCKET_EOPNOTSUPP || $socket->isClosed()) {
            throw new RuntimeException('An SSL socket was exported or invalidated');
        }
        $socket->close();

        $stream = stream_socket_server('tls://127.0.0.1:0', $errno, $error);
        $imported = Socket::import($stream);
        if ($imported->export() !== false || $imported->errCode !== SOCKET_EOPNOTSUPP) {
            throw new RuntimeException('An imported SSL stream was exported');
        }
        $imported->close();
        if ($warnings !== 2) {
            throw new RuntimeException('Missing SSL warnings');
        }
    } finally {
        restore_error_handler();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
