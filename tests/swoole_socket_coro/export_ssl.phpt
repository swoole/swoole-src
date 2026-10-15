--TEST--
swoole_socket_coro: exporting SSL descriptors allows option queries without sharing TLS state
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
skip_if_extension_not_exist('openssl');
?>
--FILE--
<?php
use Swoole\Coroutine\Socket;

function checkSslExport(Socket $socket): void
{
    $stream = $socket->export();
    if (!is_resource($stream) || $socket->isClosed()) {
        throw new RuntimeException('Cannot export SSL descriptor');
    }
    $copy = Socket::import($stream);
    if (!$copy || $copy->getOption(SOL_SOCKET, SO_TYPE) !== SOCK_STREAM) {
        throw new RuntimeException('Cannot query exported SSL descriptor');
    }
    $copy->close();
    if ($socket->getOption(SOL_SOCKET, SO_TYPE) !== SOCK_STREAM) {
        throw new RuntimeException('Closing the copy invalidated the original SSL descriptor');
    }
}

foreach ([0, SWOOLE_HOOK_SSL] as $flags) {
    Swoole\Runtime::enableCoroutine($flags);
    Swoole\Coroutine\run(function () {
        $socket = new Socket(AF_INET, SOCK_STREAM, 0);
        if (!$socket->bind('127.0.0.1', 0)) {
            throw new RuntimeException('Cannot bind SSL socket');
        }
        $socket->setProtocol(['open_ssl' => true]);
        checkSslExport($socket);
        $socket->close();

        $stream = stream_socket_server('tls://127.0.0.1:0', $errno, $error);
        $imported = Socket::import($stream);
        checkSslExport($imported);
        $imported->close();
    });
}
Swoole\Runtime::enableCoroutine(0);
echo "DONE\n";
?>
--EXPECT--
DONE
