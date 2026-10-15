--TEST--
swoole_thread: SSL socket descriptors can be duplicated into thread containers for option queries
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
skip_if_no_ssl();
skip_if_extension_not_exist('openssl');
skip_if_extension_not_exist('sockets');
if (!class_exists(Swoole\Thread\ArrayList::class)) {
    die('skip thread support is unavailable');
}
?>
--FILE--
<?php
use Swoole\Coroutine\Socket;
use Swoole\Thread\ArrayList;

function checkSslDup($value): void
{
    $list = new ArrayList([$value]);
    $copy = $list[0];
    if ($copy instanceof Socket) {
        $type = $copy->getOption(SOL_SOCKET, SO_TYPE);
        $copy->close();
    } else {
        $native = is_resource($copy) ? socket_import_stream($copy) : $copy;
        $type = socket_get_option($native, SOL_SOCKET, SO_TYPE);
        socket_close($native);
    }
    if ($type !== SOCK_STREAM) {
        throw new RuntimeException('Cannot query duplicated SSL descriptor');
    }
    unset($copy, $list);
}

foreach ([0, SWOOLE_HOOK_SSL] as $flags) {
    Swoole\Runtime::enableCoroutine($flags);
    Swoole\Coroutine\run(function () {
        $stream = stream_socket_server('tls://127.0.0.1:0', $errno, $error);
        checkSslDup($stream);
        $native = socket_import_stream($stream);
        checkSslDup($native);
        unset($native);
        $imported = Socket::import($stream);
        checkSslDup($imported);
        unset($imported);
        fclose($stream);
        $socket = new Socket(AF_INET, SOCK_STREAM, 0);
        $socket->setProtocol(['open_ssl' => true]);
        checkSslDup($socket);
        $socket->close();
    });
}
Swoole\Runtime::enableCoroutine(0);
echo "DONE\n";
?>
--EXPECT--
DONE
