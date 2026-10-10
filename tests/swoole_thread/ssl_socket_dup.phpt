--TEST--
swoole_thread: SSL sockets and SSL streams cannot be duplicated into thread containers
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

function rejectSslDup($value): void
{
    try {
        new ArrayList([$value]);
    } catch (Swoole\Exception $e) {
        if ($e->getCode() !== SOCKET_EOPNOTSUPP) {
            throw $e;
        }
        return;
    }
    throw new RuntimeException('SSL state was discarded during duplication');
}

foreach ([0, SWOOLE_HOOK_SSL] as $flags) {
    Swoole\Runtime::enableCoroutine($flags);
    Swoole\Coroutine\run(function () {
        $stream = stream_socket_server('tls://127.0.0.1:0', $errno, $error);
        rejectSslDup($stream);
        $native = socket_import_stream($stream);
        rejectSslDup($native);
        unset($native);
        $imported = Socket::import($stream);
        rejectSslDup($imported);
        unset($imported);
        fclose($stream);
        $socket = new Socket(AF_INET, SOCK_STREAM, 0);
        $socket->setProtocol(['open_ssl' => true]);
        rejectSslDup($socket);
        $socket->close();
    });
}
Swoole\Runtime::enableCoroutine(0);
echo "DONE\n";
?>
--EXPECT--
DONE
