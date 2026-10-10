--TEST--
swoole_socket_coro: exporting imported native and coroutine streams preserves independent lifetime
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
use Swoole\Coroutine\Socket;

foreach ([0, SWOOLE_HOOK_TCP] as $flags) {
    Swoole\Runtime::enableCoroutine($flags);
    Swoole\Coroutine\run(function () {
        $listener = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
        $client = stream_socket_client('tcp://' . stream_socket_get_name($listener, false));
        $peer = stream_socket_accept($listener, 1);
        fclose($listener);
        stream_set_timeout($peer, 1);
        $imported = Socket::import($client);
        $exported = $imported->export();
        if (!is_resource($exported) || $exported === $client) {
            throw new RuntimeException('Export did not duplicate the imported descriptor');
        }
        $imported->close();
        if (fwrite($exported, 'hello') !== 5 || fread($peer, 5) !== 'hello') {
            throw new RuntimeException('Closing the imported socket shut down the duplicate');
        }
        fclose($exported);
        if (fread($peer, 1) !== '') {
            throw new RuntimeException('The imported or exported descriptor leaked');
        }
        fclose($peer);
    });
}
Swoole\Runtime::enableCoroutine(0);
echo "DONE\n";
?>
--EXPECT--
DONE
