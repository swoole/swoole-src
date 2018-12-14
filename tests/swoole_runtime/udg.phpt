--TEST--
swoole_runtime: udg
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

swoole\runtime::enableCoroutine();
const N = 5;

go(function () {
    $socket = new Swoole\Coroutine\Socket(AF_UNIX, SOCK_DGRAM, 0);
    $socket->bind(__DIR__ . '/test.sock');

    for ($i = 0; $i < N; $i++)
    {
        $peer = null;
        $data = $socket->recvfrom($peer);
        echo "[Server] recv : $data\n";
    }
});

go(function () {
    $fp = stream_socket_client("udg://".__DIR__."/test.sock", $errno, $errstr, 30);
    if (!$fp) {
        echo "$errstr ($errno)<br />\n";
    } else {
        for ($i = 0; $i < N; $i++) {
            fwrite($fp, "hello-{$i}");
        }
        fclose($fp);
    }
});
swoole_event_wait();
?>
--EXPECT--
[Server] recv : hello-0
[Server] recv : hello-1
[Server] recv : hello-2
[Server] recv : hello-3
[Server] recv : hello-4
