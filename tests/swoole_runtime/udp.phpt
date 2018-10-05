--TEST--
swoole_runtime: udp client
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
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, 0);
    $socket->bind('127.0.0.1', 9601);
    for ($i = 0; $i < N; $i++)
    {
        $peer = null;
        $data = $socket->recvfrom($peer);
        echo "[Server] recvfrom[{$peer['address']}:{$peer['port']}] : $data\n";
        $socket->sendto($peer['address'], $peer['port'], "Swoole: $data");
    }
});

go(function () {
    $fp = stream_socket_client("udp://127.0.0.1:9601", $errno, $errstr, 30);
    if (!$fp) {
        echo "$errstr ($errno)<br />\n";
    } else {
        for ($i = 0; $i < N; $i++) {
            fwrite($fp, "hello-{$i}");
            $data = fread($fp, 1024);
            list($address, $port) = explode(':', (stream_socket_get_name($fp, true)));
            echo "[Client] recvfrom[{$address}:{$port}] : $data\n";
        }
        fclose($fp);
    }
});
swoole_event_wait();
?>
--EXPECTF--
[Server] recvfrom[127.0.0.1:%d] : hello-0
[Client] recvfrom[127.0.0.1:9601] : Swoole: hello-0
[Server] recvfrom[127.0.0.1:%d] : hello-1
[Client] recvfrom[127.0.0.1:9601] : Swoole: hello-1
[Server] recvfrom[127.0.0.1:%d] : hello-2
[Client] recvfrom[127.0.0.1:9601] : Swoole: hello-2
[Server] recvfrom[127.0.0.1:%d] : hello-3
[Client] recvfrom[127.0.0.1:9601] : Swoole: hello-3
[Server] recvfrom[127.0.0.1:%d] : hello-4
[Client] recvfrom[127.0.0.1:9601] : Swoole: hello-4
