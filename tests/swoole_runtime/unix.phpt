--TEST--
swoole_runtime: unix stream
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
    $socket = new Swoole\Coroutine\Socket(AF_UNIX, SOCK_STREAM, 0);
    $socket->bind(__DIR__ . '/test.sock');
    $socket->listen();

    $client = $socket->accept();

    for ($i = 0; $i < N; $i++)
    {
        $data = $client->recv();
        $client->send("Swoole: $data");
    }

    usleep(1000);
});

go(function () {
    $fp = stream_socket_client("unix://".__DIR__."/test.sock", $errno, $errstr, 30);
    if (!$fp) {
        echo "$errstr ($errno)<br />\n";
    } else {
        for ($i = 0; $i < N; $i++) {
            fwrite($fp, "hello-{$i}");
            $data = fread($fp, 1024);
            list($address) = explode(':', (stream_socket_get_name($fp, true)));
            $address = basename($address);
            echo "[Client] recvfrom[{$address}] : $data\n";
        }
        fclose($fp);
    }
});
swoole_event_wait();
?>
--EXPECT--
[Client] recvfrom[test.sock] : Swoole: hello-0
[Client] recvfrom[test.sock] : Swoole: hello-1
[Client] recvfrom[test.sock] : Swoole: hello-2
[Client] recvfrom[test.sock] : Swoole: hello-3
[Client] recvfrom[test.sock] : Swoole: hello-4
