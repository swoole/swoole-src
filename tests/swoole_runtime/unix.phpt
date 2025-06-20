--TEST--
swoole_runtime: unix stream
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Socket;
use Swoole\Event;
use Swoole\Runtime;

Runtime::enableCoroutine();

const N = 5;
const SOCK_FILE = '/tmp/test.sock';

if (is_file(SOCK_FILE)) {
    unlink(SOCK_FILE);
}

go(function () {
    $socket = new Socket(AF_UNIX, SOCK_STREAM, 0);
    Assert::true($socket->bind(SOCK_FILE), 'bind error: ' . $socket->errCode);
    Assert::true($socket->listen(), 'listen error: ' . $socket->errCode);

    $client = $socket->accept();
    Assert::notNull($client);

    for ($i = 0; $i < N; $i++) {
        $data = $client->recv();
        $client->send("Swoole: {$data}");
    }

    usleep(1000);
});

go(function () {
    $fp = stream_socket_client('unix://' . SOCK_FILE, $errno, $errstr, 30);
    if (!$fp) {
        echo "{$errstr} ({$errno})<br />\n";
    } else {
        for ($i = 0; $i < N; $i++) {
            fwrite($fp, "hello-{$i}");
            $data = fread($fp, 1024);
            [$address] = explode(':', stream_socket_get_name($fp, true));
            $address = basename($address);
            echo "[Client] recvfrom[{$address}] : {$data}\n";
        }
        fclose($fp);
    }
});
Event::wait();
?>
--EXPECT--
[Client] recvfrom[test.sock] : Swoole: hello-0
[Client] recvfrom[test.sock] : Swoole: hello-1
[Client] recvfrom[test.sock] : Swoole: hello-2
[Client] recvfrom[test.sock] : Swoole: hello-3
[Client] recvfrom[test.sock] : Swoole: hello-4
