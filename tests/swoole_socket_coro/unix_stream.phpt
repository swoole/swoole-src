--TEST--
swoole_socket_coro: unix stream
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const SOCK_FILE = '/tmp/test-server.sock';

Co\run(function () {
    @unlink(SOCK_FILE);
    $server = new Swoole\Coroutine\Socket(AF_UNIX, SOCK_STREAM, IPPROTO_IP);
    $server->bind(SOCK_FILE);
    $server->listen();

    go(function () use ($server) {
        while (!$server->isClosed()) {
            $conn = $server->accept();
            while ($data = $conn->recv()) {
                Assert::same($data, 'hello');
                $conn->send('world');
            }
        }
    });

    go(function () use ($server) {
        $client = new Swoole\Coroutine\Socket(AF_UNIX, SOCK_STREAM, IPPROTO_IP);
        $client->connect(SOCK_FILE);
        for ($n = MAX_REQUESTS; $n--;) {
            $client->send('hello');
            $data = $client->recv();
            Assert::notEmpty($data);
            if (empty($data)) {
                break;
            }
            Assert::same($data, 'world');
        }
        $client->close();
        $server->close();
    });
});
echo "DONE\n";
?>
--EXPECT--
DONE
