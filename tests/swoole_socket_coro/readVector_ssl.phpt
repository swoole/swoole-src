--TEST--
swoole_socket_coro: readVector with ssl
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Socket;

use function Swoole\Coroutine\run;

$pm = new ProcessManager();
$pm->parentFunc = function ($pid) use ($pm) {
    run(function () use ($pm) {
        $conn = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

        $conn->setProtocol([
            'open_ssl' => true,
        ]);
        $conn->connect('127.0.0.1', $pm->getFreePort());

        $ret = $conn->send('helloworld');
        Assert::eq($ret, strlen('helloworld'));
        $conn->recv();
        echo "DONE\n";
    });
};

$pm->childFunc = function () use ($pm) {
    run(function () use ($pm) {
        global $totalLength, $packedStr;
        $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        $socket->setProtocol([
            'open_ssl' => true,
            'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
            'ssl_key_file' => SSL_FILE_DIR . '/server.key',
        ]);
        Assert::assert($socket->bind('127.0.0.1', $pm->getFreePort()));
        Assert::assert($socket->listen(MAX_CONCURRENCY));

        $pm->wakeup();
        /** @var Socket */
        $conn = $socket->accept();
        Assert::assert($conn, 'error: ' . swoole_last_error());
        $conn->sslHandshake();

        Assert::eq($conn->readVector([5, 5]), ['hello', 'world']);
        $conn->send('close');
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
