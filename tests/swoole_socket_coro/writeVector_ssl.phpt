--TEST--
swoole_socket_coro: writeVector with ssl
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Socket;
use Swoole\Server;

use function Swoole\Coroutine\run;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    run(function () use ($pm) {
        $conn = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

        $conn->setProtocol([
            'open_ssl' => true,
        ]);
        $conn->connect('127.0.0.1', $pm->getFreePort());

        $iov = ['hello', 'world'];
        $ret = $conn->writeVector($iov);
        Assert::eq($ret, strlen('helloworld'));
        $pm->kill();
        echo "DONE\n";
    });
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $serv->set([
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
    ]);
    $serv->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function ($serv, $fd, $tid, $data) {
        Assert::eq($data, 'helloworld');
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
