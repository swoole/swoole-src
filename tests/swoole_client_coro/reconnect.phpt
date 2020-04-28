--TEST--
swoole_client_coro: reconnect
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;
use Swoole\Coroutine\Client;

use function Swoole\Coroutine\run;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    run(function () use ($pm) {
        $flag = 0;
        $client = new Client(SWOOLE_SOCK_TCP);
        reconnect:
        if (!$client->connect('127.0.0.1', 9501)) {
            /**
            * if we want to reconnect server, we should call $client->close() first
            */
            Assert::eq($client->errCode, SOCKET_EISCONN);
            Assert::eq($client->errMsg, swoole_strerror(SOCKET_EISCONN));
        }

        $pm->kill();

        $data = $client->recv();
        if (empty($data)) {
            if ($flag === 0) {
                $flag += 1;
                goto reconnect;
            }
        }
        echo "DONE\n";
    });
};
$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', 9501);
    $serv->set([
        'log_file' => '/dev/null',
    ]);

    $serv->on('Receive', function () {
    });

    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
