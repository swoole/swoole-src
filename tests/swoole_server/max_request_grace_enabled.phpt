--TEST--
swoole_server: max_request_grace enabled
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;

$pm->parentFunc = function () use ($pm)
{
    $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $client->set([
        'open_eof_check' => true,
        'package_eof' => "\r\n\r\n",
    ]);
    Assert::assert($client->connect('127.0.0.1', $pm->getFreePort(), -1));
    $count = 0;
    for ($i = 0; $i < 16; $i++) {
        $client->send("request $i\r\n\r\n");
        $count = max($count, (int)$client->recv());
    }
    echo "Worker served $count request(s) since start\n";
    $client->close();
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new swoole_server('127.0.0.1', $pm->getFreePort());
    $serv->set([
        'worker_num'        => 2,
        'dispatch_mode'     => 1,
        'max_request'       => 4,
        'max_request_grace' => PHP_INT_MAX,
        'open_eof_check'    => true,
        'package_eof'       => "\r\n\r\n",
        'log_file'          => '/dev/null',
    ]);
    $serv->on('workerStart', function ()  use ($pm) {
        $pm->wakeup();
    });
    $counter = 0;
    $serv->on('receive', function (swoole_server $serv, $fd, $reactorId, $data) use (&$counter) {
        $counter++;
        $serv->send($fd, $counter);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
Worker served 8 request(s) since start
