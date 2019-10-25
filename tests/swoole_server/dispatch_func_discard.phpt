--TEST--
swoole_server: dispatch_func [discard]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {

    go(function () use ($pm) {
        $client = new Co\Client(SWOOLE_SOCK_TCP);
        Assert::assert($client->connect('127.0.0.1', $pm->getFreePort(), 0.2));

        $data = str_repeat('A', 65534)."\r\n\r\n";
        Assert::assert($client->send($data));
        Assert::same(false, @$client->recv());
    });
    
    Swoole\Event::wait();
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {

    function dispatch_packet($server, $fd, $type)
    {
        return -1;
    }

    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'log_file' => '/dev/null',
        'open_eof_check' => true,
        'package_eof' => "\r\n\r\n",
        'dispatch_func' => 'dispatch_packet',
    ]);
    $server->on("WorkerStart", function (Swoole\Server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $server->on('receive', function (Swoole\Server $server, $fd, $threadId, $data) {
        $server->send($fd, $data);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
