--TEST--
swoole_server: close_max_fd
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

$pm = new SwooleTest\ProcessManager;
$pm->setWaitTimeout(5);
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $client1 = new Co\Client(SWOOLE_SOCK_TCP);
        Assert::true($client1->connect('127.0.0.1', $pm->getFreePort()));

        $httpClient = new Co\Http\Client('127.0.0.1', $pm->getFreePort());
        unset($httpClient);

        $client2 = new Co\Client(SWOOLE_SOCK_TCP);
        Assert::true($client2->connect('127.0.0.1', $pm->getFreePort()));

        Assert::same($client1->send('test 1'), 6);
        Assert::same($client1->recv(), 'Server: test 1');
        Assert::same($client2->send('test 2'), 6);
        Assert::same($client2->recv(), 'Server: test 2');

        Assert::true($client2->close());
        Assert::true($pm->wait());

        Assert::same($client1->send('ping 1'), 6);
        Assert::same($client1->recv(), 'Server: ping 1');
        Assert::true($client1->close());
        Assert::true($pm->wait());
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $log_file = __DIR__ . '/close_max_fd.log';
    $fp = fopen($log_file, 'w');
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 1,
        'log_level' => SWOOLE_LOG_ERROR,
    ]);

    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });

    $server->on('receive', function (Swoole\Server $serv, int $fd, int $rid, string $data) use ($fp) {
        fputs($fp, "recv: $data\n");
        fputs($fp, 'getClientList: ' . implode(';', $serv->getClientList()) . "\n");
        Assert::true(!empty($serv->getClientList()));
        foreach ($serv->connections as $_fd) {
            fputs($fp, "foreach: fd-{$_fd}\n");
        }
        fflush($fp);
        $serv->send($fd, "Server: " . $data);
    });

    $server->on('close', function ($server, $fd) use ($pm, $fp) {
        fputs($fp, "close: fd-{$fd}\n");
        fflush($fp);
        $pm->wakeup();
    });

    $server->start();

    fclose($fp);
    $cnt = file_get_contents($log_file);

    Assert::eq(substr_count($cnt, 'recv: test 1'), 1);
    Assert::eq(substr_count($cnt, 'recv: test 2'), 1);
    Assert::eq(substr_count($cnt, 'recv: ping 1'), 1);

    Assert::eq(substr_count($cnt, 'close: fd-2'), 1);
    Assert::eq(substr_count($cnt, 'close: fd-1'), 1);

    Assert::eq(substr_count($cnt, 'foreach: fd-1'), 3);
    Assert::eq(substr_count($cnt, 'foreach: fd-2'), 2);

    Assert::eq(substr_count($cnt, 'getClientList: 1;2'), 2);
    Assert::eq(substr_count($cnt, "getClientList: 1\n"), 1);

    unlink($log_file);
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
