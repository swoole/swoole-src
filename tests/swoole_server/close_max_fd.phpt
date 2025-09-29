--TEST--
swoole_server: close_max_fd
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        go(function() use ($pm) {
            $client = new Co\Client(SWOOLE_SOCK_TCP);
            Assert::assert($client->connect('127.0.0.1', $pm->getFreePort()));
            Assert::assert($client->send('test 1'));
            $client->recv();
            Co::sleep(1);
            $client->send('ping 1');
            Co::sleep(1);
            $pm->kill();
        });
        go(function() use ($pm) {
            $cli = new Co\Http\Client('127.0.0.1', $pm->getFreePort());
        });
        go(function() use ($pm) {
            $client = new Co\Client(SWOOLE_SOCK_TCP);
            Assert::assert($client->connect('127.0.0.1', $pm->getFreePort()));
            $client->send('test 2');
            Co::sleep(1);
        });
    });
};
$pm->childFunc = function () use ($pm) {
    $log_file = __DIR__ . '/close_max_fd.log';
    $fp = fopen($log_file, 'a');
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 1,
        'log_level' => SWOOLE_LOG_ERROR,
    ]);

    $server->on('receive', function (Swoole\Server $serv, int $fd, int $rid, string $data) use ($fp) {
        fputs($fp, "recv: $data\n");
        fputs($fp, 'getClientList: ' . implode(';', $serv->getClientList()) . "\n");
        Assert::true(!empty($serv->getClientList()));
        foreach ($serv->connections as $_fd) {
            fputs($fp, "foreach: fd-{$_fd}\n");
        }
        $serv->send($fd, "Server: " . $data);
    });

    $server->on('close', function ($server, $fd) use ($fp) {
        fputs($fp, "close: fd-{$fd}\n");
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
