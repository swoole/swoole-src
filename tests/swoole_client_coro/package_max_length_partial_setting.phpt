--TEST--
swoole_client_coro: preserve package_max_length after partial settings
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const PACKAGE_MAX_LENGTH = 1024;

Co::set(['log_level' => SWOOLE_LOG_ERROR]);

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $client->set([
            'open_length_check' => true,
            'package_length_type' => 'N',
            'package_length_offset' => 0,
            'package_body_offset' => 4,
            'package_max_length' => PACKAGE_MAX_LENGTH,
        ]);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort()));
        $client->set(['timeout' => 1]);
        Assert::false($client->recv());
        Assert::same($client->errCode, SWOOLE_ERROR_PACKAGE_LENGTH_TOO_LARGE);
    });
    Swoole\Event::wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
    ]);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Connect', function (Swoole\Server $server, int $fd) {
        $data = str_repeat('A', PACKAGE_MAX_LENGTH * 2);
        $server->send($fd, pack('N', strlen($data)) . $data);
    });
    $server->on('Receive', function () {
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
