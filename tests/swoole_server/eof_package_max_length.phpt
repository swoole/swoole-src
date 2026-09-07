--TEST--
swoole_server: enforce non-aligned package_max_length with eof protocol
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$logFile = TEST_LOG_FILE . '.eof_package_max_length';
@unlink($logFile);

$pm = new ProcessManager;

$pm->parentFunc = function () use ($pm, $logFile) {
    $send = function (string $data, string $tail = '') use ($pm) {
        $client = new Swoole\Client(SWOOLE_SOCK_TCP);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 1));
        Assert::same($client->send($data), strlen($data));
        if ($tail !== '') {
            usleep(50000);
            Assert::same($client->send($tail), strlen($tail));
        }
        @$client->recv();
        $client->close();
    };

    $send(str_repeat('A', 100000), "A\r\n");
    $send(str_repeat('A', 100008));

    $log = is_file($logFile) ? file_get_contents($logFile) : '';
    Assert::same(substr_count($log, 'The received data packet is too large'), 2);
    @unlink($logFile);
    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm, $logFile) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'open_eof_check' => true,
        'package_eof' => "\r\n",
        'package_max_length' => 100001,
        'log_file' => $logFile,
        'log_level' => SWOOLE_LOG_WARNING,
    ]);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Receive', function (Swoole\Server $server, int $fd) {
        echo "RECEIVED\n";
        $server->close($fd);
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
