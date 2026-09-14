--TEST--
swoole_client_sync: enforce package_max_length with eof protocol
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;

$recv = function (string $command) use ($pm): array {
    $client = new Swoole\Client(SWOOLE_SOCK_TCP);
    $client->set([
        'open_eof_check' => true,
        'package_eof' => "\r\n",
        'package_max_length' => 1024,
    ]);
    Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
    Assert::same($client->send($command), strlen($command));
    $warning = null;
    set_error_handler(function (int $errno, string $message) use (&$warning) {
        $warning = $message;
        return true;
    });
    $data = $client->recv();
    restore_error_handler();
    $error = swoole_last_error();
    $client->close();
    return [$data, $error, $warning];
};

$pm->parentFunc = function () use ($pm, $recv) {
    [$data, $error, $warning] = $recv('complete');
    Assert::false($data);
    Assert::same($error, SWOOLE_ERROR_PACKAGE_LENGTH_TOO_LARGE);
    Assert::contains(
        (string) $warning,
        'package length exceeds package_max_length, length=1025, package_max_length=1024'
    );

    [$data, $error, $warning] = $recv('unterminated');
    Assert::false($data);
    Assert::same($error, SWOOLE_ERROR_PACKAGE_LENGTH_TOO_LARGE);
    Assert::contains((string) $warning, 'no package eof, length=');
    Assert::contains((string) $warning, 'package_max_length=1024');

    [$data] = $recv('exact');
    Assert::same(strlen($data), 1024);
    Assert::true(str_ends_with($data, "\r\n"));

    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['log_file' => '/dev/null']);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Receive', function (Swoole\Server $server, int $fd, int $reactorId, string $command) {
        if ($command === 'complete') {
            $server->send($fd, str_repeat('A', 1023));
            Swoole\Timer::after(50, function () use ($server, $fd) {
                $server->send($fd, "\r\n");
            });
        } elseif ($command === 'unterminated') {
            $server->send($fd, str_repeat('A', 65536));
        } else {
            $server->send($fd, str_repeat('A', 1022) . "\r\n");
        }
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
