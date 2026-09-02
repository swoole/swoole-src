--TEST--
swoole_client_async: fragmented SOCKS5 response
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require TESTS_API_PATH . '/swoole_client/socks5_fake_proxy.php';

$pm = new ProcessManager();
$port = get_one_free_port();
$pm->parentFunc = function ($pid) use ($port) {
    $client = new Swoole\Async\Client(SWOOLE_SOCK_TCP);
    $client->set([
        'socks5_host' => TCP_SERVER_HOST,
        'socks5_port' => $port,
    ]);
    $client->on('connect', function (Swoole\Async\Client $client) {
        Assert::true($client->isConnected());
    });
    $client->on('receive', function (Swoole\Async\Client $client, string $data) {
        Assert::same($data, "SOCKS5 READY\n");
        $client->close();
    });
    $client->on('error', function () {
        echo "ERROR\n";
        Swoole\Event::exit();
    });
    $client->on('close', function () {
        echo "DONE\n";
        Swoole\Event::exit();
    });
    Assert::true($client->connect('socks5-target.test', 80, 2));
    Swoole\Event::wait();
};
$pm->childFunc = function () use ($pm, $port) {
    socks5_run_proxy($pm, $port);
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
