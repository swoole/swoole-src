--TEST--
swoole_client_coro: SOCKS5 handshake timeout spans fragmented reads
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require TESTS_API_PATH . '/swoole_client/socks5_fake_proxy.php';

$pm = new ProcessManager();
$port = get_one_free_port();
$pm->parentFunc = function ($pid) use ($port) {
    Co\run(function () use ($port) {
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        Assert::true($client->set([
            'timeout' => 0.11,
            'socks5_host' => TCP_SERVER_HOST,
            'socks5_port' => $port,
        ]));
        $start = microtime(true);
        Assert::false($client->connect('socks5-target.test', 80));
        Assert::same($client->errCode, SWOOLE_ERROR_SOCKS5_HANDSHAKE_FAILED);
        Assert::greaterThan(microtime(true) - $start, 0.1);
        echo "DONE\n";
    });
};
$pm->childFunc = function () use ($pm, $port) {
    socks5_run_proxy($pm, $port);
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
