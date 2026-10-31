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
    $connects = $receives = $errors = $closes = 0;
    $received = '';
    $client = new Swoole\Async\Client(SWOOLE_SOCK_TCP);
    $client->set([
        'socks5_host' => TCP_SERVER_HOST,
        'socks5_port' => $port,
    ]);
    $client->on('connect', function () use (&$connects) {
        $connects++;
    });
    $client->on('receive', function (Swoole\Async\Client $client, string $data) use (&$receives, &$received) {
        $receives++;
        $received .= $data;
        $client->close();
    });
    $client->on('error', function () use (&$errors) {
        $errors++;
    });
    $client->on('close', function () use (&$closes) {
        $closes++;
    });
    Assert::true($client->connect('socks5-target.test', 80, 2));
    Swoole\Event::wait();
    Assert::same($connects, 1);
    Assert::same($receives, 1);
    Assert::same($received, "SOCKS5 READY\n");
    Assert::same($errors, 0);
    Assert::same($closes, 1);
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm, $port) {
    socks5_run_proxy($pm, $port);
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
