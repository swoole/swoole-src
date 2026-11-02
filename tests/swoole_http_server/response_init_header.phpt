--TEST--
swoole_http_server: repeated initHeader preserves headers, cookies and trailers
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    try {
        Swoole\Coroutine\run(function () use ($pm) {
            $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
            for ($i = 0; $i < 2; $i++) {
                Assert::true($client->get('/'));
                Assert::same($client->statusCode, 200);
                Assert::same($client->body, 'hello world');
                Assert::same($client->headers['x-test'], 'value');
                Assert::same($client->cookies['token'], 'yes');
                Assert::same($client->headers['x-checksum'], 'done');
            }
            $client->close();
        });
    } finally {
        $pm->kill();
    }
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['log_file' => '/dev/null', 'http_compression' => false]);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Request', function ($request, $response) {
        Assert::true($response->initHeader());
        Assert::same($response->header, []);
        Assert::same($response->cookie, []);
        Assert::same($response->trailer, []);
        Assert::true($response->header('X-Test', 'value'));
        Assert::true($response->header('Trailer', 'X-Checksum'));
        Assert::true($response->cookie('token', 'yes'));
        Assert::true($response->trailer('X-Checksum', 'done'));
        $header = $response->header;
        $cookie = $response->cookie;
        $trailer = $response->trailer;
        Assert::true($response->initHeader());
        Assert::same($response->header, $header);
        Assert::same($response->cookie, $cookie);
        Assert::same($response->trailer, $trailer);
        Assert::true($response->write('hello '));
        Assert::true($response->end('world'));
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
