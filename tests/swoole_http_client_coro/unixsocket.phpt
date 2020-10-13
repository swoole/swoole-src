--TEST--
swoole_http_client_coro: http unix-socket
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    for ($c = MAX_CONCURRENCY; $c--;) {
        go(function () use ($pm) {
            $client = new Swoole\Coroutine\Http\Client('unix:' . str_repeat('/', mt_rand(0, 2)) . UNIXSOCK_PATH);
            for ($n = MAX_REQUESTS; $n--;) {
                Assert::assert($client->get('/'), "statusCode={$client->statusCode}, error={$client->errCode}");
                Assert::same($client->body, 'Hello Swoole!');
            }
        });
    }
    swoole_event_wait();
    echo "SUCCESS\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server(UNIXSOCK_PATH, 0, SERVER_MODE_RANDOM, SWOOLE_UNIX_STREAM);
    $server->set(['log_file' => '/dev/null']);
    $server->on(\Swoole\Constant::EVENT_START, function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->end('Hello Swoole!');
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
