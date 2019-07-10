--TEST--
swoole_http_server: http unix-socket
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    for ($c = MAX_CONCURRENCY; $c--;) {
        go(function () use ($pm) {
            $client = new Swoole\Coroutine\Client(SWOOLE_UNIX_STREAM);
            Assert::assert($client->connect(UNIXSOCK_PATH, 0, -1));
            for ($n = MAX_REQUESTS; $n--;) {
                $client->send("GET / HTTP/1.1\r\n\r\n");
                list($headers, $body) = explode("\r\n\r\n", @$client->recv());
                Assert::assert(count(explode("\n", $headers)) >= 5);
                Assert::same($body, 'Hello Swoole!');
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
