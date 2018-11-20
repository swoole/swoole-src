--TEST--
swoole_http_server: http unix-socket
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_darwin();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    for ($n = MAX_REQUESTS_LOW; $n--;) {
        $client = new Swoole\Client(SWOOLE_UNIX_STREAM, SWOOLE_SOCK_SYNC);
        $r = $client->connect(UNIXSOCK_PATH, 0, -1);
        if ($r === false) {
            echo "ERROR";
            exit;
        }
        $client->send("GET / HTTP/1.1\r\n\r\n");
        list($header, $body) = explode("\r\n\r\n", @$client->recv());
        assert($body === 'Hello Swoole!');
        $client->close();
    }
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
