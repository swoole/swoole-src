--TEST--
swoole_http_client_coro: http client with http_proxy and host and port
--SKIPIF--
<?php
require __DIR__.'/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__.'/../include/bootstrap.php';

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', 1234);
        $cli->set([
            'timeout' => 30,
            'http_proxy_host' => '127.0.0.1',
            'http_proxy_port' => $pm->getFreePort(),
        ]);
        $cli->setHeaders([
            'Host' => '127.0.0.1:1234',
        ]);
        $cli->get('/');
        $pm->kill();
    });
};

$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('0.0.0.0', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'log_file'       => '/dev/null',
        'open_eof_check' => true,
        'package_eof'    => "\r\n\r\n",
    ]);
    $server->on('Receive', function ($server, $fd, $reactor_id, $data) {
        echo $data;
        $server->close($fd);
    });
    $server->start();
};

$pm->childFirst();
$pm->run();

?>
--EXPECT--
GET http://127.0.0.1:1234/ HTTP/1.1
Host: 127.0.0.1:1234
Connection: keep-alive
Accept-Encoding: gzip, deflate, br
