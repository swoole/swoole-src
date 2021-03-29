--TEST--
swoole_http_client_coro: http client with http_proxy and host and port
--SKIPIF--
<?php
require __DIR__.'/../include/skipif.inc';
skip_if_no_http_proxy();
?>
--FILE--
<?php
require __DIR__.'/../include/bootstrap.php';

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\Run(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $cli->set([
            'timeout' => 30,
            'http_proxy_host' => HTTP_PROXY_HOST,
            'http_proxy_port' => HTTP_PROXY_PORT,
        ]);
        $cli->setHeaders([
            'Host' => '127.0.0.1:'.$pm->getFreePort(),
        ]);
        $result = $cli->get('/');
        Assert::assert($result);
        Assert::assert('Swoole' === $cli->body);
        $cli->close();
        $pm->kill();
        echo "DONE\n";
    });
};

$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('0.0.0.0', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['log_file' => '/dev/null']);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm) {
        $response->end('Swoole');
    });
    $server->start();
};

$pm->childFirst();
$pm->run();

?>
--EXPECT--
DONE
