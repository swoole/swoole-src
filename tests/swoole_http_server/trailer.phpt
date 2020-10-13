--TEST--
swoole_http_server: trailer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Swoole\Coroutine\run(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $cli->get('/');
        Assert::eq(md5('hello world'), $cli->headers['content-md5']);
        $pm->kill();
        echo "DONE\n";
    });
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort());

    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null'
    ]);

    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });

    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->header('trailer', 'Content-MD5');
        $data = 'hello world';
        $response->write($data);
        $response->trailer('Content-MD5', md5($data));
        $response->end();
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
