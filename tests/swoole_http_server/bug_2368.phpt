--TEST--
swoole_http_server: bug Github#2368
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
define('COOKIE', 'this is !@#Auth=Cookie「}」『』P{}!@#Auth=Cookie「}」『』P{}!@#Auth=Cookie「}」『』P{}!@#Auth=Cookie「}」『』P{}');
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        Assert::assert($cli->get('/'));
        Assert::same($cli->statusCode, 200);
        Assert::assert($cli->set_cookie_headers ===
            [
                'name=' . urlencode(COOKIE),
            ]
        );
    });
    Swoole\Event::wait();
    echo "SUCCESS\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('0.0.0.0', $pm->getFreePort(), SWOOLE_PROCESS);
    $http->set(array(
        'log_file' => '/dev/null',
    ));
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->cookie('name', COOKIE);
        $response->end();
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
