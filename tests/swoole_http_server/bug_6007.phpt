--TEST--
swoole_http_server: Github bug #6007
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $cli->get('/');
        Assert::assert($cli->set_cookie_headers ===
            [
                'userId=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/; domain=my.web.site; HttpOnly; Partitioned',
            ]
        );
    });
    Swoole\Event::wait();
    echo "SUCCESS\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('0.0.0.0', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $cookie = new Swoole\Http\Cookie();
        $cookie->withName('userId')
            ->withValue('') // <--
            ->withExpires(time() - 84600)
            ->withPath('/')
            ->withDomain('my.web.site')
            ->withHttpOnly(true)
            ->withPartitioned(true);
        $response->setCookie($cookie);
        $response->end();
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
