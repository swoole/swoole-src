--TEST--
swoole_http_server: too many special chars in cookie
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->setRandomFunc(function () {
    static $str = '!#$&\'()*+/:;=?@{}『』';
    return str_shuffle(str_repeat($str, mt_rand(128, 1024) / strlen($str)));
});
$pm->initRandomDataEx(1, MAX_REQUESTS);
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        for ($n = MAX_REQUESTS; $n--;) {
            Assert::assert($cli->get('/'));
            Assert::same($cli->statusCode, 200);
            Assert::same($cli->cookies['foo'], $pm->getRandomData());
        }
    });
    Swoole\Event::wait();
    echo "DONE\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort());
    $http->set(['log_file' => '/dev/null']);
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm) {
        static $pre_cookie;
        if ($pre_cookie) {
            Assert::same($request->cookie['foo'], $pre_cookie);
        }
        $response->cookie('foo', $pre_cookie = $pm->getRandomData(), time() + 60 * 30, '/');
        $response->end();
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
