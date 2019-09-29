--TEST--
swoole_server/task: huge data
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;
$pm->setRandomFunc('get_big_random');
$pm->initRandomData(MAX_REQUESTS_LOW);
$pm->parentFunc = function (int $pid) use ($pm) {
    $uri = "http://127.0.0.1:{$pm->getFreePort()}";
    go(function () use ($pm, $uri) {
        for ($c = MAX_REQUESTS_LOW; $c--;) {
            $data = $pm->getRandomData();
            $body = httpGetBody($uri, ['data' => $data]);
            Assert::same($body, $data);
        }
    });
    Swoole\Event::wait();
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $http->set([
        'log_file' => '/dev/null',
        'task_worker_num' => 4
    ]);
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($http) {
        Assert::assert($response->detach());
        $scope = IS_IN_TRAVIS ? [4, 16] : [16, 64];
        $repeat = mt_rand(...$scope);
        $http->task([
            'fd' => $response->fd,
            'repeat' => $repeat,
            'data' => str_repeat($request->rawContent(), $repeat)
        ]);
    });
    $http->on('task', function ($a, $b, $c, array $info) {
        $response = Swoole\Http\Response::create($info['fd']);
        $response->end(substr($info['data'], 0, strlen($info['data']) / $info['repeat']));
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
