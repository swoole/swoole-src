--TEST--
swoole_http_server: 413 error
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';


$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://127.0.0.1:" . $pm->getFreePort() . '/');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_POST, 1);
    $post_data = ['data' => str_repeat('A', 65536)];
    curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);

    $result = curl_exec($ch);
    Assert::isEmpty($result);
    $info = curl_getinfo($ch);
    Assert::eq($info['http_code'], 413);
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP);

    $http->set(['package_max_length' => 8192, 'log_file' => '/dev/null']);

    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });

    $http->on('request', function ($req, Swoole\Http\Response $resp)  {
        $resp->end('hello');
    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
