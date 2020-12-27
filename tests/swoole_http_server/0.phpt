--TEST--
swoole_http_server: basic functions
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;

$html = base64_encode(random_bytes(rand(2048, 65536)));

$pm->parentFunc = function ($pid) use ($pm, $html) {
    go(function () use ($pm, $html) {
        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/");
        Assert::same($data, $html);
        $pm->kill();
    });
    Swoole\Event::wait();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm, $html) {
    $serv = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set([
        'log_file' => '/dev/null',
    ]);
    $serv->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('request', function ($req, $resp) use ($html) {
        Assert::true($resp->isWritable());
        $resp->end($html);
        Assert::false($resp->isWritable());
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
