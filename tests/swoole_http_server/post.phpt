--TEST--
swoole_http_server: post
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new SwooleTest\ProcessManager;

$html = base64_encode(random_bytes(rand(2048, 65536 * 2)));

$pm->parentFunc = function ($pid) use ($pm, $html) {
    Co\run(function () use ($pm, $html) {
        $index = rand(8192, strlen($html) - 8192);
        $reqData = [
            'data1' => substr($html, 0, $index),
            'data2' => substr($html, $index)
        ];
        $resp = httpPost("http://127.0.0.1:{$pm->getFreePort()}/", $reqData);
        Assert::assert($resp);
        $respData = json_decode($resp, true);
        Assert::same($respData['data1'], $reqData['data1']);
        Assert::same($respData['data2'], $reqData['data2']);
    });
    echo "DONE\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $html) {
    $mode = SERVER_MODE_RANDOM;
    $serv = new swoole_http_server('127.0.0.1', $pm->getFreePort(), $mode);
    $serv->set([
        'log_file' => '/dev/null',
    ]);
    $serv->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('request', function ($req, $resp) use ($html) {
        $resp->end(json_encode($req->post));
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
