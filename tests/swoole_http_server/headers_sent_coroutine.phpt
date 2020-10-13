--TEST--
swoole_http_server: headers sent (coroutine enabled)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;

$pm->parentFunc = function () use ($pm) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://127.0.0.1:{$pm->getFreePort()}/");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    echo curl_exec($ch);
    echo curl_exec($ch);
    curl_close($ch);
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort());
    $http->set([
        'worker_num' => 1,
        'enable_coroutine' => true,
        'log_file' => '/dev/null'
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        ob_start();
        echo 'Test';
        $output = ob_get_clean();
        $response->write('buffered_output=' . $output . "\n");
        $response->write('headers_sent=' . (int)headers_sent() . "\n");
        $response->end();
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
buffered_output=Test
headers_sent=0
buffered_output=Test
headers_sent=0
