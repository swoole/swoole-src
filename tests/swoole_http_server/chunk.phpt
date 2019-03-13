--TEST--
swoole_http_server: http chunk
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_function_not_exist('curl_init');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $data = curlGet("http://127.0.0.1:{$pm->getFreePort()}/");
    assert(!empty($data));
    assert(md5($data) === md5_file(TEST_IMAGE));
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);

    $http->set([
        //'log_file' => '/dev/null',
    ]);

    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });

    $http->on("request", function (swoole_http_request $request,  swoole_http_response $response) {
        $data = str_split(file_get_contents(TEST_IMAGE), 8192);
        foreach ($data as $chunk)
        {
            $response->write($chunk);
        }
        $response->end();
    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
