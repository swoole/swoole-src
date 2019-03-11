--TEST--
swoole_http_server: upload file
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
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://127.0.0.1:{$pm->getFreePort()}");
    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Expect:']);

    $post_data = ['test' => str_repeat('a', 80)];

    if (function_exists("curl_file_create")) {
        $cfile = curl_file_create(TEST_IMAGE);
        $post_data['upfile'] = $cfile;
    } else {
        $post_data['upfile'] = '@' . TEST_IMAGE;
    }

    curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);  //POST数据
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    echo curl_exec($ch);
    curl_close($ch);
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort());
    $http->set(['log_file' => '/dev/null']);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        if (
            empty($request->files['upfile']) ||
            md5_file(TEST_IMAGE) !== md5_file($request->files['upfile']['tmp_name']) ||
            !is_uploaded_file($request->files['upfile']['tmp_name'])
        ) {
            $response->end("ERROR\n");
        } else {
            $response->end("OK\n");
        }
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
