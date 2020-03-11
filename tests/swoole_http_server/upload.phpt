--TEST--
swoole_http_server: upload 01
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_function_not_exist('curl_init');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://127.0.0.1:{$pm->getFreePort()}");
    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_setopt($ch, CURLOPT_POST, 1); //设置为POST方式
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Expect:'));

    $file = TEST_IMAGE;

    $post_data = array('test' => str_repeat('a', 80));

    if (function_exists("curl_file_create"))
    {
        $cfile = curl_file_create($file);
        $post_data['file'] = $cfile;
    }
    else
    {
        $post_data['file'] = '@' . $file;
    }

    curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);  //POST数据
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $res = curl_exec($ch);
    Assert::assert(!empty($res));
    Assert::same($res, md5_file($file));
    curl_close($ch);

    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);

    $http->set([
        'log_file' => '/dev/null'
    ]);

    $http->on("WorkerStart", function () use ($pm) {
        $pm->wakeup();
    });

    $http->on("request", function (swoole_http_request $request, swoole_http_response $response) {
        $response->end(md5_file($request->files['file']['tmp_name']));
    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
