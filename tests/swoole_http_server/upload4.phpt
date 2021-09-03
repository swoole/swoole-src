--TEST--
swoole_http_server: upload 04
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_function_not_exist('curl_init');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Server;

const FILENAME = "test-+=.jpg";

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://127.0.0.1:{$pm->getFreePort()}");
    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_setopt($ch, CURLOPT_POST, 1); //设置为POST方式
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Expect:'));

    $file = TEST_IMAGE;

    $post_data = array('test' => str_repeat('a', 80));

    $cfile = curl_file_create($file);
    $cfile->setPostFilename(FILENAME);
    $post_data['file'] = $cfile;

    curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);  //POST数据
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $res = curl_exec($ch);
    Assert::assert(!empty($res));
    Assert::eq($res, FILENAME);
    curl_close($ch);

    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);

    $http->set([
        'log_file' => '/dev/null'
    ]);

    $http->on("WorkerStart", function () use ($pm) {
        $pm->wakeup();
    });

    $http->on("request", function (swoole_http_request $request, swoole_http_response $response) {
        $response->end($request->files['file']['name']);
    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
