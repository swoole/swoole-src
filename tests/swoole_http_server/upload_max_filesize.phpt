--TEST--
swoole_http_server: upload max filesize
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

    $post_data = array(
        'test' => str_repeat('a', 80),
        'hello' => base64_encode(random_bytes(rand(10, 128))),
        'world' => base64_encode(random_bytes(rand(1024, 8192))),
    );

    if (function_exists("curl_file_create")) {
        $cfile = curl_file_create($file);
        $post_data['file'] = $cfile;
    } else {
        $post_data['file'] = '@' . $file;
    }

    curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);  //POST数据
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    curl_setopt($ch, CURLOPT_TIMEOUT, 1000);

    $res = curl_exec($ch);
    Assert::isEmpty(($res));
    Assert::eq(curl_getinfo($ch)['http_code'], 413);
    curl_close($ch);

    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);

    $http->set([
        'log_file' => '/dev/null',
        'package_max_length' => 64 * 1024,
        'upload_max_filesize' => 128 * 1024,
    ]);

    $http->on("WorkerStart", function () use ($pm) {
        $pm->wakeup();
    });

    $http->on("request", function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->end(md5_file($request->files['file']['tmp_name']));
    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
