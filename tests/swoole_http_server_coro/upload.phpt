--TEST--
swoole_http_server_coro: upload 01
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_function_not_exist('curl_init');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Co::set(['log_level' => 0, 'trace_flags' => SWOOLE_TRACE_HTTP]);

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $uri = "http://127.0.0.1:{$pm->getFreePort()}";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $uri.'/upload');
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
};

$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
        $server = new Co\Http\Server("127.0.0.1", $pm->getFreePort(), false);
        $server->handle('/upload', function ($request, $response) use ($server) {
            $response->end(md5_file($request->files['file']['tmp_name']));
            $server->shutdown();
        });
        $server->start();
    });
    $pm->wakeup();
    swoole_event::wait();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
