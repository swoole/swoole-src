--TEST--
swoole_http_server: cookies
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__ . "/../include/lib/curl.php";

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://127.0.0.1:9501");
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
    assert(!empty($res));
    assert($res === md5_file($file));
    curl_close($ch);

    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server("127.0.0.1", 9501, SWOOLE_BASE);

    $http->set(['log_file' => '/dev/null']);

    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });

    $http->on("request", function ($request, $response) {
        $response->end(md5_file($request->files['file']['tmp_name']));
    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
