--TEST--
swoole_http_server: upload raw
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) {
    $sock = stream_socket_client("tcp://127.0.0.1:9501");
    fwrite($sock, file_get_contents(__DIR__.'/httpdata'));
    stream_set_chunk_size($sock, 2 * 1024 * 1024);
    $data = fread($sock, 2 * 1024 * 1024);
    assert(!empty($data));
    $json = json_decode(explode("\r\n\r\n", $data, 2)[1], true);
    assert(is_array($json));
    assert(isset($json['file']));
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
        $response->end(json_encode($request->files + $request->post));
    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
