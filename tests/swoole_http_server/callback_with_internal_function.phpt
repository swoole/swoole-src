--TEST--
swoole_http_server: http server callback use new object method
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        echo httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/");
        $pm->kill();
    });
};

$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('0.0.0.0', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null'
    ]);
    $http->on('request', 'var_dump');
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
object(Swoole\Http\Request)#%d (10) {
  ["fd"]=>
  int(1)
  ["streamId"]=>
  int(0)
  ["header"]=>
  array(3) {
    ["host"]=>
    string(15) "%s"
    ["accept"]=>
    string(3) "*/*"
    ["accept-encoding"]=>
    string(4) "gzip"
  }
  ["server"]=>
  array(10) {
    ["request_method"]=>
    string(3) "GET"
    ["request_uri"]=>
    string(1) "/"
    ["path_info"]=>
    string(1) "/"
    ["request_time"]=>
    int(%d)
    ["request_time_float"]=>
    float(%f)
    ["server_port"]=>
    int(%d)
    ["remote_port"]=>
    int(%d)
    ["remote_addr"]=>
    string(9) "127.0.0.1"
    ["master_time"]=>
    int(%d)
    ["server_protocol"]=>
    string(8) "HTTP/1.1"
  }
  ["request"]=>
  NULL
  ["cookie"]=>
  NULL
  ["get"]=>
  NULL
  ["files"]=>
  NULL
  ["post"]=>
  NULL
  ["tmpfiles"]=>
  NULL
}
object(Swoole\Http\Response)#%d (4) {
  ["fd"]=>
  int(1)
  ["header"]=>
  NULL
  ["cookie"]=>
  NULL
  ["trailer"]=>
  NULL
}