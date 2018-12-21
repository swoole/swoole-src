--TEST--
swoole_server: length check 5
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require __DIR__ . "/../include/bootstrap.php";

$type = 'l';
$offset = 4;
$port = get_one_free_port();
$server = new swoole_server("0.0.0.0", $port);
$server->set(['open_length_check' => true, 'package_length_type' => $type, 'package_body_offset' => $offset, 'package_length_offset' => 0, 'log_level' => 4]);
$server->on('receive', function ($server, $fd, $rid, $data) use ($type) {
    assert($data == pack($type, 5) . 'hello');
    $server->shutdown();
});
$server->on('workerStart', function ($server, $wid) use ($type, $port) {
    if ($wid == 0) {
        $cli = new swoole_client(SWOOLE_TCP);
        $cli->connect("127.0.0.1", $port);
        $cli->send(pack($type, 5) . 'hello!');
    }
});
$server->start();
?>
--EXPECT--