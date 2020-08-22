--TEST--
swoole_event: add event after server start
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

const FILE = __DIR__.'/tmp_result.txt';

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $pm->kill();
    $str = swoole_string(file_get_contents(FILE));
    Assert::true($str->contains('HTTP/1.1 302 Moved Temporarily') or $str->contains('HTTP/1.1 301 Moved Permanently'));
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort());
    $serv->set(array(
        "worker_num" => 1,
        'log_file' => '/dev/null',
    ));
    $serv->on("start", function (Server $serv) use ($pm) {
        $fp = stream_socket_client("tcp://www.qq.com:80", $errno, $errstr, 30);
        fwrite($fp, "GET / HTTP/1.1\r\nHost: www.qq.com\r\n\r\n");

        swoole_event_add($fp, function ($fp) use ($pm) {
            $resp = fread($fp, 8192);
            swoole_event_del($fp);
            fclose($fp);
            file_put_contents(FILE, $resp);
            $pm->wakeup();
        });
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $data) {

    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
unlink(FILE);
?>
--EXPECT--
