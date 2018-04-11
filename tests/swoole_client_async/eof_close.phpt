--TEST--
swoole_client: eof protocol [async] [close]
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

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
    $client->set(['open_eof_check' => true, 'open_eof_split' => true, "package_eof" => "\r\n\r\n"]);

    $client->on("connect", function (swoole_client $cli)
    {
        $cli->send("recv\r\n\r\n");
    });

    $client->on("receive", function (swoole_client $cli, $pkg) use ($pid, $pm) {
        echo "RECEIVED\n";
        $cli->close();
        $pm->kill();
    });

    $client->on("error", function(swoole_client $cli) {
        print("error");
    });

    $client->on("close", function(swoole_client $cli) {
        echo "CLOSED\n";
    });

    if (!$client->connect('127.0.0.1', 9501, 0.5, 0))
    {
        echo "Over flow. errno=" . $client->errCode;
        die("\n");
    }
};

$pm->childFunc = function () use ($pm)
{
    $serv = new swoole_server("127.0.0.1", 9501, SWOOLE_BASE);
    $serv->set(array(
        'package_eof' => "\r\n\r\n",
        'open_eof_check' => true,
        'open_eof_split' => true,
        'dispatch_mode' => 3,
        'package_max_length' => 1024 * 1024 * 2, //2M
        'socket_buffer_size' => 128 * 1024 * 1024,
        "worker_num" => 1,
        'log_file' => '/dev/null',
    ));
    $serv->on("WorkerStart", function (\swoole_server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data) {
        $serv->send($fd, str_repeat('A', rand(100, 2000)) . "\r\n\r\n");
    });
    $serv->start();
};
$pm->async = true;
$pm->childFirst();
$pm->run();
?>
--EXPECT--
RECEIVED
CLOSED
