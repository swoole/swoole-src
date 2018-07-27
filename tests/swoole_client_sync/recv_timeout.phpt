--TEST--
swoole_client_sync: recv timeout

--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($pm)
{
    $client = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $r = $client->connect(TCP_SERVER_HOST, 9501, 0.5);
    assert($r);
    $client->send(pack('N', filesize(TEST_IMAGE)));
    $data = @$client->recv();
    assert($data == false);
    assert($client->errCode == SOCKET_EAGAIN);
    $pm->kill();
    $client->close();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new \swoole_server(TCP_SERVER_HOST, 9501, SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
    ]);
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on("Receive", function (\swoole_server $serv, $fd, $rid, $data)
    {
        //do nothing
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
