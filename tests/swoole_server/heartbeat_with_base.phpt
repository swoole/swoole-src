--TEST--
swoole_server: heart beat with SWOOLE_BASE
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

$port = get_one_free_port();

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($port)
{
    $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    if (!$client->connect('127.0.0.1', 9501, 5, 0))
    {
        echo "Over flow. errno=" . $client->errCode;
        die("\n");
    }
    $s1 = time();
    assert($client->recv() === '');
    $s2 = time();
    assert($s2 - $s1 > 1);
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm, $port)
{
    $serv = new swoole_server("127.0.0.1", 9501, SWOOLE_BASE);
    $serv->set(array(
        'heartbeat_check_interval' => 1,
        'heartbeat_idle_time' => 2,
    ));
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data)
    {
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--

