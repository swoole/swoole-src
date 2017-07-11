--TEST--
swoole_client: sync sendfile

--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
$port = get_one_free_port();
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($port)
{
    $client = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $r = $client->connect(TCP_SERVER_HOST, $port, 0.5);
    assert($r);
    $client->send(pack('N', filesize(TEST_IMAGE)));
    $ret = $client->sendfile(TEST_IMAGE);
    assert($ret);

    $data = $client->recv();
    $client->send(pack('N', 8) . 'shutdown');
    $client->close();
    assert($data === md5_file(TEST_IMAGE));
};

$pm->childFunc = function () use ($pm, $port)
{
    $serv = new \swoole_server(TCP_SERVER_HOST, $port, SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
        'open_length_check' => true,
        'dispatch_mode' => 1,
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 4,
        'package_max_length' => 2000000,
    ]);
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on("Receive", function (\swoole_server $serv, $fd, $rid, $data)
    {
        if (substr($data, 4, 8) == 'shutdown')
        {
            $serv->shutdown();
            return;
        }
        $serv->send($fd, md5(substr($data, 4)));
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
