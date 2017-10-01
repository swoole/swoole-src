--TEST--
swoole_server: send big udp packet to server
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
//最大长度：65535 - UDP包头 8字节 + IP包头 20字节 = 65507
const N = 65507;
require_once __DIR__ . "/../include/swoole.inc";
$port = get_one_free_port();

$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($port)
{
    $client = new swoole_client(SWOOLE_SOCK_UDP, SWOOLE_SOCK_SYNC);
    if (!$client->connect('127.0.0.1', $port))
    {
        exit("connect failed\n");
    }
    $client->send(str_repeat('A',  N));
    $data = $client->recv();
    assert(strlen($data) == N);
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm, $port)
{
    $serv = new swoole_server("127.0.0.1", $port, SWOOLE_BASE, SWOOLE_SOCK_UDP);
    $serv->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $serv->on("workerStart", function ($serv) use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('packet', function ($serv, $data, $client)
    {
        $serv->sendto($client['address'], $client['port'], str_repeat('B', strlen($data)));
    });
    $serv->start();
};


$pm->childFirst();
$pm->run();
?>
--EXPECT--
