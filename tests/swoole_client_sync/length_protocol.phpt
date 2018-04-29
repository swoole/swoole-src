--TEST--
swoole_client: length protocol [sync]
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
$port = get_one_free_port();
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($port)
{
    $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $client->set([
        'open_length_check' => true,
        'package_max_length' => 1024 * 1024,
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 4,
    ]);
    if (!$client->connect('127.0.0.1', $port, 0.5, 0))
    {
        echo "Over flow. errno=" . $client->errCode;
        die("\n");
    }

    $client->send("recv\r\n\r\n");

    //小包
    for ($i = 0; $i < 1000; $i++)
    {
        $pkg = $client->recv();
        assert($pkg and strlen($pkg) <= 2048);
    }
    echo "SUCCESS\n";
    //慢速发送
    for ($i = 0; $i < 100; $i++)
    {
        $pkg = $client->recv();
        assert($pkg and strlen($pkg) <= 8192);
    }
    echo "SUCCESS\n";
    //大包
    for ($i = 0; $i < 1000; $i++)
    {
        $pkg = $client->recv();
        assert($pkg != false);
        $_pkg = unserialize(substr($pkg, 4));
        assert(is_array($_pkg));
        assert($_pkg['i'] == $i);
        assert($_pkg['data'] <= 256 * 1024);
    }
    echo "SUCCESS\n";
    $client->close();

    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm, $port)
{
    $serv = new swoole_server("127.0.0.1", $port, SWOOLE_BASE);
    $serv->set(array(
        "worker_num" => 1,
        'log_file' => '/dev/null',
    ));
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data)
    {
        //小包
        for ($i = 0; $i < 1000; $i++)
        {
            $data = str_repeat('A', rand(100, 2000));
            $serv->send($fd, pack('N', strlen($data)) . $data);
        }
        //慢速发送
        for ($i = 0; $i < 100; $i++)
        {
            $data = str_repeat('A', rand(3000, 6000));
            $n = rand(1000, 2000);
            $serv->send($fd, pack('N', strlen($data)). substr($data, 0, $n));
            usleep(rand(10000, 50000));
            $serv->send($fd, substr($data, $n));
        }
        //大包
        for ($i = 0; $i < 1000; $i++)
        {
            $data = serialize(['i' => $i, 'data' => str_repeat('A', rand(20000, 256 * 1024))]);
            $serv->send($fd, pack('N', strlen($data)) . $data);
        }
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
SUCCESS
SUCCESS
