--TEST--
swoole_server: eof server
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
    if (!$client->connect('127.0.0.1', 9501, 0.5, 0))
    {
        echo "Over flow. errno=" . $client->errCode;
        die("\n");
    }

    $data = array(
        'name' => __FILE__,
        'sid' => 1000236,
        'content' => str_repeat('A', 8192 * rand(1, 3)),
    );

    $_serialize_data = serialize($data). "\r\n\r\n";;

    $chunk_size = 2048;
    $len = strlen($_serialize_data);
    $chunk_num = intval($len / $chunk_size) + 1;
    for ($i = 0; $i < $chunk_num; $i++)
    {
        if ($len < ($i + 1) * $chunk_size)
        {
            $sendn = $len - ($i * $chunk_size);
        }
        else
        {
            $sendn = $chunk_size;
        }
        $client->send(substr($_serialize_data, $i * $chunk_size, $sendn));
        usleep(10000);
    }
    echo $client->recv();
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm, $port)
{
    $serv = new swoole_server("127.0.0.1", 9501, SWOOLE_BASE);
    $serv->set(array(
        'package_eof' => "\r\n\r\n",
        'open_eof_check' => true,
        'open_eof_split' => true,
        'dispatch_mode' => 3,
        'package_max_length' => 1024 * 1024 * 2, //2M
        "worker_num" => 1,
        'log_file' => '/dev/null',
    ));
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data)
    {
        $_data = unserialize(rtrim($data));
        if ($_data and is_array($_data) and $_data['sid'] == 1000236)
        {
            $serv->send($fd, "SUCCESS");
        }
        else
        {
            $serv->send($fd, "ERROR");
        }
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
