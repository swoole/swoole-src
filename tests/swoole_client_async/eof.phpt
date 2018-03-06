--TEST--
swoole_client: eof protocol [async]
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
$port = get_one_free_port();
$pm->parentFunc = function ($pid) use ($port)
{
    $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
    $client->set(['open_eof_check' => true, 'open_eof_split' => true, "package_eof" => "\r\n\r\n"]);

    $client->on("connect", function (swoole_client $cli)
    {
        $cli->send("recv\r\n\r\n");
    });

    $client->on("receive", function(swoole_client $cli, $pkg) use ($pid) {
        static $i = 0;
        $i++;

        //小包
        if ($i <= 1000)
        {
            assert($pkg and strlen($pkg) <= 2048);
            if ($i == 1000)
            {
                echo "SUCCESS\n";
            }
            return;
        }
        //慢速发送
        elseif ($i <= 1100)
        {
            assert($pkg and strlen($pkg) <= 8192);
            if ($i == 1100)
            {
                echo "SUCCESS\n";
            }
            return;
        }
        //大包
        else
        {
            assert($pkg != false);
            $_pkg = unserialize($pkg);
            assert(is_array($_pkg));
            assert($_pkg['i'] == $i - 1100 - 1);
            assert($_pkg['data'] <= 256 * 1024);
            if ($i == 2100) {
                echo "SUCCESS\n";
                $cli->close();
                swoole_process::kill($pid);
            }
        }
    });

    $client->on("error", function(swoole_client $cli) {
        print("error");
    });

    $client->on("close", function(swoole_client $cli) {
        swoole_event_exit();
    });

    if (!$client->connect('127.0.0.1', $port, 0.5, 0))
    {
        echo "Over flow. errno=" . $client->errCode;
        die("\n");
    }
};

$pm->childFunc = function () use ($pm, $port)
{
    $serv = new swoole_server("127.0.0.1", $port, SWOOLE_BASE);
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
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data)
    {
        //小包
        for ($i = 0; $i < 1000; $i++)
        {
            $serv->send($fd, str_repeat('A', rand(100, 2000)) . "\r\n\r\n");
        }
        //慢速发送
        for ($i = 0; $i < 100; $i++)
        {
            $serv->send($fd, str_repeat('A', rand(1000, 2000)));
            usleep(rand(10000, 50000));
            $serv->send($fd, str_repeat('A', rand(2000, 4000)) . "\r\n\r\n");
        }
        //大包
        for ($i = 0; $i < 1000; $i++)
        {
            $serv->send($fd, serialize(['i' => $i, 'data' => str_repeat('A', rand(20000, 256 * 1024))]) . "\r\n\r\n");
        }
    });
    $serv->start();
};
$pm->async = true;
$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
SUCCESS
SUCCESS
