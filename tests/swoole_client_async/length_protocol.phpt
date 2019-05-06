--TEST--
swoole_client_async: length protocol [async]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
    $client->set([
        'open_length_check' => true,
        'package_max_length' => 1024 * 1024,
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 4,
    ]);

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
            Assert::assert($pkg and strlen($pkg) <= 2048);
            if ($i == 1000)
            {
                echo "SUCCESS\n";
            }
            return;
        }
        //慢速发送
        elseif ($i <= 1100)
        {
            Assert::assert($pkg and strlen($pkg) <= 8192);
            if ($i == 1100)
            {
                echo "SUCCESS\n";
            }
            return;
        }
        //大包
        else
        {
            Assert::assert($pkg != false);
            $_pkg = unserialize(substr($pkg, 4));
            Assert::assert(is_array($_pkg));
            Assert::eq($_pkg['i'], $i - 1100 - 1);
            Assert::assert($_pkg['data'] <= 256 * 1024);
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

    if (!$client->connect('127.0.0.1', $pm->getFreePort(), 0.5, 0))
    {
        echo "Over flow. errno=" . $client->errCode;
        die("\n");
    }
};

$pm->childFunc = function () use ($pm)
{
    $serv = new swoole_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set(array(
        "worker_num" => 1,
        'send_yield' => true,
        'log_file' => '/tmp/swoole.log',
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

$pm->async = true;
$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
SUCCESS
SUCCESS
