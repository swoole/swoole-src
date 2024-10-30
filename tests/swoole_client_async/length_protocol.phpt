--TEST--
swoole_client_async: length protocol [async]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $client = new Swoole\Async\Client(SWOOLE_SOCK_TCP);
    $client->set([
        'open_length_check' => true,
        'package_max_length' => 1024 * 1024,
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 4,
    ]);

    $client->on("connect", function (Swoole\Async\Client $cli) {
        $cli->send("recv\r\n\r\n");
    });

    $client->on("receive", function (Swoole\Async\Client $cli, $pkg) use ($pid) {
        static $i = 0;
        $i++;

        //小包
        if ($i <= 1000) {
            Assert::assert($pkg and strlen($pkg) <= 2048);
            if ($i == 1000) {
                echo "SUCCESS\n";
            }
            return;
        } //慢速发送
        elseif ($i <= 1100) {
            Assert::assert($pkg and strlen($pkg) <= 8192);
            if ($i == 1100) {
                echo "SUCCESS\n";
            }
            return;
        } //大包
        else {
            Assert::assert($pkg != false);
            $_pkg = unserialize(substr($pkg, 4));
            Assert::assert(is_array($_pkg));
            Assert::same($_pkg['i'], $i - 1100 - 1);
            Assert::lengthBetween($_pkg['data'], 20000, 256 * 1024);
            if ($i == 2100) {
                echo "SUCCESS\n";
                $cli->close();
                Swoole\Process::kill($pid);
            }
        }
    });

    $client->on("error", function (Swoole\Async\Client $cli) {
        print("error");
    });

    $client->on("close", function (Swoole\Async\Client $cli) {
        Swoole\Event::exit();
    });

    if (!$client->connect('127.0.0.1', $pm->getFreePort(), 0.5, 0)) {
        echo "Over flow. errno=" . $client->errCode;
        die("\n");
    }
};

$pm->childFunc = function () use ($pm) {
    $serv = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set(array(
        "worker_num" => 1,
        'send_yield' => true,
        'log_file' => '/tmp/swoole.log',
    ));
    $serv->on("WorkerStart", function (\Swoole\Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function (Swoole\Server $serv, $fd, $rid, $data) {
        //小包
        for ($i = 0; $i < 1000; $i++) {
            $data = str_repeat('A', rand(100, 2000));
            $serv->send($fd, pack('N', strlen($data)) . $data);
        }
        //慢速发送
        for ($i = 0; $i < 100; $i++) {
            $data = str_repeat('A', rand(3000, 6000));
            $n = rand(1000, 2000);
            $serv->send($fd, pack('N', strlen($data)) . substr($data, 0, $n));
            usleep(rand(10000, 50000));
            $serv->send($fd, substr($data, $n));
        }
        //大包
        for ($i = 0; $i < 1000; $i++) {
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
