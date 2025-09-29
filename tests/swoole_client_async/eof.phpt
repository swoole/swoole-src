--TEST--
swoole_client_async: eof protocol [async]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$port = get_one_free_port();
$pm->parentFunc = function ($pid) use ($port) {
    $client = new Swoole\Async\Client(SWOOLE_SOCK_TCP);
    $client->set(['open_eof_check' => true, 'open_eof_split' => true, "package_eof" => "\r\n\r\n"]);

    $client->on("connect", function (Swoole\Async\Client $cli) {
        $cli->send("recv\r\n\r\n");
    });

    $client->on("receive", function (Swoole\Async\Client $cli, $pkg) use ($pid) {
        static $i = 0;
        $i++;

        Assert::assert($pkg != false);
        Assert::assert(str_ends_with($pkg, "\r\n\r\n"));

        //小包
        if ($i <= 1000) {
            Assert::assert($pkg and strlen($pkg) <= 2048);
            if ($i == 1000) {
                echo "SUCCESS\n";
            }
        } //慢速发送
        elseif ($i <= 1100) {
            Assert::assert($pkg and strlen($pkg) <= 8192);
            if ($i == 1100) {
                echo "SUCCESS\n";
            }
        } //大包
        else {
            $_pkg = unserialize(substr($pkg, 0, strlen($pkg) - 4));
            Assert::assert(is_array($_pkg));
            Assert::same($_pkg['i'], $i - 1100 - 1);
            Assert::same(md5($_pkg['data']), $_pkg['md5']);
            Assert::lengthBetween($_pkg['data'], 20000, 256 * 1024 * 1.5);
            if ($i == 2100) {
                echo "SUCCESS\n";
                $cli->close();
                Swoole\Process::kill($pid);
            }
        }
    });

    $client->on("error", function (Swoole\Async\Client $cli) {
        echo "ERROR\n";
    });

    $client->on("close", function (Swoole\Async\Client $cli) {
        echo "CLOSE\n";
        Swoole\Event::exit();
    });

    if (!$client->connect('127.0.0.1', $port, 0.5, 0)) {
        echo "Over flow. errno=" . $client->errCode;
        die("\n");
    }
};

$pm->childFunc = function () use ($pm, $port) {
    $serv = new Swoole\Server('127.0.0.1', $port, SWOOLE_BASE);
    $serv->set(array(
        'package_eof' => "\r\n\r\n",
        'open_eof_check' => true,
        'open_eof_split' => true,
        'package_max_length' => 1024 * 1024 * 2,
        'socket_buffer_size' => 128 * 1024 * 1024,
        'worker_num' => 1,
        'log_file' => TEST_LOG_FILE,
        'send_yield' => true,
    ));
    $serv->on("WorkerStart", function (\Swoole\Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function (Swoole\Server $serv, $fd, $rid, $data) {
        //小包
        for ($i = 0; $i < 1000; $i++) {
            $serv->send($fd, str_repeat('A', rand(100, 2000)) . "\r\n\r\n");
        }
        //慢速发送
        for ($i = 0; $i < 100; $i++) {
            $serv->send($fd, str_repeat('A', rand(1000, 2000)));
            usleep(rand(10000, 50000));
            $serv->send($fd, str_repeat('A', rand(2000, 4000)) . "\r\n\r\n");
        }
        //大包
        for ($i = 0; $i < 1000; $i++) {
            $data = base64_encode(random_bytes(random_int(20000, 256 * 1024)));
            $md5 = md5($data);
            $serv->send($fd, serialize(['i' => $i, 'md5' => $md5, 'data' => $data]) . "\r\n\r\n");
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
CLOSE
