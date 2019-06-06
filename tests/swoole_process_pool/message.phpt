--TEST--
swoole_process_pool: simple send test
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $client = new swoole_client(SWOOLE_SOCK_TCP);
    Assert::assert($client->connect('127.0.0.1', 8089, 5));
    $data = "hello swoole!";
    $client->send(pack('N', strlen($data)) . $data);
    $ret = $client->recv();
    $len = unpack('Nlen', substr($ret, 0, 4))['len'];
    $ret .= $client->recv($len - (strlen($ret) - 4));
    $ret = substr($ret, 4, $len);
    echo $ret;
    $client->close();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $pool = new Swoole\Process\Pool(1, SWOOLE_IPC_SOCKET);

    $pool->on('workerStart', function (Swoole\Process\Pool $pool, int $workerId) {
        $client = new swoole_client(SWOOLE_SOCK_TCP);
        Assert::assert($client->connect('127.0.0.1', 8089, 5));
        $data = "hello swoole! (from workerStart)";
        $client->send(pack('N', strlen($data)) . $data);
        $client->close();
    });

    $pool->on("message", function (Swoole\Process\Pool $pool, string $message) {
        echo "{$message}\n";
        if ($message === "hello swoole!") {
            $pool->write("hello ");
            $pool->write("client!");
            $pool->write("\n");
        }
    });

    $pool->listen('127.0.0.1', 8089);

    $pool->start();
};

$pm->childFirst();
$pm->run();

?>
--EXPECT--
hello swoole! (from workerStart)
hello swoole!
hello client!
