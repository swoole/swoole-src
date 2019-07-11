--TEST--
swoole_server: max_request
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$counter = new swoole_atomic();

$pm->parentFunc = function ($pid) use ($pm)
{
    $client = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $client->set(["open_eof_check" => true, "package_eof" => "\r\n\r\n"]);
    $r = $client->connect('127.0.0.1', $pm->getFreePort(), -1);
    if ($r === false)
    {
        echo "ERROR";
        exit;
    }
    for ($i = 0; $i < 4000; $i++)
    {
        $data = "PKG-$i" . str_repeat('A', rand(100, 20000)) . "\r\n\r\n";
        if ($client->send($data) === false) {
            echo "send error\n";
            break;
        }
        $ret = $client->recv();
        Assert::same(strlen($ret), strlen($data) + 8);
    }
    $client->close();
    global $counter;
    Assert::assert($counter->get() > 10);
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    $serv = new \swoole_server('127.0.0.1', $pm->getFreePort());
    $serv->set([
        "worker_num" => 4,
        'dispatch_mode' => 1,
        "open_eof_split" => true,
        "package_eof" => "\r\n\r\n",
        'max_request' => 200,
        'log_file' => '/dev/null',
    ]);
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        global $counter;
        $counter->add(1);
        $pm->wakeup();
    });
    $serv->on("Receive", function (\swoole_server $serv, $fd, $reactorId, $data)
    {
        $serv->send($fd, "Server: $data");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();

?>
--EXPECT--
