--TEST--
swoole_server: check chunk total size
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Server;
use Swoole\Client;
use Swoole\Process;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm)
{
    $client = new Client(SWOOLE_SOCK_TCP);
    if (!$client->connect('127.0.0.1', $pm->getFreePort(), 0.5, 0))
    {
        echo "Over flow. errno=" . $client->errCode;
        die("\n");
    }

    $data = str_repeat('A', 1 * 1024 * 1024) . "\r\n";
    $chunk_size = 2048;
    $len = strlen($data);
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
        $client->send(substr($data, $i * $chunk_size, $sendn));
    }
    $recv_data = $client->recv();
    Process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set(array(
        'package_eof' => "\r\n",
        'open_eof_check' => true,
        "worker_num" => 1,
    ));
    $serv->on("WorkerStart", function (Server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $data)
    {
        Assert::length($data, 1 * 1024 * 1024 + 2);
        $serv->send($fd, "shutdown");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
