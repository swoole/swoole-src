--TEST--
swoole_client_coro: length protocol func
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    go(function() use ($pm) {
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $client->set([
            'open_length_check' => true,
            'package_max_length' => 1024 * 1024,
            'package_length_func' => function ($data) {
                $n = strpos($data, '|');
                if ($n == false)
                {
                    return -1;
                }
                else
                {
                    return intval(substr($data, 0, $n)) + $n + 1;
                }
            },
        ]);
        if (!$client->connect('127.0.0.1', $pm->getFreePort(), 0.5, 0)) {
            echo "Over flow. errno=" . $client->errCode;
            die("\n");
        }
        $int = rand(1000, 5000);
        $data = json_encode(['data' => RandStr::gen($int), 'index' => 2, 'len' => $int]);
        $client->send(pack('N', strlen($data) + 4) . $data);
        $pkg = $client->recv();
        Assert::assert($pkg != false and strlen($pkg) > 100);
        $pm->kill();
    });
};

$pm->childFunc = function () use ($pm) {
    $serv = new swoole_server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
        'open_length_check' => true,
        'package_max_length' => 1024 * 1024,
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 0,
    ]);
    $serv->on("WorkerStart", function (\swoole_server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data)
    {
        $data = str_repeat('A', rand(100, 2000));
        $serv->send($fd, strlen($data) . "|" . $data);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
