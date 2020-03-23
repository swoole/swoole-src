--TEST--
swoole_server: enable_reuse_port
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

const N = IS_IN_TRAVIS ? 32 : 128;
const W = 4;

$pm = new SwooleTest\ProcessManager;
$count = new Swoole\Atomic(0);

$pm->parentFunc = function ($pid) use ($pm) {
    $c = new Swoole\Coroutine\Scheduler();

    $workerCounter = [];

    $c->parallel(
        N,
        function () use ($pm, &$workerCounter) {
            $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
            if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
                echo "Over flow. errno=" . $client->errCode;
                die("\n");
            }

            $data = base64_decode(random_bytes(rand(1024, 8192))) . "\r\n\r\n";;
            $client->send($data);
            $data = $client->recv();
            Assert::assert($data);
            $json = json_decode($data);
            if (!isset($workerCounter[$json->worker])) {
                $workerCounter[$json->worker] = 0;
            }
            $workerCounter[$json->worker]++;
        }
    );

    $c->start();
    $pm->kill();

    foreach ($workerCounter as $c) {
        Assert::greaterThan($c, N / W / 2);
    }
};

$pm->childFunc = function () use ($pm, $count) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set(
        array(
            'package_eof' => "\r\n\r\n",
            'open_eof_check' => true,
            'open_eof_split' => true,
            'enable_reuse_port' => true,
            'package_max_length' => 1024 * 1024 * 2, //2M
            "worker_num" => W,
            'log_file' => '/dev/null',
        )
    );
    $serv->on(
        "workerStart",
        function (Server $serv) use ($pm, $count) {
            $count->add(1);
            if ($count->get() == $serv->setting['worker_num']) {
                $pm->wakeup();
            }
        }
    );
    $serv->on(
        'receive',
        function (Server $serv, $fd, $rid, $data) {
            $serv->send($fd, json_encode(['worker' => $serv->getWorkerId()]));
        }
    );
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
