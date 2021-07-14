--TEST--
swoole_server: dispatch_mode = 8 [co conn lb]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Client;
use Swoole\Coroutine\System;
use Swoole\Server;
use Swoole\Table;

use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

$table = new Table(64);
$table->column('count', Table::TYPE_INT);
$table->create();

$pm = new SwooleTest\ProcessManager;
$pm->magic_code = rand(10000000, 90000000);
$pm->parentFunc = function ($pid) use ($pm, $table) {
    run(function () use ($pm, $table) {
        $n = 200;
        while ($n--) {
            go(function () use ($pm, $table) {
                $client = new Client(SWOOLE_SOCK_TCP);
                if (!$client->connect('127.0.0.1', $pm->getFreePort(), 0.5, 0)) {
                    echo "Over flow. errno=" . $client->errCode;
                    die("\n");
                }

                $data = array(
                    'name' => __FILE__,
                    'sid' => $pm->magic_code,
                    'content' => str_repeat('A', 8192 * rand(1, 3)),
                );

                $_serialize_data = serialize($data) . "\r\n\r\n";
                $client->send($_serialize_data);
                Assert::eq($client->recv(), "SUCCESS\n");
            });
        }
    });

    $pm->kill();

    $array = array_column(iterator_to_array($table), 'count');
    $standard_deviation = sqrt(swoole_get_variance(swoole_get_average($array), $array));
    Assert::greaterThan($standard_deviation, 1);
    Assert::lessThan($standard_deviation, 5);
    echo 'DONE' . PHP_EOL;
};

$pm->childFunc = function () use ($pm, $table) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $serv->set(array(
        'package_eof' => "\r\n\r\n",
        'open_eof_check' => true,
        'open_eof_split' => true,
        'dispatch_mode' => 8,
        'package_max_length' => 1024 * 1024 * 2,
        "worker_num" => 4,
        'log_file' => '/dev/null',
        "reload_async" => true,
    ));
    $serv->on("WorkerStart", function (Server $serv, $worker_id) use ($pm) {
        if ($worker_id == 0) {
            $pm->wakeup();
        }
    });
    $serv->on('connect', function (Server $serv, $fd, $rid) use ($table) {
        $table->incr($serv->getWorkerId(), 'count');
        if (rand(1000, 9999) % 4 == 0) {
            System::sleep(0.5);
        }
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $data) use ($pm) {
        Assert::eq($serv->getClientInfo($fd)['worker_id'], $serv->getWorkerId());
        $_data = unserialize(rtrim($data));
        if ($_data and is_array($_data) and $_data['sid'] == $pm->magic_code) {
            $serv->send($fd, "SUCCESS\n");
        } else {
            $serv->send($fd, "ERROR\n");
        }
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
