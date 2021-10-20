--TEST--
swoole_server: dispatch_mode = 9 [co req lb]
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

const N = 1024;
const EOF = "\r\n\r\n";

$pm = new SwooleTest\ProcessManager;
$pm->magic_code = rand(10000000, 90000000);
$pm->parentFunc = function ($pid) use ($pm, $table) {
    run(function () use ($pm, $table) {
        $client = new Client(SWOOLE_SOCK_TCP);
        $client->set(array(
            'package_eof' => EOF,
            'open_eof_check' => true,
            'open_eof_split' => true,
        ));
        if (!$client->connect('127.0.0.1', $pm->getFreePort(), 0.5, 0)) {
            echo "Over flow. errno=" . $client->errCode;
            die("\n");
        }

        $rand = rand(1, 4);

        $data = array(
            'name' => __FILE__,
            'sid' => $pm->magic_code,
            'content' => str_repeat('A', 1024 * $rand),
        );

        $_serialize_data = serialize($data) . EOF;

        go(function () use ($client) {
            $n = N;
            while ($n--) {
                Assert::eq($client->recv(), "SUCCESS" . EOF);
            }
            $client->close();
        });

        $n = N;
        while ($n--) {
            $client->send($_serialize_data);
            if ($n % 10 == 1) {
                System::sleep(0.002);
            }
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
        'dispatch_mode' => 9,
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

    $serv->on('receive', function (Server $serv, $fd, $rid, $data) use ($pm, $table) {
        $table->incr($serv->getWorkerId(), 'count');
        if (rand(1000, 9999) % 10 == 0) {
            System::sleep(0.5);
        }
        $_data = unserialize(rtrim($data));
        if ($_data and is_array($_data) and $_data['sid'] == $pm->magic_code) {
            $serv->send($fd, "SUCCESS".EOF);
        } else {
            $serv->send($fd, "ERROR".EOF);
        }
    });

    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
