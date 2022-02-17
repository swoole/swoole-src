--TEST--
swoole_server: dispatch_mode = 10 [concurrent lb]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Constant;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\System;
use Swoole\Http\Server;
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
        $rand = rand(1, 4);
        $data = array(
            'name' => __FILE__,
            'sid' => $pm->magic_code,
            'content' => str_repeat('A', 1024 * $rand),
        );
        $_serialize_data = serialize($data) . EOF;
        $n = N;
        while ($n--) {
            for ($i = 0; $i < 16; $i++) {
                go(function () use ($pm, $_serialize_data) {
                    $client = new Client('127.0.0.1', $pm->getFreePort());
                    Assert::true($client->post('/', $_serialize_data));
                    Assert::eq($client->getStatusCode(), 200);
                    Assert::eq($client->getBody(), "SUCCESS" . EOF);
                });
            }
            System::sleep(0.002);
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
        'dispatch_mode' => SWOOLE_DISPATCH_CONCURRENT_LB,
        'worker_num' => 4,
        'log_file' => '/dev/null',
    ));

    $serv->on(Constant::EVENT_WORKER_START, function (Server $serv, $worker_id) use ($pm) {
        if ($worker_id == 0) {
            $pm->wakeup();
        }
    });

    $serv->on(Constant::EVENT_REQUEST, function ($req, $resp) use ($pm, $table, $serv) {
        $table->incr($serv->getWorkerId(), 'count');
        if (rand(1000, 9999) % 10 == 0) {
            System::sleep(0.5);
        }
        $_data = unserialize(rtrim($req->getContent()));
        if ($_data and is_array($_data) and $_data['sid'] == $pm->magic_code) {
            $resp->end("SUCCESS" . EOF);
        } else {
            $resp->end("ERROR" . EOF);
        }
    });

    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
