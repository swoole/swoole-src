--TEST--
swoole_pdo_pgsql: long running pgsql test
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_pgsql.inc';

use Swoole\Coroutine;
use Swoole\Coroutine\WaitGroup;
use Swoole\Coroutine\Channel;
use function Swoole\Coroutine\run;

Coroutine::set(['hook_flags' => SWOOLE_HOOK_PDO_PGSQL]);
run(function() {
    $waitGroup = new WaitGroup();
    $channel = new Channel(1);
    Coroutine::create(function() use ($waitGroup, $channel) {
        $waitGroup->add();
        $pdo = pdo_pgsql_test_inc::create();
        $pdo->query("SELECT pg_sleep(5);");
        $waitGroup->done();
        echo 'DONE' . PHP_EOL;
    });

    Coroutine::create(function() use ($waitGroup, $channel) {
        $waitGroup->add();
        $result = $channel->pop(2);
        if (!$result) {
            echo 'channel pop timeout' . PHP_EOL;
        }
        $waitGroup->done();
    });

    var_dump(1);
    Coroutine::sleep(1);
    var_dump(2);
    $waitGroup->wait();
});
?>
--EXPECTF--
int(1)
int(2)
channel pop timeout
DONE
