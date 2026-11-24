--TEST--
swoole_pdo_pgsql: Github bug #5635
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
    $waitGroup->add(2);
    $channel = new Channel(1);

    Coroutine::create(function() use ($waitGroup, $channel) {
        $pdo = pdo_pgsql_test_inc::create();
        // Exercise a pending database read without inserting or retaining millions of rows.
        $stmt = $pdo->query("SELECT 1 AS id, 'data1' AS data FROM pg_sleep(0.2)");
        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
        Assert::same(count($data), 1);
        Assert::same((int) $data[0]['id'], 1);
        Assert::same($data[0]['data'], 'data1');
        $channel->push($data);
        $waitGroup->done();
        echo 'DONE' . PHP_EOL;
    });

    Coroutine::create(function() use ($waitGroup, $channel) {
        $result = $channel->pop(0.05);
        Assert::false($result);
        if (!$result) {
            echo 'channel pop timeout' . PHP_EOL;
        }
        $waitGroup->done();
    });

    var_dump(1);
    Coroutine::sleep(0.02);
    var_dump(2);
    $waitGroup->wait();
});
?>
--EXPECTF--
int(1)
int(2)
channel pop timeout
DONE
