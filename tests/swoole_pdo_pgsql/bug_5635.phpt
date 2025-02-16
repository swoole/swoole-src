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

ini_set("memory_limit", "-1");

$pdo = pdo_pgsql_test_inc::create();
$pdo->exec('create table bug_5635 (id int, data varchar(1024));');
$pdo->exec(<<<EOL
DO $$
BEGIN
FOR i IN 1..5000000 LOOP
INSERT INTO bug_5635(id, data) VALUES (i, 'data' || i);
END LOOP;
END $$;
EOL);

Coroutine::set(['hook_flags' => SWOOLE_HOOK_PDO_PGSQL]);
run(function() {
    $waitGroup = new WaitGroup();
    $channel = new Channel(1);

    Coroutine::create(function() use ($waitGroup, $channel) {
        $start = time();
        $waitGroup->add();
        $pdo = pdo_pgsql_test_inc::create();
        $stmt = $pdo->query("select * from bug_5635;");
        $data = $stmt->fetchAll();
        Assert::true(count($data) == 5000000);
        $channel->push($data ?? [], 10);
        $waitGroup->done();
        echo 'DONE' . PHP_EOL;
    });

    Coroutine::create(function() use ($waitGroup, $channel) {
        $waitGroup->add();
        $result = $channel->pop(1.5);
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
--CLEAN--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_pgsql.inc';
$pdo = pdo_pgsql_test_inc::create();
$pdo->exec('drop table bug_5635;');
?>
--EXPECTF--
int(1)
int(2)
channel pop timeout
DONE
