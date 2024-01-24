--TEST--
swoole_pdo_pgsql: test hook pgsql
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_pgsql.inc';

const N = 20;

Co\run(static function (): void {
    $sleep_count = 0;
    Co\go(function () use (&$sleep_count) {
        $n = N;
        while ($n--) {
            Co::sleep(0.002);
            $sleep_count++;
        }
    });
    // disable pdo_pgsql hook
    Swoole\Runtime::enableCoroutine(0);
    $pdo = pdo_pgsql_test_inc::create();
    $statement = $pdo->prepare('SELECT pg_sleep(1)');
    $statement->execute();
    Assert::eq($sleep_count, 0);
    Assert::keyExists($statement->fetchAll(PDO::FETCH_ASSOC)[0], 'pg_sleep');
});

echo "Done\n";
?>
--EXPECTF--
Done
