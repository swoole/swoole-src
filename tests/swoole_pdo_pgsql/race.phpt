--TEST--
swoole_pdo_pgsql: race
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_pgsql.inc';

Co\run(static function (): void {
    $pdo = pdo_pgsql_test_inc::create();
    $msg = [];
    $n = 2;

    while ($n--) {
        Co\go(function () use ($pdo, &$msg) {
            $statement = $pdo->prepare('SELECT pg_sleep(1)');
            try {
                $statement->execute();
                Assert::keyExists($statement->fetchAll(PDO::FETCH_ASSOC)[0], 'pg_sleep');
            } catch (\PDOException $e) {
                $msg[] = $e->getMessage();
            }
        });
    }
    Assert::count($msg, 1);
    Assert::contains($msg[0], 'SQLSTATE[HY000]: General error');
});

echo "Done\n";
?>
--EXPECTF--
Done
