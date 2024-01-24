--TEST--
swoole_pdo_odbc: test hook pgsql
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';

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
    $pdo = new PDO(ODBC_DSN);
    $statement = $pdo->prepare('SELECT sleep(1) ss');
    $statement->execute();
    Assert::eq($sleep_count, N);
    Assert::keyExists($statement->fetchAll(PDO::FETCH_ASSOC)[0], 'ss');
});

echo "Done\n";
?>
--EXPECTF--
Done
