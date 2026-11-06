--TEST--
swoole_pdo_odbc: statements with bound parameters do not block the event loop
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';

const N = 20;

Co\run(static function (): void {
    // pdo_odbc binds string parameters as data-at-execution, so the statement is sent and
    // awaited in SQLParamData rather than in SQLExecute
    $sleep_count = 0;
    Co\go(function () use (&$sleep_count) {
        $n = N;
        while ($n--) {
            Co::sleep(0.002);
            $sleep_count++;
        }
    });
    $pdo = new PDO(ODBC_DSN);
    $statement = $pdo->prepare('SELECT sleep(?) ss');
    $statement->execute(['1']);
    Assert::eq($sleep_count, N);
    Assert::keyExists($statement->fetchAll(PDO::FETCH_ASSOC)[0], 'ss');

    $begin = microtime(true);
    $wg = new Co\WaitGroup();
    for ($i = 0; $i < 4; $i++) {
        $wg->add();
        Co\go(function () use ($wg) {
            $statement = (new PDO(ODBC_DSN))->prepare('SELECT sleep(?) ss');
            $statement->execute(['1']);
            Assert::keyExists($statement->fetchAll(PDO::FETCH_ASSOC)[0], 'ss');
            $wg->done();
        });
    }
    $wg->wait();
    Assert::lessThan(microtime(true) - $begin, 2);
});

echo "Done\n";
?>
--EXPECTF--
Done
