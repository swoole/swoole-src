--TEST--
swoole_pdo_odbc: race
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';
$begin = microtime(true);

Co\run(static function (): void {
    $pdo = new PDO(ODBC_DSN);
    $msg = [];
    $n = 2;
    while ($n--) {
        Co\go(function () use ($pdo, &$msg) {
            $statement = $pdo->prepare('SELECT sleep(1) ss');
            try {
                $statement->execute();
                Assert::keyExists($statement->fetchAll(PDO::FETCH_ASSOC)[0], 'ss');
            } catch (\PDOException $e) {
                $msg[] = $e->getMessage();
            }
        });
    }
    Assert::count($msg, 0);
});

Assert::greaterThanEq(microtime(true) - $begin, 2);
echo "Done\n";
?>
--EXPECTF--
Done
