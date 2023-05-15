--TEST--
swoole_pdo_pgsql: race
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';
Co::set(['trace_flags' => SWOOLE_TRACE_CO_ODBC, 'log_level' => SWOOLE_LOG_DEBUG]);
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
                var_dump('sss');
            } catch (\PDOException $e) {
                $msg[] = $e->getMessage();
            }
        });
    }

    var_dump($msg);

//    Assert::count($msg, 1);
//    Assert::contains($msg[0], 'SQLSTATE[HY000]: General error');
});

echo "Done\n";
?>
--EXPECTF--
Done
