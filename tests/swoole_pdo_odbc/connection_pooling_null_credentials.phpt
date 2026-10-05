--TEST--
swoole_pdo_odbc: connection pooling with omitted and null credentials
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip('ODBC driver is required', !in_array('odbc', PDO::getAvailableDrivers(), true));
?>
--INI--
pdo_odbc.connection_pooling=strict
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Co\run(function () {
    for ($round = 0; $round < 4; $round++) {
        $wg = new Swoole\Coroutine\WaitGroup();
        for ($i = 0; $i < 2; $i++) {
            $wg->add();
            Co\go(function () use ($wg, $round) {
                $pdo = match ($round) {
                    0 => new PDO(ODBC_DSN),
                    1 => new PDO(ODBC_DSN, null, null),
                    2 => new PDO(ODBC_DSN, MYSQL_SERVER_USER, null),
                    3 => new PDO(ODBC_DSN, null, MYSQL_SERVER_PWD),
                };
                Assert::eq($pdo->query('SELECT 1')->fetchColumn(), 1);
                $wg->done();
            });
        }
        $wg->wait();
    }
});

echo "DONE\n";
?>
--EXPECT--
DONE
