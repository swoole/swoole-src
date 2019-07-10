--TEST--
swoole_runtime: pdo create outside coroutine
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_pdo_not_support_mysql8();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine(false);
$start = microtime(true);
$pdo_map = [];
for ($i = 5; $i--;) {
    $pdo_map[] = new PDO(
        "mysql:host=" . MYSQL_SERVER_HOST . ";port=" . MYSQL_SERVER_PORT . ";dbname=" . MYSQL_SERVER_DB . ";charset=utf8",
        MYSQL_SERVER_USER, MYSQL_SERVER_PWD
    );
}

Swoole\Runtime::enableCoroutine(true);
for ($i = 5; $i--;) {
    $pdo = $pdo_map[$i];
    go(function () use ($pdo) {
        $pdo->exec("SELECT sleep(0.1)");
        Assert::same($pdo->errorCode(), PDO::ERR_NONE);
    });
}
swoole_event_wait();
Assert::assert((microtime(true) - $start) > 5 * 0.1);
echo "DONE\n";
?>
--EXPECT--
DONE
