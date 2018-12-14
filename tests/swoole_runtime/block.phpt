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
Swoole\Runtime::enableCoroutine();

$start = microtime(true);
$pdo_map = [];
for ($i = 5; $i--;) {
    $pdo_map[] = new PDO(
        "mysql:host=" . MYSQL_SERVER_HOST . ";dbname=" . MYSQL_SERVER_DB . ";charset=utf8",
        MYSQL_SERVER_USER, MYSQL_SERVER_PWD
    );
}
for ($i = 5; $i--;) {
    $pdo = $pdo_map[$i];
    go(function () use ($pdo) {
        $pdo->exec("SELECT sleep(0.1)");
        assert($pdo->errorCode() === PDO::ERR_NONE);
    });
}
swoole_event_wait();
assert((microtime(true) - $start) > 5 * 0.1);
echo "DONE\n";
?>
--EXPECT--
DONE
