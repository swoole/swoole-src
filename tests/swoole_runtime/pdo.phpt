--TEST--
swoole_runtime: pdo
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_php_version_lower_than('7.1');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();

function mysql_sleep(float $time)
{
    $pdo = new PDO(
        "mysql:host=" . MYSQL_SERVER_HOST . ";dbname=" . MYSQL_SERVER_DB . ";charset=utf8",
        MYSQL_SERVER_USER, MYSQL_SERVER_PWD
    );
    $pdo->exec("SELECT sleep({$time})");
}

function onRequest()
{
    mysql_sleep(.1);
}

$start = microtime(true);
for ($i = MAX_CONCURRENCY_LOW; $i--;) {
    go('onRequest');
}
swoole_event_wait();
assert((microtime(true) - $start) < .2);
echo "DONE\n";
?>
--EXPECT--
DONE
