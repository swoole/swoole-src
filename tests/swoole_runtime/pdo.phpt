--TEST--
swoole_runtime: pdo
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_pdo_not_support_mysql8();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();
$count = 0;

function mysql_sleep(float $time)
{
    $pdo = new PDO(
        "mysql:host=" . MYSQL_SERVER_HOST . ";port=" . MYSQL_SERVER_PORT . ";dbname=" . MYSQL_SERVER_DB . ";charset=utf8",
        MYSQL_SERVER_USER, MYSQL_SERVER_PWD
    );
    $pdo->exec("SELECT sleep({$time})");
    if (Assert::assert($pdo->errorCode() ===  PDO::ERR_NONE)){
        global $count;
        $count++;
    }
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
Assert::same($count, MAX_CONCURRENCY_LOW);
Assert::assert((microtime(true) - $start) < .5);
//关闭协程，否则会致命错误
Swoole\Runtime::enableCoroutine(false);
mysql_sleep(.1); //block IO
echo "DONE\n";
?>
--EXPECT--
DONE
