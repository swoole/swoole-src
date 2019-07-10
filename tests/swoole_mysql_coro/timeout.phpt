--TEST--
swoole_mysql_coro: timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
for ($c = MAX_CONCURRENCY_LOW; $c--;) {
    go(function () {
        $mysql = new Swoole\Coroutine\MySQL;
        $connected = $mysql->connect([
            'host' => MYSQL_SERVER_HOST,
            'port' => MYSQL_SERVER_PORT,
            'user' => MYSQL_SERVER_USER,
            'password' => MYSQL_SERVER_PWD,
            'database' => MYSQL_SERVER_DB
        ]);
        Assert::assert($connected);
        $statement = $mysql->prepare('SELECT SLEEP(1)');
        Assert::assert($statement instanceof Co\Mysql\Statement);
        $timeout = ms_random(0.1, 0.5);
        $s = microtime(true);
        $use_query = !!mt_rand(0, 1);
        if ($use_query) {
            $ret = $mysql->query('SELECT SLEEP(1)', $timeout);
        } else {
            $ret = $statement->execute(null, $timeout);
        }
        time_approximate($timeout, microtime(true) - $s);
        Assert::assert(!$ret);
        Assert::same($use_query ? $mysql->errno : $statement->errno, SWOOLE_MYSQLND_CR_SERVER_GONE_ERROR);
    });
}
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
