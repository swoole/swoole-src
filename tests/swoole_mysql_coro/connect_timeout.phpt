--TEST--
swoole_mysql_coro: connect timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $mysql = new Swoole\Coroutine\MySQL;
    // tcp connect timeout
    $s = microtime(true);
    $connected = $mysql->connect([
        'host' => '192.0.0.1',
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB,
        'timeout' => ($timeout = mt_rand(100, 500) / 1000)
    ]);
    time_approximate($timeout, microtime(true) - $s);
    Assert::assert(!$connected);
    Assert::assert($mysql->connected === false);
    Assert::assert($mysql->connect_errno === SWOOLE_MYSQLND_CR_CONNECTION_ERROR);
    // handshake timeout
    $s = microtime(true);
    $connected = $mysql->connect([
        'host' => REDIS_SERVER_HOST,
        'port' => REDIS_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB,
        'timeout' => ($timeout = mt_rand(100, 500) / 1000)
    ]);
    time_approximate($timeout, microtime(true) - $s);
    Assert::false($connected);
    Assert::same($mysql->connected, false);
    Assert::same($mysql->connect_errno, SWOOLE_MYSQLND_CR_CONNECTION_ERROR);
});
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
