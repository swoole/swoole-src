--TEST--
swoole_mysql_coro: mysql defer and fetch
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $mysql = new Swoole\Coroutine\MySQL;
    $mysql->connect([
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB,
        'fetch_mode' => true
    ]);
    $mysql->setDefer(true);
    for ($n = 0; $n < MAX_REQUESTS; $n++) {
        if ($n === 0 || mt_rand(0, 1)) {
            $ret = $mysql->prepare('SELECT ?+?');
            Assert::true($ret);
            $statement = $mysql->recv();
            Assert::isInstanceOf($statement, Swoole\Coroutine\MySQL\Statement::class);
        }
        $a = mt_rand(0, 65535);
        $b = mt_rand(0, 65535);
        /** @var $statement Swoole\Coroutine\MySQL\Statement */
        Assert::true($statement->execute([$a, $b]));
        Assert::true($statement->recv());
        $result = $statement->fetchAll();
        if (Assert::isArray($result)) {
            Assert::same(reset($result[0]), (float)($a + $b));
        }
    }
});
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
