--TEST--
swoole_mysql_coro: mysql prepare (insert)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $client = new Swoole\Coroutine\MySQL;
    $server = [
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB,
    ];

    if (Assert::true($client->connect($server))) {
        /* @var $statement Swoole\Coroutine\MySQL\Statement */
        $statement = $client->prepare('INSERT INTO ckl (`domain`,`path`,`name`) VALUES (?,?,?)');
        if (Assert::isInstanceOf($statement, Swoole\Coroutine\MySQL\Statement::class)) {
            if (Assert::true($statement->execute(['www.baidu.com', '/search', 'baidu']))) {
                Assert::same($statement->affected_rows, 1);
                Assert::greaterThan($statement->insert_id, 0);
                Assert::same($client->affected_rows, $statement->affected_rows);
                Assert::same($client->insert_id, $statement->insert_id);
                if (Assert::false($statement->execute())) {
                    Assert::same($statement->errno, SWOOLE_MYSQLND_CR_INVALID_PARAMETER_NO);
                    Assert::same($client->error, $statement->error);
                    Assert::same($client->errno, $statement->errno);
                }
                echo "SUCCESS\n";
            }
        }
    }
});
?>
--EXPECT--
SUCCESS
