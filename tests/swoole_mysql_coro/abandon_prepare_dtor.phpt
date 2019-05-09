--TEST--
swoole_mysql_coro: mysql prepare dtor
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $mysql = new Co\MySQL;
    $mysql->connect([
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB
    ]);
    for ($n = MAX_REQUESTS; $n--;) {
        $statement = $mysql->prepare('SELECT ?');
        $statement = null;
        Co::sleep(0.001);
        $result = $mysql->query('show status like \'Prepared_stmt_count\'');
        assert($result[0]['Value'] === '0');
    }
});
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
