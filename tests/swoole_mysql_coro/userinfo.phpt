--TEST--
swoole_mysql_coro: mysql prepare dtor
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_pdo_not_support_mysql8();
?>
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
        'database' => MYSQL_SERVER_DB
    ]);
    $result = $mysql->query('SELECT * FROM `userinfo`');
    $pdo = new PDO(
        "mysql:host=" . MYSQL_SERVER_HOST . ";port=" . MYSQL_SERVER_PORT . ";dbname=" . MYSQL_SERVER_DB . ";charset=utf8",
        MYSQL_SERVER_USER, MYSQL_SERVER_PWD
    );
    $pdo_result = $pdo->query('SELECT * FROM `userinfo`')->fetchAll(PDO::FETCH_ASSOC);
    Assert::same($result, $pdo_result);

    $result = $mysql->prepare('SELECT * FROM `userinfo`')->execute();
    $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
    $pdo_stmt = $pdo->prepare('SELECT * FROM `userinfo`');
    $pdo_stmt->execute();
    $pdo_result =$pdo_stmt->fetchAll(PDO::FETCH_ASSOC);

    Assert::same($result, $pdo_result);
});
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
