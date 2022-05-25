--TEST--
swoole_mysql_coro: Statement->execute() failed, then execute successfully, errorInfo is incorrect
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use function Swoole\Coroutine\run;

run(function () {
    $mysql = new Co\MySQL;
    $mysql->connect([
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB
    ]);
    Assert::true(false !== $mysql->query('DROP TABLE IF EXISTS test_statement_error'));
    Assert::true(false !== $mysql->query('CREATE TABLE test_statement_error (x int)'));
    $stmt = $mysql->prepare('insert into test_statement_error values(?)');
    Assert::true(false !== $stmt);

    // fail
    var_dump($stmt->execute([\PHP_INT_MIN]), $stmt->error, $stmt->errno, $mysql->error, $mysql->errno);

    // success
    var_dump($stmt->execute([1]), $stmt->error, $stmt->errno, $mysql->error, $mysql->errno);
});
?>
--EXPECT--
bool(false)
string(65) "SQLSTATE[22003] [1264] Out of range value for column 'x' at row 1"
int(1264)
string(65) "SQLSTATE[22003] [1264] Out of range value for column 'x' at row 1"
int(1264)
bool(true)
string(0) ""
int(0)
string(0) ""
int(0)
