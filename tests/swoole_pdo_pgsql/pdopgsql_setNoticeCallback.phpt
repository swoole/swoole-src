--TEST--
swoole_pdo_pgsql: subclass basic
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_php_version_lower_than('8.4');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;
run(function() {
    $host = PGSQL_HOST;
    $port = PGSQL_PORT;
    $user = PGSQL_USER;
    $password = PGSQL_PASSWORD;
    $dbname = PGSQL_DBNAME;

    $pdo = new Pdo\Pgsql("pgsql:host={$host};port={$port};dbname={$dbname}", $user, $password);

    $pdo->exec("DROP TABLE IF EXISTS parent CASCADE");
    $pdo->exec("DROP TABLE IF EXISTS child CASCADE");
    $pdo->exec('CREATE TABLE parent(id int primary key)');
    $pdo->exec('CREATE TABLE child(id int references parent)');

    $pdo->setNoticeCallback(function ($message) {
        sleep(1);
        echo $message;
    });

    $pdo->exec('TRUNCATE parent CASCADE');
    echo "DONE" . PHP_EOL;
});
?>
--EXPECT--
DONE
NOTICE:  truncate cascades to table "child"
