--TEST--
swoole_pdo_pgsql: pgsql copyFromArray
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
use Swoole\Coroutine\WaitGroup;

run(function() {
    $host = PGSQL_HOST;
    $port = PGSQL_PORT;
    $user = PGSQL_USER;
    $password = PGSQL_PASSWORD;
    $dbname = PGSQL_DBNAME;

    $data = [];
    for($i = 1; $i <= 1000000; $i++) {
        $data[] = $i . "\tJohn\tDoe";
    }

    $sql = "CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        first_name VARCHAR(50) NOT NULL,
        last_name VARCHAR(50)
    )";

    $pdo = new Pdo\Pgsql("pgsql:host={$host};port={$port};dbname={$dbname}", $user, $password);
    $pdo->exec("DROP TABLE IF EXISTS users CASCADE");
    $pdo->exec($sql);

    $waitGroup = new WaitGroup();
    go(function() use($waitGroup, $pdo, $data) {
        $waitGroup->add();
        $result = $pdo->copyFromArray('users', $data);
        Assert::true($result);
        $waitGroup->done();
    });

    sleep(2);
    echo "Hello World" . PHP_EOL;
    $waitGroup->wait();
});
?>
--EXPECT--
Hello World
