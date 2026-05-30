--TEST--
swoole_pdo_pgsql: pgsql getNotify
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

    $waitGroup = new WaitGroup();
    go(function() use($host, $port, $user, $password, $dbname, $waitGroup) {
        $waitGroup->add();
        $pdo = new Pdo\Pgsql("pgsql:host={$host};port={$port};dbname={$dbname}", $user, $password);
        $pdo->query('LISTEN test');
        $notification = $pdo->getNotify(PDO::FETCH_ASSOC, 10000);
        var_dump($notification);
        $notification = $pdo->getNotify(PDO::FETCH_ASSOC, 1000);
        Assert::false($notification);
        $waitGroup->done();
    });

    go(function() use($host, $port, $user, $password, $dbname, $waitGroup) {
        echo "start NOTIFY test" . PHP_EOL;
        $waitGroup->add();
        sleep(1);
        $pdo = new Pdo\Pgsql("pgsql:host={$host};port={$port};dbname={$dbname}", $user, $password);
        $pdo->exec("NOTIFY test, 'payload string'");
        $waitGroup->done();
    });

    $waitGroup->wait();
});
?>
--EXPECTF--
start NOTIFY test
array(3) {
  ["message"]=>
  string(4) "test"
  ["pid"]=>
  int(%d)
  ["payload"]=>
  string(14) "payload string"
}
