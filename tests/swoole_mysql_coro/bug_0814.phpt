--TEST--
swoole_mysql_coro: mysql prepare (select)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine as co;

co::create(function () {
    $db = new co\MySQL();
    $server = [
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB,
    ];

    $ret1 = $db->connect($server);
    if (!$ret1) {
        echo "CONNECT[1] ERROR\n";
        return;
    }

    /**
     * 第一次执行prepare
     */
    $stmt = $db->prepare('SELECT * FROM userinfo WHERE id=?');
    if (!$stmt) {
        echo "PREPARE ERROR\n";
        return;
    }

    $ret3 = $stmt->execute([5]);
    if (!$ret3) {
        echo "EXECUTE ERROR#{$stmt->errno}: {$stmt->error}\n";
        return;
    }
    Assert::assert(count($ret3) > 0);

    $s = microtime(true);
    $ret = $db->query("select sleep(20)", 0.1);
    time_approximate(0.1, microtime(true) - $s);
    Assert::false($ret);
    Assert::same($db->errno, SWOOLE_MYSQLND_CR_SERVER_GONE_ERROR);
    $ret1 = $db->connect($server);
    if (!$ret1) {
        echo "CONNECT[2] ERROR\n";
        return;
    }

    /**
     * 第二次执行prepare
     */
    $stmt = $db->prepare('SELECT * FROM userinfo WHERE id=?');
    if (!$stmt) {
        echo "PREPARE ERROR\n";
        return;
    }

    $ret3 = $stmt->execute([5]);
    if (!$ret3) {
        echo "EXECUTE ERROR#{$stmt->errno}: {$stmt->error}\n";
        return;
    }
    Assert::assert(count($ret3) > 0);
});

?>
--EXPECT--
