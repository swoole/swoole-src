--TEST--
swoole_mysql_coro: mysql prepare field type
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine as Co;

Co::create(function () {
    $db = new Co\MySQL();
    $server = [
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB,
        'strict_type' => true,
    ];

    $ret1 = $db->connect($server);
    if (! $ret1) {
        echo "CONNECT ERROR\n";

        return;
    }

    $stmt = $db->prepare('SELECT ? as a, ? as b, ? as c, ? as d, ? + ? as e');
    if (! $stmt) {
        echo "PREPARE ERROR\n";

        return;
    }

    $ret3 = $stmt->execute([123, 3.14, true, false, 11, 22]);
    if (! $ret3) {
        echo "EXECUTE ERROR#{$stmt->errno}: {$stmt->error}\n";

        return;
    }
    if (Assert::isArray($ret3)) {
        Assert::same(reset($ret3), ['a' => 123, 'b' => 3.14, 'c' => 1, 'd' => 0, 'e' => 33]);
    }
});

?>
--EXPECT--
