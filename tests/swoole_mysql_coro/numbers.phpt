--TEST--
swoole_mysql_coro: floating point value precision and unsigned big int overflow
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use function Swoole\Coroutine\run;

ini_set('serialize_precision', -1);
ini_set('precision', -1);

run(function () {
    $db = new Swoole\Coroutine\Mysql;
    $server = [
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB,
        'strict_type' => false
    ];
    $db->connect($server);
    $r_string1 = $db->query('SELECT * FROM numbers');
    $db->close();
    $server['strict_type'] = true;
    $db->connect($server);
    $r_strong1 = $db->query('SELECT * FROM numbers');
    $stmt = $db->prepare('SELECT * FROM numbers');
    $r_strong2 = $stmt->execute();

    try {
        $pdo = new PDO(
            "mysql:host=" . MYSQL_SERVER_HOST . ";port=" . MYSQL_SERVER_PORT . ";dbname=" . MYSQL_SERVER_DB . ";charset=utf8",
            MYSQL_SERVER_USER, MYSQL_SERVER_PWD
        );
        $r_string2 = $pdo->query('SELECT * FROM numbers')->fetchAll(PDO::FETCH_ASSOC);
        $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
        $stmt = $pdo->prepare('SELECT * FROM numbers');
        $stmt->execute();
        $r_strong3 = $stmt->fetchAll(PDO::FETCH_ASSOC);
        Assert::same($r_string1, $r_string2);
        Assert::same($r_strong2, $r_strong3);
    } catch (\PDOException $e) {
        Assert::same($e->getCode(), 2054); // not support auth plugin
    }

    if (!is_musl_libc()) {
        Assert::same($r_strong1, $r_strong2);
    }
    var_dump($r_strong2);
});
?>
--EXPECT--
array(3) {
  [0]=>
  array(13) {
    ["id"]=>
    int(1)
    ["tinyint"]=>
    int(127)
    ["utinyint"]=>
    int(255)
    ["smallint"]=>
    int(32767)
    ["usmallint"]=>
    int(65535)
    ["mediumint"]=>
    int(8388607)
    ["umediumint"]=>
    int(16777215)
    ["int"]=>
    int(2147483647)
    ["uint"]=>
    int(4294967294)
    ["bigint"]=>
    int(9223372036854775807)
    ["ubigint"]=>
    string(20) "18446744073709551615"
    ["float"]=>
    float(1.23457)
    ["double"]=>
    float(1.2345678901234567)
  }
  [1]=>
  array(13) {
    ["id"]=>
    int(2)
    ["tinyint"]=>
    int(-128)
    ["utinyint"]=>
    int(123)
    ["smallint"]=>
    int(-32768)
    ["usmallint"]=>
    int(12345)
    ["mediumint"]=>
    int(-8388608)
    ["umediumint"]=>
    int(123456)
    ["int"]=>
    int(-2147483648)
    ["uint"]=>
    int(123456)
    ["bigint"]=>
    int(-9223372036854775808)
    ["ubigint"]=>
    int(123456)
    ["float"]=>
    float(-1.23457)
    ["double"]=>
    float(-1.2345678901234567)
  }
  [2]=>
  array(13) {
    ["id"]=>
    int(3)
    ["tinyint"]=>
    int(0)
    ["utinyint"]=>
    int(0)
    ["smallint"]=>
    int(0)
    ["usmallint"]=>
    int(0)
    ["mediumint"]=>
    int(0)
    ["umediumint"]=>
    int(0)
    ["int"]=>
    int(0)
    ["uint"]=>
    int(0)
    ["bigint"]=>
    int(0)
    ["ubigint"]=>
    int(0)
    ["float"]=>
    float(1.23)
    ["double"]=>
    float(1.23)
  }
}
