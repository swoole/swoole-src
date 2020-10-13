--TEST--
swoole_mysql_coro: multi field
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

define('FIELD_NUM', 8192);

Co\Run(function () {
    $db = new Co\MySQL();
    $server = [
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB
    ];
    $ret = $db->connect($server);
    if (Assert::true($ret)) {
        $n = range(0, FIELD_NUM - 1);
        $fields = implode(", ", $n);
        $result = $db->query("select $fields");
        Assert::assert(count($result[0]) == FIELD_NUM);
        echo "DONE\n";
    }
});
?>
--EXPECT--
DONE
