--TEST--
swoole_mysql_coro: select big data from db
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $db = new Swoole\Coroutine\Mysql;
    $server = [
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB
    ];
    Assert::assert($db->connect($server));

    $table_name = get_safe_random(16);
    $createTable = "CREATE TABLE {$table_name} (\nid bigint PRIMARY KEY AUTO_INCREMENT,\n`content` text NOT NULL\n);";
    if (Assert::assert($db->query($createTable))) {
        $statement = $db->prepare("INSERT INTO {$table_name} VALUES (?, ?)");
        $random = [];
        for ($n = 0; $n < MAX_REQUESTS; $n++) {
            $random[$n] = str_repeat(get_safe_random(256), 128); // 32K
            $ret = $statement->execute([$n + 1, $random[$n]]);
            Assert::assert($ret);
        }
        $statement = $db->prepare("SELECT * FROM {$table_name}");
        $ret = $statement->execute();
        for ($n = 0; $n < MAX_REQUESTS; $n++) {
            Assert::same($ret[$n]['content'], $random[$n]);
        }
        Assert::assert($db->query("DROP TABLE {$table_name}"));
    }
});
?>
--EXPECT--
