--TEST--
swoole_mysql_coro: use fetch to get data
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
co::set([
    'socket_connect_timeout' => 10,
    'socket_timeout' => 10
]);
go(function () {
    $db = new Swoole\Coroutine\Mysql;
    $server = [
        'host' => MYSQL_SERVER_HOST,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB
    ];
    assert($db->connect($server));

    $table_name = get_safe_random(16);
    $createTable = "CREATE TABLE {$table_name} (\nid bigint PRIMARY KEY AUTO_INCREMENT,\n`content` text NOT NULL\n);";
    if (assert($db->query($createTable))) {
        $statement = $db->prepare("INSERT INTO {$table_name} VALUES (?, ?)");
        $random = [];
        for ($n = 0; $n < MAX_REQUESTS; $n++) {
            $random[$n] = str_repeat(get_safe_random(256), 128); // 32K
            $ret = $statement->execute([$n + 1, $random[$n]]);
            assert($ret);
        }
        $statement = $db->prepare("SELECT * FROM {$table_name}");
        $ret = $statement->execute();
        assert($ret[0]['content'] === $random[0]);
        assert($db->query("DROP TABLE {$table_name}"));
    }
});
?>
--EXPECT--
