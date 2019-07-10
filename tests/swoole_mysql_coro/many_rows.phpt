--TEST--
swoole_mysql_coro: insert and select many rows
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
    $row_num = [100, 200, 1000, 3000][PRESSURE_LEVEL];
    if (Assert::assert($db->query($createTable))) {
        $sql = "INSERT INTO {$table_name} (`content`) VALUES " . rtrim(str_repeat('(?), ', $row_num), ', ');
        $statement = $db->prepare($sql);
        $random = [];
        for ($n = 0; $n < $row_num; $n++) {
            $random[$n] = get_safe_random(64);
        }
        $statement->execute($random);
        $statement = $db->prepare("SELECT * FROM {$table_name}");
        $result = $statement->execute();
        if (Assert::assert(count($result) === $row_num)) {
            for ($n = 0; $n < $row_num; $n++) {
                Assert::same($result[$n]['content'], $random[$n]);
            }
        }
        Assert::assert($db->query("DROP TABLE {$table_name}"));
        echo "DONE\n";
    }
});
?>
--EXPECT--
DONE
