--TEST--
swoole_mysql_coro: mysql null
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $mysql = new Swoole\Coroutine\MySQL();
    $connected = $mysql->connect([
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB,
        'strict_type' => true
    ]);
    assert($connected);
    assert($mysql->query('INSERT INTO `custom` (`content`) VALUES (NULL)'));
    assert($mysql->query('INSERT INTO `custom` (`content`) VALUES ("")'));
    assert($mysql->query('INSERT INTO `custom` (`content`) VALUES ("NULL")'));
    $result = $mysql->query('select `content` from custom');
    var_dump(array_merge_recursive(...$result)['content']);
    assert($mysql->query('TRUNCATE TABLE `custom`'));

    $stmt = $mysql->prepare('INSERT INTO `custom` (`content`) VALUES (?)');
    assert($stmt->execute([NULL]));
    assert($stmt->execute(['']));
    assert($stmt->execute(['NULL']));
    $result = $mysql->query('select `content` from custom');
    var_dump(array_merge_recursive(...$result)['content']);
    assert($mysql->query('TRUNCATE TABLE `custom`'));
});
?>
--EXPECT--
array(3) {
  [0]=>
  NULL
  [1]=>
  string(0) ""
  [2]=>
  string(4) "NULL"
}
array(3) {
  [0]=>
  NULL
  [1]=>
  string(0) ""
  [2]=>
  string(4) "NULL"
}
