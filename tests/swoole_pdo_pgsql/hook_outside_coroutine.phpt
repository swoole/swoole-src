--TEST--
swoole_pdo_pgsql: use hooked pgsql outside a coroutine
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_pgsql.inc';

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_PDO_PGSQL);
$pdo = pdo_pgsql_test_inc::create();
$statement = $pdo->prepare('SELECT 1 AS one');
$statement->execute();
var_dump($statement->fetchAll(PDO::FETCH_ASSOC)[0]['one']);
?>
--EXPECT--
int(1)
