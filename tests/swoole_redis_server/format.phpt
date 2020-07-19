--TEST--
swoole_redis_server: format
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Redis\Server;
echo Server::format(Server::ERROR);
echo Server::format(Server::ERROR, "BAD REQUEST");
echo Server::format(Server::NIL);
echo Server::format(Server::STATUS);
echo Server::format(Server::STATUS, "SUCCESS");
echo Server::format(Server::INT, 1000);
echo Server::format(Server::STRING, "hello swoole");
echo Server::format(Server::SET, ["php", "is", "best"]);
echo Server::format(Server::MAP, ["php" => 99, "java" => 88, "c++" => '666']);
?>
--EXPECT--
-ERR
-BAD REQUEST
$-1
+OK
+SUCCESS
:1000
$12
hello swoole
*3
$3
php
$2
is
$4
best
*6
$3
php
$2
99
$4
java
$2
88
$3
c++
$3
666
