--TEST--
swoole_client_async: a live client at script end is destructed without double free
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
error_reporting(E_ALL & ~E_DEPRECATED);

$cli = new Swoole\Async\Client(SWOOLE_SOCK_UDP);
$cli->on('receive', function () {});
$cli->on('close', function () { echo "close\n"; });
Assert::true($cli->connect('127.0.0.1', 9));
echo "end\n";
?>
--EXPECT--
end
close
