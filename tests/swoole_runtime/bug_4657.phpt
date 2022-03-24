--TEST--
swoole_runtime: bug 4657
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_ALL);

Swoole\Coroutine\run(function () {
    $socket = socket_create(AF_INET, SOCK_STREAM, 0);
    var_dump($socket);
    var_dump($socket instanceof \Socket);

    Swoole\Runtime::enableCoroutine(false);
    $socket = socket_create(AF_INET, SOCK_STREAM, 0);
    var_dump($socket);
});
?>
--EXPECTF--
object(Swoole\Coroutine\Socket)#3 (6) {
  ["fd"]=>
  int(%d)
  ["domain"]=>
  int(%d)
  ["type"]=>
  int(%d)
  ["protocol"]=>
  int(%d)
  ["errCode"]=>
  int(0)
  ["errMsg"]=>
  string(0) ""
}
bool(true)
object(Socket)#4 (0) {
}
