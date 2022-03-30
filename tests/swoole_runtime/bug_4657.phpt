--TEST--
swoole_runtime: bug 4657
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if(PHP_VERSION_ID < 80000) {
    skip_unsupported('php version is too low');
}
?>
--FILE--
<?php
use Socket as BaseSocket;
use Swoole\Coroutine\Socket;
use function Swoole\Coroutine\run;

$socket = socket_create(AF_INET, SOCK_STREAM, 0);
var_dump($socket);

run(function () {
    $socket = socket_create(AF_INET, SOCK_STREAM, 0);
    var_dump($socket);
    var_dump($socket instanceof BaseSocket);
});

$socket = socket_create(AF_INET, SOCK_STREAM, 0);
var_dump($socket);
?>
--EXPECTF--
object(Socket)#%d (%d) {
}
object(Swoole\Coroutine\Socket)#%d (%d) {
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
object(Socket)#%d (%d) {
}
