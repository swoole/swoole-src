--TEST--
Test for socket_create_pair()
--SKIPIF--
<?php
if (!extension_loaded('sockets')) {
    die('SKIP The sockets extension is not loaded.');
}?>
--FILE--
<?php
use Swoole\Runtime;
use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {

$sockets = array();
if (strtolower(substr(PHP_OS, 0, 3)) == 'win') {
    $domain = AF_INET;
} else {
    $domain = AF_UNIX;
}
socket_create_pair($domain, SOCK_STREAM, 0, $sockets);
var_dump($sockets);
});
?>
--EXPECT--
array(2) {
  [0]=>
  object(Swoole\Coroutine\Socket)#1 (0) {
  }
  [1]=>
  object(Swoole\Coroutine\Socket)#2 (0) {
  }
}
