--TEST--
ext/sockets - socket_set_block - basic test
--CREDITS--
Florian Anderiasch
fa@php.net
--SKIPIF--
<?php
    if (!extension_loaded('sockets')) {
        die('skip sockets extension not available.');
    }
?>
--FILE--
<?php
use Swoole\Runtime;
use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {

    $s_c_l = socket_create_listen(0);
    socket_set_nonblock($s_c_l);
    var_dump($s_c_l);
    //socket_accept($s_c_l);
    socket_close($s_c_l);
});
?>
--EXPECT--
object(Swoole\Coroutine\Socket)#1 (0) {
}
