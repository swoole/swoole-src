--TEST--
swoole_coroutine/cancel: throw exception in coroutine with internal callable
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use function Swoole\Coroutine\run;
use Swoole\Coroutine;
use Swoole\Runtime;

Runtime::enableCoroutine(SWOOLE_HOOK_SLEEP);

run(function () {
    $cid = Coroutine::create('usleep', 1000000);
    Coroutine::cancel($cid, true);
});
?>
--EXPECTF--
Fatal error: Uncaught Swoole\Coroutine\CanceledException in :0
Stack trace:
%A
  thrown in Unknown on line 0
