--TEST--
swoole_runtime/stream_select: Bug the result of stream_select() is not equal to $read + $write + $error
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
if (!getenv('TEST_PHP_EXECUTABLE')) {
    exit('skip TEST_PHP_EXECUTABLE not defined');
}
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
Co\run(function () {
    $php = realpath(getenv('TEST_PHP_EXECUTABLE'));
    $pipes = [];
    $proc = proc_open(
        "$php"
        , [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']]
        , $pipes, __DIR__, [], []
    );
    var_dump($proc);
    if (!$proc) {
        exit(1);
    }
    $r = $pipes;
    $w = [];
    $e = [];
    $ret = stream_select($r, $w, $e, 1);
    var_dump($ret, (count($r) + count($w) + count($e)));

    foreach ($pipes as $pipe) {
        fclose($pipe);
    }
    proc_terminate($proc);
    if (defined('SIGKILL')) {
        proc_terminate($proc, SIGKILL);
    } else {
        proc_terminate($proc);
    }
    proc_close($proc);
});
?>
--EXPECTF--
resource(%d) of type (process/coroutine)
int(0)
int(0)
