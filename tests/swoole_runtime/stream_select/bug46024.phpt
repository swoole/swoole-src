--TEST--
swoole_runtime/stream_select: Bug #46024 stream_select() doesn't return the correct number
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
go(function () {
    $php = realpath(getenv('TEST_PHP_EXECUTABLE'));
    $pipes = [];
    $proc = proc_open(
        "$php -n -i"
        , [0 => ['pipe', 'r'], 1 => ['pipe', 'w']]
        , $pipes, __DIR__, [], []
    );
    var_dump($proc);
    if (!$proc) {
        exit(1);
    }
    $r = [$pipes[1]];
    $w = [$pipes[0]];
    $e = null;
    $ret = stream_select($r, $w, $e, 1);
    var_dump($ret === (count($r) + count($w)));
    fread($pipes[1], 1);

    $r = [$pipes[1]];
    $w = [$pipes[0]];
    $e = null;
    $ret = stream_select($r, $w, $e, 1);
    var_dump($ret === (count($r) + count($w)));

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
Swoole\Event::wait();
?>
--EXPECTF--
resource(%d) of type (process/coroutine)
bool(true)
bool(true)
