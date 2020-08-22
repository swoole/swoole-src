--TEST--
swoole_runtime/stream_select: swoole_runtime/stream_set_blocking
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
file_put_contents(__DIR__ . '/child.php', '<?php echo \'test\', PHP_EOL;fread(STDIN, 1);');
Swoole\Runtime::enableCoroutine();
Co\run(function () {

    $descriptorspec = [
        ['pipe', 'r'],
        ['pipe', 'w'], // stdout
    ];
    $p = proc_open('php ' . __DIR__ . '/child.php', $descriptorspec, $pipes);
    Assert::resource($p);
    foreach ($pipes as $pipe) {
        Assert::true(stream_set_blocking($pipe, false));
    }
    while (true) {
        $r = [$pipes[1]];
        $w = [];
        $e = [];
        if (stream_select($r, $w, $e, 0) && $r) {
            foreach ($r as $pipe) {
                for ($i = 0; $i < 2; ++$i) {
                    $time = microtime(true);
                    // The second execution will not be blocked
                    $data = @fread($pipe, 4096);
                    Assert::lessThan(microtime(true) - $time, 1);
                    var_dump($i . ':' . $data);
                }
            }
            break;
        }
        sleep(1);
    }
    proc_close($p);
});
unlink(__DIR__ . '/child.php');
?>
--EXPECTF--
string(7) "0:test
"
string(2) "1:"
