--TEST--
swoole_runtime/exec: shell functions allow another coroutine to run
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

Assert::setThrowException(true);

use function Swoole\Coroutine\run;

$pm = ProcessManager::exec(function () {
    $fn_list = ['exec', 'shell_exec', 'system', 'passthru'];
    Swoole\Runtime::setHookFlags(SWOOLE_HOOK_ALL);
    run(function () use ($fn_list)  {
        foreach ($fn_list as $fn) {
            $gate = tempnam(sys_get_temp_dir(), 'swoole-exec-');
            unlink($gate);
            $released = false;
            Co\go(function () use ($gate, &$released) {
                Co::sleep(0.001);
                touch($gate);
                $released = true;
            });
            // The child can finish only after the coroutine above runs during the shell call.
            $code = <<<'PHP'
$deadline = microtime(true) + 5;
do {
    clearstatcache(true, $argv[1]);
    if (is_file($argv[1])) {
        echo "ping statistics\nDONE\n";
        exit(0);
    }
    usleep(1000);
} while (microtime(true) < $deadline);
exit(1);
PHP;
            $cmd = escapeshellarg(PHP_BINARY) . ' -n -r ' . escapeshellarg($code) . ' ' . escapeshellarg($gate);
            try {
                $rs = $fn($cmd);
                Assert::true($released, $fn . ' blocked the release coroutine');
                var_dump($rs);
            } finally {
                @unlink($gate);
            }
        }
    });
});

Assert::eq(substr_count($pm->getChildOutput(), 'ping statistics'), 3);
Assert::eq($pm->getChildExitStatus(), 0);
?>
--EXPECTF--
