--TEST--
swoole_thread: fatal error
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;

$pm = ProcessManager::exec(function () {
    $args = Thread::getArguments();
    if (empty($args)) {
        echo "start child thread\n";
        $threads[] = new Thread(__FILE__, 'error');
        $threads[0]->join();
        echo "stop thread exited\n";
    } else {
        Co\run(function () {
            (function () {
                swoole_implicit_fn('fatal_error');
            })();
        });
    }
    echo "DONE\n";
});
$output = $pm->getChildOutput();
Assert::contains($output, "start child thread\n");
Assert::contains($output, "stop child thread\n");
Assert::contains($output, "Fatal error: Uncaught Swoole\Error: test");
?>
--EXPECT--
