--TEST--
swoole_thread: failed thread creation releases duplicated argument resources
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
skip_if_not_linux();
skip_if_function_not_exist('posix_setrlimit');
skip('RLIMIT_NPROC is not enforced for root', posix_geteuid() === 0);
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;

$arguments = Thread::getArguments();
if ($arguments !== null) {
    Assert::true(is_resource($arguments[0]));
    return;
}

$socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
Assert::notSame($socket, false);
$limits = posix_getrlimit();
$soft = $limits['soft maxproc'] === 'unlimited' ? POSIX_RLIMIT_INFINITY : $limits['soft maxproc'];
$hard = $limits['hard maxproc'] === 'unlimited' ? POSIX_RLIMIT_INFINITY : $limits['hard maxproc'];
$before = count(scandir('/proc/self/fd'));
$failed = 0;
try {
    // Change only this test process's limit; force pthread_create to fail without exhausting resources.
    Assert::true(posix_setrlimit(POSIX_RLIMIT_NPROC, 0, $hard));
    for ($i = 0; $i < 4; $i++) {
        try {
            $thread = new Thread(__FILE__, $socket);
            $thread->join();
        } catch (Swoole\Exception $exception) {
            $failed++;
        }
    }
} finally {
    Assert::true(posix_setrlimit(POSIX_RLIMIT_NPROC, $soft, $hard));
}
Assert::same($failed, 4);
Assert::same(count(scandir('/proc/self/fd')), $before);

// A normal start must still transfer ownership and expose the argument in the new thread.
$thread = new Thread(__FILE__, $socket);
Assert::true($thread->join());
Assert::same($thread->getExitStatus(), 0);
fclose($socket);
echo "DONE\n";
?>
--EXPECT--
DONE
