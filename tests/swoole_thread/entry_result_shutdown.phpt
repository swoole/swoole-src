--TEST--
swoole_thread: getResult is unavailable until shutdown completes, including detached threads
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
skip_if_php_version_lower_than('8.4');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$file = tempnam(sys_get_temp_dir(), 'swoole_thread_shutdown_');
file_put_contents($file, <<<'PHP'
<?php
[$ready, $release] = Swoole\Thread::getArguments();
register_shutdown_function(static function () use ($ready, $release): void {
    $ready->push(true, Swoole\Thread\Queue::NOTIFY_ONE);
    if (!$release->pop(5)) {
        throw new RuntimeException('Timed out waiting for the parent');
    }
});
return 'finished';
PHP);
try {
    foreach ([false, true] as $detach) {
        $ready = new Swoole\Thread\Queue();
        $release = new Swoole\Thread\Queue();
        $thread = new Swoole\Thread($file, $ready, $release);
        if ($detach) {
            Assert::true($thread->detach());
        }
        Assert::true($ready->pop(5));
        Assert::true($thread->isAlive());
        Assert::same(Swoole\Thread::activeCount(), 2);
        try {
            $thread->getResult();
            Assert::true(false);
        } catch (Error $error) {
            Assert::contains($error->getMessage(), 'before the thread has exited');
        } finally {
            $release->push(true, Swoole\Thread\Queue::NOTIFY_ONE);
        }
        if ($detach) {
            $deadline = microtime(true) + 5;
            while ($thread->isAlive() && microtime(true) < $deadline) {
                usleep(1000);
            }
        } else {
            Assert::true($thread->join());
        }
        Assert::false($thread->isAlive());
        Assert::same($thread->getExitStatus(), 0);
        Assert::same($thread->getResult(), 'finished');
        Assert::same($thread->getResult(), 'finished');
    }
    // Dropping a detached object must not free its result storage before return.
    file_put_contents($file, <<<'PHP'
<?php
[$ready, $release] = Swoole\Thread::getArguments();
$ready->push(true, Swoole\Thread\Queue::NOTIFY_ONE);
if (!$release->pop(5)) {
    throw new RuntimeException('Timed out waiting for the parent');
}
return str_repeat('detached-result', 1024);
PHP);
    $ready = new Swoole\Thread\Queue();
    $release = new Swoole\Thread\Queue();
    $thread = new Swoole\Thread($file, $ready, $release);
    Assert::true($thread->detach());
    Assert::true($ready->pop(5));
    unset($thread);
    $release->push(true, Swoole\Thread\Queue::NOTIFY_ONE);
    $deadline = microtime(true) + 5;
    while (Swoole\Thread::activeCount() > 1 && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::same(Swoole\Thread::activeCount(), 1);
} finally {
    unlink($file);
}
echo "DONE\n";
?>
--EXPECT--
DONE
