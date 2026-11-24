<?php
// Start a native thread. Requires a ZTS build with --enable-swoole-thread.
// Run: php examples/thread/hello.php
use Swoole\Thread;

$args = Thread::getArguments();
if (empty($args)) {
    $thread = new Thread(__FILE__, 'child');
    $thread->join();
    echo 'child thread finished' . PHP_EOL;
} else {
    echo 'hello from the ', $args[0], ' thread' . PHP_EOL;
}
