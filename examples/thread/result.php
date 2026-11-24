<?php

use Swoole\Thread;

// Requires PHP ZTS and a Swoole build with internal thread entries and getResult().
// Usage: php examples/thread/result.php [file-or-url]
// Example: php examples/thread/result.php https://example.com/
if (PHP_VERSION_ID < 80400 || !class_exists(Thread::class) || !method_exists(Thread::class, 'getResult')) {
    fwrite(STDERR, "This example requires PHP 8.4+ ZTS and Swoole thread entry/result support.\n");
    exit(1);
}

$source = $argv[1] ?? __FILE__;

// The constructor starts the worker immediately. No start() call is needed.
$thread = new Thread('file_get_contents', $source);
echo "Worker started; the main thread can continue doing other work.\n";

// Wait for the worker, including its shutdown callbacks and request cleanup.
if (!$thread->join()) {
    fwrite(STDERR, "Unable to join the worker thread.\n");
    exit(1);
}
if ($thread->getExitStatus() !== 0) {
    fwrite(STDERR, 'Worker failed with exit status ' . $thread->getExitStatus() . "\n");
    exit(1);
}

// This is file_get_contents()'s return value, not captured stdout.
// getResult() throws Error if called while the worker is still running.
$result = $thread->getResult();
if ($result === false) {
    fwrite(STDERR, 'Unable to read ' . $source . "\n");
    exit(1);
}

printf("Read %d bytes from %s\n", strlen($result), $source);
var_dump($result);
