<?php
require __DIR__ . '/../../../include/bootstrap.php';
$args = Swoole\Thread::getArguments();
$val = $args[0] . '_' . time() . '_' . uniqid();
putenv('TEST_THREAD_' . $args[0] . '=' . $val);
Assert::eq(getenv('TEST_THREAD_' . $args[0]), $val);
