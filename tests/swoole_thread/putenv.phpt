--TEST--
swoole_thread: putenv
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$c = 8;
$threads = [];

for ($i = 0; $i < $c; $i++) {
    $threads[] = new Swoole\Thread(TESTS_API_PATH . '/swoole_thread/putenv.php', $i);
}

for ($i = 0; $i < $c; $i++) {
    $threads[$i]->join();
}

for ($i = 0; $i < $c; $i++) {
    $env = getenv('TEST_THREAD_' . $i);
    Assert::notEmpty($env);
}
?>
--EXPECT--
