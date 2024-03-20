<?php
echo "begin\n";
$GLOBALS['uuid'] = uniqid();
var_dump(Swoole\Thread::getId());
$args = Swoole\Thread::getArguments();
var_dump($args);
var_dump($GLOBALS['uuid']);

if ($args[0] == 'thread-2') {
    $t3 = Swoole\Thread::exec('mt.php', 'thread-3', PHP_OS);
    $t3->join();
}

sleep(5);
echo "end\n";
