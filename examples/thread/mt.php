<?php
echo "begin\n";
var_dump(Swoole\Thread::getId());
$args = Swoole\Thread::getArguments();
var_dump($args);

if ($args[0] == 'thread-2') {
    $t3 = Swoole\Thread::run('mt.php', ['thread-3'], PHP_OS);
    $t3->join();
}

sleep(5);
echo "end\n";
