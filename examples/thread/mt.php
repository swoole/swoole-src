<?php
//echo "begin\n";

$args = Swoole\Thread::getArguments();
echo Swoole\Thread::getId() . "\t" . 'gmap[uuid]' . "\t" . $args[2]['uuid'] . "\n";

//if ($args[0] == 'thread-2') {
//    $t3 = Swoole\Thread::exec('mt.php', 'thread-3', PHP_OS);
//    $t3->join();
//}

sleep(5);
//echo "end\n";
