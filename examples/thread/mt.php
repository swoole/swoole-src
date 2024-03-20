<?php
//echo "begin\n";

$args = Swoole\Thread::getArguments();
echo Swoole\Thread::getId() . "\t" . 'gmap[uuid]' . "\t" . $args[2]['uuid'] . "\n";
$args[2]['hello'] = uniqid('swoole');
var_dump(count($args[2]));

$args[3][] = uniqid('swoole');
$args[3][count($args[3])] = uniqid('php');

echo Swoole\Thread::getId() . "\t" . 'glist[0]' . "\t" . $args[3][0] . "\n";
var_dump(count($args[3]));

//if ($args[0] == 'thread-2') {
//    $t3 = Swoole\Thread::exec('mt.php', 'thread-3', PHP_OS);
//    $t3->join();
//}

//sleep(5);
//echo "end\n";
