<?php
ini_set('memory_limit', '2G');
$args = Swoole\Thread::getArguments();

$dict = $args[1];
const COUNT = 10000000;

$n = COUNT;
$s = microtime(true);
while ($n--) {
    $dict['key-' . $n] = $n * 3;
}
echo $args[0] . "\t" . 'array set: ' . round(microtime(true) - $s, 6) . ' seconds' . PHP_EOL;

$c = 0;
$n = COUNT;
$s = microtime(true);
while ($n--) {
    $c += $dict['key-' . $n];
}
echo $args[0] . "\t" . 'array get: ' . round(microtime(true) - $s, 6) . ' seconds' . PHP_EOL;
