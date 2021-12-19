--TEST--
swoole_server: invalid option
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

$serv = new Server('127.0.0.1', 0, SWOOLE_BASE);
$options = [
    'worker_num' => 1,
    'backlog' => 128,
    'invalid_option' => true,
];

try {
    $serv->set($options);
} catch (\Swoole\Exception $e) {
    echo $e->getMessage();
}

?>
--EXPECTREGEX--
Warning: unsupported option \[invalid_option\] in [\w\W]*php on line \d+
#0  (\[internal function\]: )?Swoole\\Server\\Helper::checkOptions\(\)
#1  (\[internal function\]: )?Swoole\\Server\\Port->set\(\)
#2  ([\w\W]*php\(\d+\): Swoole\\Server->set\(\)|Swoole\\Server->set\(\) called at \[[\w\W]*php:\d+\])
