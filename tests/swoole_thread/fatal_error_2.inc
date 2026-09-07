<?php

use Swoole\Thread;

$args = Thread::getArguments();
if (empty($args)) {
    echo "start child thread\n";
    fflush(STDOUT);
    $threads[] = new Thread(__FILE__, 'error');
    $threads[0]->join();
    echo "stop child thread\n";
    fflush(STDOUT);
} else {
    (function () {
        swoole_implicit_fn('fatal_error');
    })();
}
echo "DONE\n";
