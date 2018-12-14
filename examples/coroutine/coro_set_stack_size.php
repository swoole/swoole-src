<?php
use Swoole\Coroutine as co;

co::set(['stack_size' => 1024*1024*4]);

co::create(function () {
    var_dump(co::stats());
    echo "no coro exit\n";
});
echo "exec file end\n";
