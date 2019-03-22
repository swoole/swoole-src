<?php
use Swoole\Coroutine as co;
// co::set(['trace_flags' => 1]);

var_dump(SWOOLE_CORO_SCHEDULE);
co::create(function () {
    echo "no coro exit\n";
});
echo "exec file end\n";
