<?php
// co::set(['trace_flags' => 1]);

co::create(function () {
    echo "no coro exit\n";
});
echo "exec file end\n";
