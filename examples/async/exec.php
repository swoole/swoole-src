<?php
$pid = Swoole\Async::exec("ps aux", function ($result, $status) {
    var_dump(strlen($result), $status);
});

var_dump($pid);
