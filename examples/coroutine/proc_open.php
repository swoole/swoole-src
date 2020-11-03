<?php
Swoole\Runtime::setHookFlags(SWOOLE_HOOK_ALL);
Swoole\Coroutine\run(function () {

    $descriptorspec = array(
        0 => array("pipe", "r"),
        1 => array("pipe", "w"),
        2 => array("pipe", "w"),
    );

    $process = proc_open('unknown', $descriptorspec, $pipes);

    var_dump($pipes);

    var_dump(fread($pipes[2], 8192));

    $return_value = proc_close($process);

    echo "command returned $return_value\n";
});