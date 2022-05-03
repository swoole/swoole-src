<?php
Co\run(function () {
    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
    
    $descriptorspec = array(
       0 => array("pipe", "r"),
       1 => array("pipe", "w"),
       2 => array("file", "/tmp/error-output.txt", "a")
    );

    $process = proc_open('php '.__DIR__.'/read_stdin.php', $descriptorspec, $pipes);
    
    $n = 10;
    while($n--) {
        fwrite($pipes[0], "hello #$n \n");
        echo fread($pipes[1], 8192);
    }

    fclose($pipes[0]);
    proc_close($process);
});