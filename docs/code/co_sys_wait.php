<?php

(new Swoole\Process(function () {
    echo "child process start\n";
    sleep(1);
    echo "child process exit\n";
}))->start();

Co\run(function () {
    $info = Swoole\Coroutine\System::wait(5);
    var_dump($info);
});