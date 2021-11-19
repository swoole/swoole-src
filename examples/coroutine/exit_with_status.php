<?php
$exit_status = 0;
go(function () {
    try {
        exit(123);
    } catch (\Swoole\ExitException $e) {
        global $exit_status;
        $exit_status = $e->getStatus();
    }
});
Swoole\Event::wait();
exit($exit_status);
