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
swoole_event_wait();
exit($exit_status);
