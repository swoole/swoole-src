<?php
Co\run(function () {
    $stdin = fopen("php://stdin", 'r');
    $ip = Swoole\Coroutine\System::waitEvent($stdin, SWOOLE_EVENT_READ, 5);
    if ($ip) {
      echo fgets($stdin);
    } else {
      echo "timeout\n";
    }
});