<?php
Co\run(function () {
    $result = Swoole\Coroutine\System::waitSignal(SIGINT);
    if ($result) {
        echo "SIGINT trigger\n";
    }
});