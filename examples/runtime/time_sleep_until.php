<?php
Swoole\Runtime::enableCoroutine();
go(function () {
    var_dump(time_sleep_until(time() - 1));
    var_dump(time_sleep_until(microtime(true) + 0.2));
});
