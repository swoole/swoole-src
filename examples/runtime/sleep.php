<?php
Swoole\Runtime::enableCoroutine();
go(function () {
    sleep(1);
});
