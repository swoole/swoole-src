<?php
Swoole\Runtime::enableCoroutine();
go(function () {
    var_dump(unlink('data.txt'));
});
