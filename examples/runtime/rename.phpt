<?php
Swoole\Runtime::enableCoroutine();
go(function () {
    var_dump(rename('data.txt', 'data2.txt'));
});
