<?php
Swoole\Runtime::enableCoroutine();
go(function () {
    var_dump(gethostbyname("www.baidu.com"));
});

