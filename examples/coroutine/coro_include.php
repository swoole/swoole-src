<?php

if ('WIN' == substr(PHP_OS, 0, 3)) {
    exit('skip for Windows');
}
if (!extension_loaded('swoole')) {
    exit('swoole extension is required');
}
