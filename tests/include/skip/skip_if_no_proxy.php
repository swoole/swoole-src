<?php
require_once __DIR__ . '../skipif.inc';
require_once __DIR__ . '../config.php';

if (IS_IN_DOCKER || check_tcp_port(HTTP_PROXY_HOST, HTTP_PROXY_PORT) !== 1) {
    exit('skip by no http proxy available');
}