<?php
require_once __DIR__ . '../skipif.inc';
require_once __DIR__ . '../config.php';

if (!HTTP_PROXY_AVAILABLE) {
    exit('skip by no http proxy available');
}