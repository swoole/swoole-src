<?php

if (substr(PHP_OS, 0, 3) == 'WIN') {
	die ("skip not for Windows");
}

if (!class_exists('swoole_http_client')) {
	die ("skip for async-httpclient is not enabled");
}

