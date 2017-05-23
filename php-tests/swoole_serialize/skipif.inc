<?php

if (substr(PHP_OS, 0, 3) == 'WIN') {
	die ("skip not for Windows");
}

if (PHP_VERSION_ID < 70000) {
	die ("skip not for Version blow php7");
}

if (!class_exists('swoole_serialize')) {
	die ("skip for swoole_serialize is not enabled");
}
