<?php
define('SWOOLE_LIBRARY', true);

$useShortname = ini_get_all('swoole')['swoole.use_shortname']['local_value'];
$useShortname = strtolower(trim(str_replace('0', '', $useShortname)));
if (! in_array($useShortname, ['', 'off', 'false'], true)) {
    define('SWOOLE_USE_SHORTNAME', true);
} else {
    define('SWOOLE_USE_SHORTNAME', false);
}