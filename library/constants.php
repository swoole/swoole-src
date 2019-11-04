<?php
define('SWOOLE_LIBRARY', true);

$useShortname = ini_get_all('swoole')['swoole.use_shortname']['local_value'];
$useShortname = strtolower(trim(str_replace('0', '', $useShortname)));
define('SWOOLE_USE_SHORTNAME', !in_array($useShortname, ['', 'off', 'false'], true));
