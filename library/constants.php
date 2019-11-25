<?php
define('SWOOLE_LIBRARY', true);
define('SWOOLE_USE_SHORTNAME',
    !in_array(
        strtolower(trim(str_replace('0', '',
            ini_get_all('swoole')['swoole.use_shortname']['local_value']
        ))),
        ['', 'off', 'false'],
        true
    )
);
