<?php
if (ini_get('swoole.use_shortname') === 'On') {
    function _string(?string $string = ''): Swoole\StringObject
    {
        return new Swoole\StringObject($string);
    }

    function _array(?array $array = []): Swoole\ArrayObject
    {
        return new Swoole\ArrayObject($array);
    }
}
