<?php
if (!function_exists('_string')) {
    /**
     * @param  string $str
     * @return Swoole\StringObject
     */
    function _string($str)
    {
        return new Swoole\StringObject($str);
    }
}

if (!function_exists('_array')) {
    /**
     * @param  array $array
     * @return Swoole\ArrayObject
     */
    function _array($array)
    {
        return new Swoole\ArrayObject($array);
    }
}