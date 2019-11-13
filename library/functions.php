<?php
if (SWOOLE_USE_SHORTNAME) {
    /**
     * @param string $string
     * @return Swoole\StringObject
     */
    function _string(string $string = ''): Swoole\StringObject
    {
        return new Swoole\StringObject($string);
    }

    /**
     * @param array $array
     * @return Swoole\ArrayObject
     */
    function _array(array $array = []): Swoole\ArrayObject
    {
        return new Swoole\ArrayObject($array);
    }
}

/**
 * @param string $string
 * @return Swoole\StringObject
 */
function swoole_string(string $string = ''): Swoole\StringObject
{
    return new Swoole\StringObject($string);
}

/**
 * @param array $array
 * @return Swoole\ArrayObject
 */
function swoole_array(array $array = []): Swoole\ArrayObject
{
    return new Swoole\ArrayObject($array);
}

/**
 * @param array $array
 * @param $key
 * @param $default_value
 * @return mixed
 */
function swoole_array_default_value(array $array, $key, $default_value = null)
{
    return array_key_exists($key, $array) ? $array[$key] : $default_value;
}
