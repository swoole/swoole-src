<?php
if (ini_get('swoole.use_shortname') === 'On') {
    /**
     * @param string $string
     * @return \Swoole\StringObject
     */
    function _string(string $string = ''): Swoole\StringObject
    {
        return new Swoole\StringObject($string);
    }

    /**
     * @param array $array
     * @return \Swoole\ArrayObject
     */
    function _array(array $array = []): Swoole\ArrayObject
    {
        return new Swoole\ArrayObject($array);
    }
}

/**
 * @param $value
 * @return \Swoole\StringObject|\Swoole\ArrayObject
 */
function swoole_detect_type($value)
{
    if (is_array($value)) {
        return new \Swoole\ArrayObject($value);
    } elseif (is_string($value)) {
        return new \Swoole\StringObject($value);
    } else {
        return $value;
    }
}

/**
 * @param array $array
 * @return \Swoole\ArrayObject
 */
function swoole_array(array $array = []): Swoole\ArrayObject
{
    return new Swoole\ArrayObject($array);
}

/**
 * @param string $string
 * @return \Swoole\StringObject
 */
function swoole_string(string $string = ''): Swoole\StringObject
{
    return new Swoole\StringObject($string);
}

/**
 * @param $array
 * @param $key
 * @param string $default_value
 * @return string
 */
function swoole_default_value($array, $key, $default_value = '')
{
    return array_key_exists($key, $array) ? $array[$key] : $default_value;
}