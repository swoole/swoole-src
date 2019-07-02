<?php
if (ini_get('swoole.use_shortname') === 'On') {
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

    /**
     * @return Swoole\Coroutine\Scheduler
     */
    function scheduler()
    {
        static $scheduler = null;
        if (!$scheduler) {
            $scheduler = new Swoole\Coroutine\Scheduler();
        }
        return $scheduler;
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
function swoole_array_default_value(array $array, $key, $default_value = '')
{
    return array_key_exists($key, $array) ? $array[$key] : $default_value;
}
