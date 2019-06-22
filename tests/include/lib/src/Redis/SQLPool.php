<?php

namespace SwooleTest\Redis;

Class SQLPool
{
    private static $instance;

    public static function init()
    {
        self::$instance = new self;
    }

    /**
     * @param string $name
     * @return \SplQueue
     */
    public static function i(string $name): \SplQueue
    {
        return self::$instance->$name ?? (self::$instance->$name = new \SplQueue);
    }

    public static function release()
    {
        self::$instance = null;
    }

}
