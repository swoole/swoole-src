<?php

namespace SwooleTest\Redis;

class SQLPool
{
    /**
     * @var self
     */
    private static $instance;

    /**
     * @param string $name
     * @return \SplQueue
     */
    public static function i(string $name): \SplQueue
    {
        if (!self::$instance) {
            self::$instance = new self;
        }
        return self::$instance->$name ?? (self::$instance->$name = new \SplQueue);
    }

    public static function release()
    {
        self::$instance = null;
    }

}
