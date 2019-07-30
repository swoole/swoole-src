<?php

namespace Swoole\Coroutine;

use BadMethodCallException;
use InvalidArgumentException;
use RuntimeException;
use Swoole\Coroutine;

abstract class ObjectPool
{
    protected static $context = [];
    protected $object_pool;
    protected $busy_pool;
    protected $type;

    public function __construct($type, $pool_size = 10, $concurrency = 10)
    {
        if (empty($type)) {
            throw new InvalidArgumentException('ObjectPool misuse: parameter type can not be empty');
        }
        if (!is_numeric($concurrency) || $concurrency <= 0) {
            throw new InvalidArgumentException('ObjectPool misuse: parameter concurrency must larger than 0');
        }

        $this->object_pool = new Channel($pool_size);
        $this->busy_pool = new Channel($concurrency);
        $this->type = $type;
    }

    public function get()
    {
        $context = Coroutine::getContext();
        if (!$context) {
            throw new BadMethodCallException('ObjectPool misuse: get must be used in coroutine');
        }
        $type = $this->type;
        Coroutine::defer(function () {
            $this->free();
        });
        if (isset($context[$type])) {
            return $context[$type];
        }
        if (!$this->object_pool->isEmpty()) {
            $object = $this->object_pool->pop();
            $context["new"] = false;
        } else {
            /* create concurrency control */
            $this->busy_pool->push(true);
            $object = $this->create();
            if (empty($object)) {
                throw new RuntimeException('ObjectPool misuse: create object failed');
            }
            $context["new"] = true;
        }

        $context[$type] = $object;
        return $object;
    }

    public function free()
    {
        $context = Coroutine::getContext();
        if (!$context) {
            throw new BadMethodCallException('ObjectPool misuse: free must be used in coroutine');
        }
        $type = $this->type;
        $object = $context[$type];
        $this->object_pool->push($object);
        if ($context["new"]) {
            $this->busy_pool->pop();
        }
    }

    public abstract function create();
}
