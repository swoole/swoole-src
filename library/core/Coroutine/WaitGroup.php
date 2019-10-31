<?php

namespace Swoole\Coroutine;

use BadMethodCallException;
use InvalidArgumentException;

class WaitGroup
{
    protected $cid;
    protected $count = 0;

    public function __construct()
    {
        $this->cid = \Swoole\Coroutine::getCid();
    }

    public function add(int $delta = 1): void
    {
        $count = $this->count + $delta;
        if ($count < 0) {
            throw new InvalidArgumentException('negative WaitGroup counter');
        }
        $this->count = $count;
    }

    public function done(): void
    {
        $count = $this->count - 1;
        if ($count < 0) {
            throw new BadMethodCallException('negative WaitGroup counter');
        }
        $this->count = $count;
        if ($this->cid == \Swoole\Coroutine::getCid()) {
            return;
        }
        \Swoole\Coroutine::resume($this->cid);
    }

    public function wait(float $timeout = -1): void
    {
        while ($this->count > 0) {
            \Swoole\Coroutine::yield();
        }
    }
}
