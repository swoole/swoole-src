<?php

namespace Swoole\Coroutine;

use BadMethodCallException;
use InvalidArgumentException;

class WaitGroup
{
    protected $chan;
    protected $count = 0;
    protected $waiting = false;

    public function __construct()
    {
        $this->chan = new Channel(1);
    }

    public function add(int $delta = 1): void
    {
        if ($this->waiting) {
            throw new BadMethodCallException('WaitGroup misuse: add called concurrently with wait');
        }
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
        if ($count === 0 && $this->waiting) {
            $this->chan->push(true);
        }
    }

    public function wait(float $timeout = -1): bool
    {
        if ($this->count > 0) {
            $this->waiting = true;
            $done = $this->chan->pop($timeout);
            $this->waiting = false;
            return $done;
        }
        return true;
    }
}
