<?php

namespace Swoole\Coroutine;

class WaitGroup
{
    protected $chan;
    protected $count = 0;

    public function __construct()
    {
        $this->chan = new Channel();
    }

    public function add()
    {
        $this->count++;
    }

    public function done()
    {
        $this->chan->push(true);
    }

    public function wait()
    {
        while ($this->count--) {
            $this->chan->pop();
        }
    }

}
