<?php

namespace SwooleTest;

use Swoole\Thread;

class ThreadManager extends ProcessManager
{
    public $useConstantPorts = true;

    function run($redirectStdout = false): void
    {
        $args = Thread::getArguments();
        if (empty($args)) {
            ($this->parentFunc)();
        } else {
            ($this->childFunc)(...$args);
        }
    }
}
