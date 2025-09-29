<?php

namespace SwooleTest;

use Swoole\Process;

class ChildProcess
{
    protected $process;

    protected function __construct($script)
    {
        $this->process = new Process(function (Process $worker) use ($script) {
            $worker->exec('/bin/sh', ['-c', $script]);
        }, true, SOCK_STREAM, false);
        $this->process->start();
    }

    public function read()
    {
        return $this->process->read();
    }

    public function write(string $data): void
    {
        $this->process->write($data);
    }

    static function exec(string $script): ChildProcess
    {
        return new self($script);
    }
}
