<?php

namespace SwooleTest;

use Swoole\Process;
use Swoole;
use function Swoole\Coroutine\run as run;

class CurlManager
{
    protected $port;
    protected $nativeCurl = false;

    function __construct() {
        $this->nativeCurl = defined('SWOOLE_HOOK_NATIVE_CURL');
    }

    function disableNativeCurl() {
        $this->nativeCurl = false;
    }

    function getUrlBase()
    {
        return "http://127.0.0.1:{$this->port}";
    }

    protected function runCliServer($port)
    {
        $proc = new Process(function (Process $p) use ($port) {
            $exec = "/usr/bin/env php -t " . __DIR__ . " -n -S 127.0.0.1:{$port} " . __DIR__ . "/responder/get.php";
            $p->exec('/bin/sh', ['-c', $exec]);
        }, true, 1);

        $proc->start();
        while (1) {
            usleep(10000);
            if (@file_get_contents($this->getUrlBase() . '/')) {
                break;
            }
        }
        return $proc;
    }

    function run(callable $fn, $createCliServer = true)
    {
        if ($createCliServer) {
            $this->port = get_one_free_port();
            $proc = $this->runCliServer($this->port);
        } else {
            $proc = null;
        }

        global $argc, $argv;
        if (!($argc > 1 and $argv[1] == 'ori')) {
            $flags = $this->nativeCurl ? SWOOLE_HOOK_NATIVE_CURL : SWOOLE_HOOK_CURL;
            Swoole\Runtime::enableCoroutine($flags);
        }

        run(function () use ($fn, $proc) {
            $fn("127.0.0.1:{$this->port}");
            if ($proc) {
                Swoole\Process::kill($proc->pid);
            }
        });

        if ($createCliServer) {
            Process::wait();
        }
    }
}
