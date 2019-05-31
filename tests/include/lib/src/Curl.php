<?php
namespace SwooleTest;

use Swoole\Process;
use Swoole;

class Curl
{
    protected $port;

    function getUrlBase()
    {
        return "http://127.0.0.1:{$this->port}";
    }

    protected function run_cli_server($port)
    {
        $proc = new Process(function (Process $p) use ($port) {
            $exec = "/usr/bin/env php -t " . __DIR__ . " -n -S 127.0.0.1:{$port} " . __DIR__ . "/responder/get.php";
            $p->exec('/bin/sh', array('-c', $exec));
        }, true, 1);

        $proc->start();
        while(true) {
            usleep(10000);
            if (@file_get_contents($this->getUrlBase().'/')) {
                break;
            }
        }
        return $proc;
    }

    function run(callable $fn) {

        $this->port = get_one_free_port();
        $proc = $this->run_cli_server(  $this->port);

        Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_CURL);

        go(function () use ($fn, $proc) {
            $fn();
            Swoole\Process::kill($proc->pid);
        });
        Swoole\Event::wait();
    }
}