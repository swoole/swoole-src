<?php
declare(ticks = 1);
Swoole\Async::set([
    'enable_signalfd' => false,
]);

class FunctionTimeoutException extends RuntimeException
{
    
}

function test()
{
    sleep(1);
}

$serv = new Swoole\Http\Server("127.0.0.1", 9502);

$serv->set(['worker_num' => 1]);

$serv->on('WorkerStart', function($serv, $workerId) {
    pcntl_signal(SIGALRM, function () {
        Swoole\Process::alarm(-1);
        throw new FunctionTimeoutException; 
    });
});

$serv->on('Request', function($request, $response) {
    try
    {
        Swoole\Process::alarm(100 * 1000);
        test();
        Swoole\Process::alarm(-1);
        $response->end("<h1>Finish</h1>");
    }
    catch(FunctionTimeoutException $e)
    {
        $response->end("<h1>Timeout</h1>");
    }

});

$serv->start();
