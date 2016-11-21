<?php
/**
 * @Author: syyuanyizhi@163.com
    connect refuse： errorCode  111
    I/O     timeout：errorCode  110
    http 9510
    tcp  9511

 */
class Server
{
    public $server;

    public function run()
    {
        $this->server = new Swoole\Http\Server("0.0.0.0", 9510);
        $this->server->set([
            'worker_num' => 1,
            'daemonize' => true,
            'log_file' => '/data/markyuan/swoole.log',
        ]);
        $this->server->on('Request', ['Server', 'onRequest']);
        $this->server->start();
    }
    public static function onRequest($request, $response)
    {

        $response->end('xxxx');
    }


    public static function staticFunc()
    {
        echo "in static function";
    }
}

$server = new Server();

$server->run();



