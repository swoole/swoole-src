<?php
/**
 * @Author: syyuanyizhi@163.com
    connect refuse： errorCode  111
    I/O     timeout：errorCode  110

 */
class Server
{
    public $server;

    public function run()
    {
        $this->server = new Swoole\Http\Server("0.0.0.0", 9502);
        $this->server->set([
            'worker_num' => 1,
            'daemonize' => true,
            'log_file' => '/data/markyuan/swoole.log',
        ]);
        $this->server->on('Request', ['Server', 'onRequest']);
        $this->server->start();
    }

    private static function https(){
        //--enable-openssl 
        for($i=0;$i<2;$i++){
            $cli = new Swoole\Coroutine\Http\Client('10.166.145.243',443,TRUE );
            $cli->set([ 'timeout' => 1]);
            $cli->setHeaders([
                'Host' => "api.mp.qq.com",
                "User-Agent" => 'Chrome/49.0.2587.3',
                'Accept' => 'text/html,application/xhtml+xml,application/xml',
                'Accept-Encoding' => 'gzip',
            ]);
            $ret = ($cli->get('/cgi-bin/token?appid=3333&secret=222'.$i.$i.$i.$i.$i));
            $cli->close();
        }
    }

    private static function http(){
        for($i=0;$i<2;$i++){
            $cli = new Swoole\Coroutine\Http\Client('0.0.0.0', 9599);
            $cli->set([ 'timeout' => 1]);
            $cli->setHeaders([
                'Host' => "api.mp.qq.com",
                "User-Agent" => 'Chrome/49.0.2587.3',
                'Accept' => 'text/html,application/xhtml+xml,application/xml',
                'Accept-Encoding' => 'gzip',
            ]);
            $ret = ($cli->get('/cn/token?appid=1FxxxxS9V'.$i.$i.$i.$i.$i));
            $cli->close();
        }
    }

    private static function multihttp(){
        $multi = new Swoole\Coroutine\Multi();
        $cliAA= new Swoole\Coroutine\Http\Client('0.0.0.0', 9599);
        $cliAA->set([ 'timeout' => 1]);//
        $cliAA->setHeaders([
            'Host' => "api.mp.qq.com",
            "User-Agent" => 'Chrome/49.0.2587.3',
        ]);
        $cliBB= new Swoole\Coroutine\Http\Client('0.0.0.0', 9599);
        $cliBB->set([ 'timeout' => 1]);//
        $cliBB->setHeaders([
            'Host' => "api.mp.qq.com",
            "User-Agent" => 'Chrome/49.0.2587.3',
        ]);
        $multi->add(['AAAA' => $cliAA, 'BBBB' => $cliBB]);
        $retAA = ($cliAA->get('/cn/token?appid=AAA'));
        $retBB = ($cliBB->get('/cn/token?appid=BBB'));
        $ret = $multi->recv();
        $cliAA->close();
        $cliBB->close();
    }

    private static function tcp(){
        for($i=0;$i<2;$i++){
            $tcp_cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
            $ret = $tcp_cli ->connect("10.213.144.140", 9805);
            $ret = $tcp_cli ->send('test for the coro');
            $ret = $tcp_cli ->recv();
            $ret=$tcp_cli->close();
        }
    }

 private static function tcpmulti(){
        $multi = new Swoole\Coroutine\Multi();
        $cliAA = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $cliBB = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $multi->add(['AAAA' => $cliAA, 'BBBB' => $cliBB]);
        $retAA = $cliAA ->connect("10.213.144.140", 9805);
        $retBB = $cliBB ->connect("10.213.144.140", 9805);       
        $retAA = $cliAA ->send('test for the coro');
        $retBB = $cliBB ->send('test for the coro');
        $ret = $multi->recv();
        $cliAA->close();
        $cliBB->close();
    }

    public static function onRequest($request, $response)
    {
        self::multihttp();
        self::http();
        self::https();
        self::tcp();
        self::tcpmulti();
        $response->end('xxxx');
    }


    public static function staticFunc()
    {
        echo "in static function";
    }
}

$server = new Server();

$server->run();



