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
        $this->server = new Swoole\Http\Server("0.0.0.0", 9508);
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
            $cli = new Swoole\Coroutine\Http\Client('0.0.0.0',443,TRUE );
            $cli->set([ 'timeout' => 1]);
            $cli->setHeaders([
                'Host' => "api.mp.qq.com",
                "User-Agent" => 'Chrome/49.0.2587.3',
                'Accept' => 'text/html,application/xhtml+xml,application/xml',
                'Accept-Encoding' => 'gzip',
            ]);
            $ret = ($cli->get('/cgi-bin/token?appid=3333&secret=222'.$i.$i.$i.$i.$i));
            error_log(__LINE__.var_export($cli,true).PHP_EOL,3,'/tmp/markyuan');
            $cli->close();
        }
    }

    private static function http(){
        error_log(__LINE__.'---------- begin --- http --------------'.PHP_EOL,3,'/tmp/markyuan');
        for($i=0;$i<2;$i++){
            $cli = new Swoole\Coroutine\Http\Client('0.0.0.0', 9510);
            $cli->set([ 'timeout' => 1]);
            $cli->setHeaders([
                'Host' => "api.mp.qq.com",
                "User-Agent" => 'Chrome/49.0.2587.3',
                'Accept' => 'text/html,application/xhtml+xml,application/xml',
                'Accept-Encoding' => 'gzip',
            ]);
            error_log(__LINE__.var_export($cli,true).PHP_EOL,3,'/tmp/markyuan');
            $ret = ($cli->get('/cn/token?appid=1FxxxxS9V'.$i.$i.$i.$i.$i));
            error_log(__LINE__.var_export($ret,true).PHP_EOL,3,'/tmp/markyuan');
            error_log(__LINE__.var_export($cli,true).PHP_EOL,3,'/tmp/markyuan');
            $cli->close();
        }
        error_log(__LINE__.'---------- end --- http --------------'.PHP_EOL,3,'/tmp/markyuan');

    }

    private static function multihttp(){
        
        error_log(__LINE__.'---------- begin --- multi --------------'.PHP_EOL,3,'/tmp/markyuan');
        
        $cliAA= new Swoole\Coroutine\Http\Client('0.0.0.0', 9510);
        $cliAA->set(['timeout' => 1]);
        $cliAA->setHeaders([
            'Host' => "api.mp.qq.com",
            "User-Agent" => 'Chrome/49.0.2587.3',
        ]);
        $cliBB= new Swoole\Coroutine\Http\Client('0.0.0.0', 9510);
        $cliBB->set([ 'timeout' => 1]);//
        $cliBB->setHeaders([
            'Host' => "api.mp.qq.com",
            "User-Agent" => 'Chrome/49.0.2587.3',
        ]);
        error_log(__LINE__.var_export($cliAA,true).PHP_EOL,3,'/tmp/markyuan');
        error_log(__LINE__.var_export($cliBB,true).PHP_EOL,3,'/tmp/markyuan');
        $retAA=$cliAA->setDefer(1);
        $retBB=$cliBB->setDefer(1);
        error_log(__LINE__.var_export($retAA,true).PHP_EOL,3,'/tmp/markyuan');
        error_log(__LINE__.var_export($retBB,true).PHP_EOL,3,'/tmp/markyuan');
        error_log(__LINE__.var_export($cliAA,true).PHP_EOL,3,'/tmp/markyuan');
        error_log(__LINE__.var_export($cliBB,true).PHP_EOL,3,'/tmp/markyuan');
        $retAA = ($cliAA->get('/cn/token?appid=AAA'));
        $retBB = ($cliBB->get('/cn/token?appid=BBB'));
        error_log(__LINE__.var_export($retAA,true).PHP_EOL,3,'/tmp/markyuan');
        error_log(__LINE__.var_export($retBB,true).PHP_EOL,3,'/tmp/markyuan');
        error_log(__LINE__.var_export($cliAA,true).PHP_EOL,3,'/tmp/markyuan');
        error_log(__LINE__.var_export($cliBB,true).PHP_EOL,3,'/tmp/markyuan');
        $retAA=$cliAA->recv();
        $retBB=$cliBB->recv();
        error_log(__LINE__.var_export($retAA,true).PHP_EOL,3,'/tmp/markyuan');
        error_log(__LINE__.var_export($retBB,true).PHP_EOL,3,'/tmp/markyuan');
        error_log(__LINE__.var_export($cliAA,true).PHP_EOL,3,'/tmp/markyuan');
        error_log(__LINE__.var_export($cliBB,true).PHP_EOL,3,'/tmp/markyuan');
        $retAA=$cliAA->close();
        $retBB=$cliBB->close();
        error_log(__LINE__.'---------- end --- multi --------------'.PHP_EOL,3,'/tmp/markyuan');
    }

    
    
    private static function tcp(){
        for($i=0;$i<2;$i++){
            $tcp_cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
            $ret = $tcp_cli ->connect("0.0.0.0", 9511);
            $ret = $tcp_cli ->send('test for the coro');
            $ret = $tcp_cli ->recv();
            $ret=$tcp_cli->close();
        }
    }

 private static function coro_dns(){
    swoole_async_set(array('use_async_resolver'=>1));
    swoole_async_set(array('dns_cache_refresh_time'=>0));
    $ret=swoole_async_dns_lookup_coro("www.baidu.com",0.5);
    error_log(' ip and host '.$host.print_r($ret,true),'3','/home/yuanyizhi/markyuan/markyuan.log');
    return $ret;
//  swoole_async_dns_lookup("www.baidu.com", function($host, $ip){
//  error_log(' ip and host '.$host.'  and  ip '.$ip,'3','/home/yuanyizhi/markyuan/markyuan.log');
//  });
    }


private static function tcpmulti(){
        $cliAA = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $cliBB = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $retAA = $cliAA ->connect("0.0.0.0", 9511);
        $retBB = $cliBB ->connect("0.0.0.0", 9511);       
        $retAA = $cliAA ->send('test for the coro');
        $retBB = $cliBB ->send('test for the coro');
        $retAA = $cliAA->recv();
        $retBB = $cliBB->recv();
        $cliAA->close();
        $cliBB->close();
    }

    public static function onRequest($request, $response)
    {
//        self::multihttp();
//        self::http();
        //self::https();
//        self::tcp();
      //  self::tcpmulti();
        $ret=self::coro_dns();
        $response->end(print_r($ret,true));
    }


    public static function staticFunc()
    {
        echo "in static function";
    }
}

$server = new Server();

$server->run();



