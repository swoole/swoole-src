<?php
/**
 * @Author: markyuan
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

        for($i=0;$i<2;$i++){
            error_log(__LINE__.' ' . var_export($i, true).'----------------'.PHP_EOL, 3, '/tmp/markyuan.log');
            $cli = new Swoole\Coroutine\Http\Client('10.166.145.243',443,TRUE );
            error_log(__LINE__.' ' .__LINE__.PHP_EOL, 3, '/tmp/markyuan.log');
            $cli->set([ 'timeout' => 1]);
            $cli->setHeaders([
                'Host' => "api.mp.qq.com",
                "User-Agent" => 'Chrome/49.0.2587.3',
                'Accept' => 'text/html,application/xhtml+xml,application/xml',
                'Accept-Encoding' => 'gzip',
            ]);
            error_log(__LINE__.' ' .PHP_EOL, 3, '/tmp/markyuan.log');
            $ret = ($cli->get('/cgi-bin/token?appid=3333&secret=222'.$i.$i.$i.$i.$i));
            error_log(__LINE__.' ' . var_export($ret, true).PHP_EOL, 3, '/tmp/markyuan.log');
            error_log(__LINE__.' ' . var_export($cli, true).PHP_EOL, 3, '/tmp/markyuan.log');
            error_log(__LINE__.' ' . var_export($cli->errCode, true).PHP_EOL, 3, '/tmp/markyuan.log');
            $cli->close();
            error_log(__LINE__.' ' . var_export($i, true).'----------------'.PHP_EOL, 3, '/tmp/markyuan.log');
        }
    }

    private static function http(){
        for($i=0;$i<2;$i++){
            error_log(__LINE__.' ' . var_export($i, true).'----------------'.PHP_EOL, 3, '/tmp/markyuan.log');
            $cli = new Swoole\Coroutine\Http\Client('0.0.0.0', 9599);
            error_log(__LINE__.' ' .__LINE__.PHP_EOL, 3, '/tmp/markyuan.log');
            $cli->set([ 'timeout' => 1]);
            $cli->setHeaders([
                'Host' => "api.mp.qq.com",
                "User-Agent" => 'Chrome/49.0.2587.3',
                'Accept' => 'text/html,application/xhtml+xml,application/xml',
                'Accept-Encoding' => 'gzip',
            ]);
            error_log(__LINE__.' ' .PHP_EOL, 3, '/tmp/markyuan.log');
            $ret = ($cli->get('/cn/token?appid=1FxxxxS9V'.$i.$i.$i.$i.$i));
            error_log(__LINE__.' ' . var_export($ret, true).PHP_EOL, 3, '/tmp/markyuan.log');
            error_log(__LINE__.' ' . var_export($cli, true).PHP_EOL, 3, '/tmp/markyuan.log');
            error_log(__LINE__.' ' . var_export($cli->errCode, true).PHP_EOL, 3, '/tmp/markyuan.log');
            $cli->close();
            error_log(__LINE__.' ' . var_export($i, true).'----------------'.PHP_EOL, 3, '/tmp/markyuan.log');
        }
    }

    private static function multihttp(){
        $multi = new Swoole\Coroutine\Multi();
        $cliAA= new Swoole\Coroutine\Http\Client('0.0.0.0', 9599);
        error_log( __LINE__.PHP_EOL, 3, '/tmp/markyuan.log');
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
        error_log(' ' .__LINE__.PHP_EOL, 3, '/tmp/markyuan.log');
        $retAA = ($cliAA->get('/cn/token?appid=AAA'));
        $retBB = ($cliBB->get('/cn/token?appid=BBB'));
        error_log(__LINE__.' AA ' . var_export($retAA, true).PHP_EOL, 3, '/tmp/markyuan.log');
        error_log(__LINE__.' BB ' . var_export($retBB, true).PHP_EOL, 3, '/tmp/markyuan.log');
        $retBB = ($cliBB->get('/cn/token?appid=BBB'));
        error_log(__LINE__.' AA ' . var_export($retAA, true).PHP_EOL, 3, '/tmp/markyuan.log');
        error_log(__LINE__.' AA '  . var_export($cliAA, true).PHP_EOL, 3, '/tmp/markyuan.log');
        error_log(__LINE__.' AA '  . var_export($cliAA->errCode, true).PHP_EOL, 3, '/tmp/markyuan.log');
        error_log(__LINE__.' BB '  . var_export($retBB, true).PHP_EOL, 3, '/tmp/markyuan.log');
        error_log(__LINE__.' BB '. var_export($cliBB, true).PHP_EOL, 3, '/tmp/markyuan.log');
        error_log(__LINE__.' BB '. var_export($cliBB->errCode, true).PHP_EOL, 3, '/tmp/markyuan.log');
        $ret = $multi->recv();
        error_log(__LINE__.' AA '. var_export($retAA, true).PHP_EOL, 3, '/tmp/markyuan.log');
        error_log(__LINE__.' AA ' . var_export($cliAA, true).PHP_EOL, 3, '/tmp/markyuan.log');
        error_log(__LINE__.' BB '. var_export($retBB, true).PHP_EOL, 3, '/tmp/markyuan.log');
        error_log(__LINE__.' BB ' . var_export($cliBB, true).PHP_EOL, 3, '/tmp/markyuan.log');
        error_log(__LINE__ . var_export($ret, true).PHP_EOL, 3, '/tmp/markyuan.log');
        $cliAA->close();
        $cliBB->close();
    }

    private static function tcp(){
        for($i=0;$i<2;$i++){
            $tcp_cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
            error_log(__LINE__.'  ' . var_export($tcp_cli, true).PHP_EOL, 3, '/tmp/markyuan.log');
            $ret = $tcp_cli ->connect("10.213.144.140", 9805);
            error_log(__LINE__.'  ' . var_export($ret, true).PHP_EOL, 3, '/tmp/markyuan.log');
            $ret = $tcp_cli ->send('test for the coro');
            error_log(__LINE__.'  ' . var_export($ret, true).PHP_EOL, 3, '/tmp/markyuan.log');
            $ret = $tcp_cli ->recv(100);
            error_log(__LINE__.'  ' . var_export($ret, true).PHP_EOL, 3, '/tmp/markyuan.log');
            $ret=$tcp_cli->close();
            error_log(__LINE__.'  ' . var_export($ret, true).PHP_EOL, 3, '/tmp/markyuan.log');
        }
    }

 private static function tcpmulti(){
        $multi = new Swoole\Coroutine\Multi();
        $cliAA = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $cliBB = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $multi->add(['AAAA' => $cliAA, 'BBBB' => $cliBB]);
        error_log(' ' .__LINE__.PHP_EOL, 3, '/tmp/markyuan.log');
        $retAA = $cliAA ->connect("10.213.144.140", 9805);
        $retBB = $cliBB ->connect("10.213.144.140", 9805);
        error_log(__LINE__.' AA ' . var_export($retAA, true).PHP_EOL, 3, '/tmp/markyuan.log');
        error_log(__LINE__.' BB ' . var_export($retBB, true).PHP_EOL, 3, '/tmp/markyuan.log');
        $retAA = $cliAA ->send('test for the coro');
        $retBB = $cliBB ->send('test for the coro');
        error_log(__LINE__.' AA ' . var_export($retAA, true).PHP_EOL, 3, '/tmp/markyuan.log');
        error_log(__LINE__.' BB ' . var_export($retBB, true).PHP_EOL, 3, '/tmp/markyuan.log');
        $ret = $multi->recv();
        error_log(' ' .__LINE__.var_export($ret,true).PHP_EOL, 3, '/tmp/markyuan.log');
        error_log(__LINE__.' AA '. var_export($retAA, true).PHP_EOL, 3, '/tmp/markyuan.log');
        error_log(__LINE__.' AA ' . var_export($cliAA, true).PHP_EOL, 3, '/tmp/markyuan.log');
        error_log(__LINE__.' BB '. var_export($retBB, true).PHP_EOL, 3, '/tmp/markyuan.log');
        error_log(__LINE__.' BB ' . var_export($cliBB, true).PHP_EOL, 3, '/tmp/markyuan.log');
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



