<?php
/**
 * User: lufei
 * Date: 2020/8/6
 * Email: lufei@swoole.com
 */

namespace Swoole\Rpc;

include __DIR__ . '/Tools.php';
include __DIR__ . '/User.php';

use Swoole\Rpc\Tools;
use Swoole\Server;

class RpcServer
{
    protected $server;

    public function __construct()
    {
        $this->server = new Server('0.0.0.0', 9502);
        $this->server->set(
            [
                'open_length_check' => true, // 打开包长检测
                'package_length_type' => 'N', // 长度值的类型，与 PHP 的 pack 函数一致
                'package_length_offset' => 0, // 第N个字节是包长度的值
                'package_body_offset' => 4, // 第几个字节开始计算长度
            ]
        );
        $this->onReceive();
        $this->start();
    }

    public function onReceive()
    {
        $this->server->on('receive', function ($ser, $fd, $reactor_id, $data) {
                $pack_data = Tools::unpack($data);

                $class = $pack_data['class'];
                $method = $pack_data['method'];
                $params = $pack_data['params'];

                $class = __NAMESPACE__ . "\\" . $class;
                $res = call_user_func_array(array(new $class, $method), $params);
                $ser->send($fd, Tools::pack($res));
        });
    }

    public function start()
    {
        $this->server->start();
    }
}

$server = new RpcServer();