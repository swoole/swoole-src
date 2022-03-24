<?php
/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2017 The Swoole Group                             |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.0 of the Apache license,    |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.apache.org/licenses/LICENSE-2.0.html                      |
 | If you did not receive a copy of the Apache2.0 license and are unable|
 | to obtain it through the world-wide-web, please send a note to       |
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <rango@swoole.com>                             |
 +----------------------------------------------------------------------+
 */

namespace SwooleTest;

use Swoole;
use \RandStr;

abstract class LengthServer
{
    protected $setting;
    protected $index = array();
    protected $recv_bytes = 0;
    protected $count = 0;
    protected $show_lost_package = false;

    static public $pkg_num = 100000;
    static public $pkg_len_min = 100;
    static public $pkg_len_max = 200000;
    static public $random_bytes = true;

    /**
     * @var Swoole\Coroutine\Server
     */
    protected $serv;

    protected $debug = false;

    function onReceive($data)
    {
        $header = unpack('Nlen/Nindex/Nsid', substr($data, 0, 12));
        if ($header['index'] % 1000 == 0 and $this->debug) {
            echo "#{$header['index']} recv package. sid={$header['sid']}, length=" . strlen($data) . ", bytes={$this->recv_bytes}\n";
        }
        if ($header['index'] > self::$pkg_num) {
            echo "invalid index #{$header['index']}\n";
        }
        $this->index[$header['index']] = true;
    }

    abstract function onWorkerStart();

    /**
     * TestServer_Co constructor.
     * @param int $port
     * @param bool $ssl
     * @throws \Swoole\Exception
     */
    function __construct(int $port, bool $ssl = false)
    {
        $serv = new  Swoole\Coroutine\Server('127.0.0.1', $port, $ssl);
        $this->serv = $serv;
        $this->setting = [
            'open_length_check' => true,
            'package_max_length' => 1024 * 1024,
            'package_length_type' => 'N',
            'package_length_offset' => 0,
            'package_body_offset' => 4,
        ];
    }

    /**
     * @param $conn \Swoole\Coroutine\Server\Connection
     * @param $data
     */
    function _receive($conn, $data)
    {
        $this->count++;
        $this->recv_bytes += strlen($data);
        $this->onReceive($data);
        if ($this->count == self::$pkg_num) {
            $conn->send("end\n");
        }
    }

    function onClose()
    {
        echo "Total count={$this->count}, bytes={$this->recv_bytes}\n";
        if ($this->show_lost_package) {
            for ($i = 0; $i < self::$pkg_num; $i++) {
                if (!isset($this->index[$i])) {
                    echo "lost package#$i\n";
                }
            }
        }
        $this->count = $this->recv_bytes = 0;
        unset($this->index);
        $this->index = array();
    }

    function set($conf)
    {
        $this->setting += $conf;
    }

    function start()
    {
        $this->serv->set($this->setting);
        $this->serv->handle(function ($conn) {
            while (true) {
                $data = $conn->recv();
                if (!$data) {
                    $this->onClose();
                    break;
                } else {
                    $this->_receive($conn, $data);
                }
            }
        });
        $this->onWorkerStart();
        $this->serv->start();
    }

    /**
     * @return string
     * @throws Exception
     */
    static function getPacket()
    {
        static $index = 0;
        $sid = rand(10000000, 99999999);
        $n = rand(self::$pkg_len_min, self::$pkg_len_max);

        $data = self::$random_bytes ? RandStr::getBytes($n) : (new \Swoole\StringObject('A'))->repeat($n)->toString();
        return pack('NNN', $n + 8, $index++, $sid) . $data;
    }
}
