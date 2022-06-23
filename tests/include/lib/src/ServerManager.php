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


class ServerManager
{
    protected $host;
    protected $file;
    public $port;

    /**
     * ServerManager constructor.
     * @param $file
     * @throws \Exception
     */
    function __construct($file)
    {
        if (!is_file($file))
        {
            throw new \Exception("server file [$file] not exists.");
        }
        $this->file = $file;
    }

    function listen($host = '127.0.0.1', $port = 0)
    {
        $this->port = $port == 0 ? get_one_free_port() : $port;
        $this->host = $host;
    }

    function run($debug = false)
    {
        return start_server($this->file, $this->host, $this->port, "/dev/null", null, null, $debug);
    }
}
