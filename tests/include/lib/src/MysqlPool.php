<?php

namespace SwooleTest;

use RuntimeException;
use Swoole\Coroutine\Channel;

class MysqlPool
{
    /**
     * @var MysqlPool
     */
    private static $instance;

    /**
     * @var Channel
     */
    private $pool;

    /**
     * @var array
     */
    private $config;

    /**
     * MysqlPool constructor.
     * @param array $config
     */
    public function __construct(array $config = [])
    {
        if (empty($this->pool)) {
            $this->config = $config;
            $this->pool = new Channel($this->config['pool_size']);

            for ($index = 0; $index < $this->config['pool_size']; $index++) {
                // $mysql = new MyDb();
                $mysql = new DbWrapper();
                $res = $mysql->connect($config);
                if ($res === false) {
                    throw new RuntimeException("failed to connect mysql server.");
                } else {
                    $this->put($mysql);
                }
            }
        }
    }

    public function put($mySQL)
    {
        $this->pool->push($mySQL);
    }

    public function get()
    {
        /**
         * @var \Swoole\Coroutine\Mysql $mysql
         */
        $mysql = $this->pool->pop($this->config['pool_get_timeout']);
        if ($mysql === false) {
            throw new RuntimeException('Get mysql timeout, all mysql connection is used');
        }

        return $mysql;
    }

    /**
     * @param array $config
     * @return MysqlPool
     */
    public static function getInstance(array $config = [])
    {
        if (!empty(self::$instance)) {
            return self::$instance;
        }

        if (empty($config)) {
            throw new RuntimeException('Mysql config empty');
        }
        self::$instance = new static($config);

        return self::$instance;
    }

    /**
     * @return mixed
     * @desc 获取当时连接池可用对象
     */
    public function getLength()
    {
        return $this->pool->length();
    }
}
