<?php

namespace SwooleTest\Redis;

/**
 * Class Redis
 * @package SwooleTest\Bug\Redis
 * @method del($key)
 * @method set($key, $value, $args)
 */
Class Redis
{
    public $is_in_pool = false;

    public $name;

    /**
     * @var \Swoole\Coroutine\Redis
     */
    public $client;

    public static function i(array $options)
    {
        $name = 'redis_' . $options['host'] . ':' . $options['port'];
        $pool = SQLPool::i($name);
        /**@var $redis Redis */
        if (count($pool) > 0 && ($redis = $pool->shift()) && $redis->isConnect()) {
            //满足 1.会话池里有空闲连接 2.返回了一个非空连接 3.Redis没有超时时间
            $redis->is_in_pool = false;
            return $redis;
        }
        return new self($name, $options);
    }

    public static function main(): self
    {
        return self::i([
            'host' => REDIS_SERVER_HOST,
            'port' => REDIS_SERVER_PORT
        ]);
    }

    private function __construct(string $name, array $options)
    {
        $this->name = $name;
        $this->client = new \Swoole\Coroutine\Redis();
        if (!$this->client->connect($options['host'], $options['port'])) {
            new DBConnectException('[Redis: ' . $this->client->errCode . '] ' . $this->client->errMsg,
                $this->client->errCode);
        }
    }

    public function isConnect(): bool
    {
        return $this->client->connected ?? false;
    }

    public function __call(string $name, $params)
    {
        if ($this->is_in_pool) {
            throw new \BadMethodCallException('this redis client is in pool!');
        }
        $ret = call_user_func_array([$this->client, $name], $params);
        $this->revert();
        return $ret;
    }

    public function revert()
    {
        SQLPool::i($this->name)->push($this);
        $this->is_in_pool = true;
    }

    public function __destruct()
    {
        $this->client->close();
    }

}
