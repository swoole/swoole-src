<?php

namespace SwooleTest\Redis;

class Lock
{
    const EXPIRES = 5;

    private $random;
    private $expires;
    private $keyMap = [];

    public static function i(): self
    {
        return new self;
    }

    public function __construct()
    {
        $this->random = substr(md5(microtime()), 0, 8);
    }

    public function lock(string $key, int $expires = self::EXPIRES): bool
    {
        $this->expires = $expires;
        $ret = Redis::main()->set($key, $this->random, ['nx', 'ex' => $this->expires]);
        if ($ret) {
            $this->keyMap[$key] = microtime(true);
        }
        return !!$ret;
    }

    public function unlock(string $key = null)
    {
        if ($key) {
            // unlock one
            if ($this->keyMap[$key] ?? false) {
                if ($this->keyMap[$key] < microtime(true) - $this->expires) {
                    return; // have already expired
                } else {
                    @Redis::main()->del($key);
                }
                unset($this->keyMap[$key]);
            }
        } else {
            // unlock all
            foreach ($this->keyMap as $key => $expires) {
                $this->unlock($key);
            }
        }
    }

    public function __destruct()
    {
        $this->unlock();
    }

}