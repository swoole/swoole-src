<?php
/**
 * User: lufei
 * Date: 2020/8/6
 * Email: lufei@swoole.com
 */

namespace Swoole\Rpc;

class User
{
    public function getList($uid, $type)
    {
        return [
            'uid' => $uid,
            'type' => $type,
            'time' => date('Y-m-d H:i:s')
        ];
    }
}