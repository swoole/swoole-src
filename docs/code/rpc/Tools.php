<?php
/**
 * User: lufei
 * Date: 2020/8/6
 * Email: lufei@swoole.com
 */

namespace Swoole\Rpc;

class Tools
{
    /**
     * 数据打包
     * @param $data
     * @param bool $encode_json
     * @return string
     */
    public static function pack($data, $encode_json = true)
    {
        // json编码
        if ($encode_json) {
            $_send_data = json_encode($data);
        } else {
            $_send_data = $data;
        }
        //加入包头
        return pack('N', strlen($_send_data)) . $_send_data;
    }

    /**
     * 数据解包
     * @param $data
     * @param bool $decode_json
     * @return bool|mixed|string
     */
    public static function unpack($data, $decode_json = true)
    {
        $_data = substr($data, 4);
        if ($decode_json) {
            return json_decode($_data, true);
        } else {
            return $_data;
        }
    }
}