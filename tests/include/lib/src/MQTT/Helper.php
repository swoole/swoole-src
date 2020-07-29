<?php

namespace SwooleTest\MQTT;

class Helper
{
    public static function getHeader($data)
    {
        $byte = ord($data[0]);

        $header['type'] = ($byte & 0xF0) >> 4;
        $header['dup'] = ($byte & 0x08) >> 3;
        $header['qos'] = ($byte & 0x06) >> 1;
        $header['retain'] = $byte & 0x01;

        return $header;
    }

    public static function encodePublish($data)
    {
        $cmd = 3 << 4;
        $body = pack('n', strlen($data['topic'])) . $data['topic'] . $data['content'];

        $length = strlen($body);
        $string = '';
        do {
            $digit = $length % 128;
            $length = $length >> 7;
            if ($length > 0) {
                $digit = ($digit | 0x80);
            }
            $string .= chr($digit);
        } while ($length > 0);

        $head = chr($cmd) . $string;
        return $head . $body;
    }
}