<?php

use Swoole\Coroutine\Client;

/**
 * @param ProcessManager $pm
 * @throw RuntimeException
 */
function form_data_test_1(ProcessManager $pm)
{
    Swoole\Coroutine\run(function () use ($pm) {
        $client = new Client(SWOOLE_SOCK_TCP);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort()));
        $req = file_get_contents(SOURCE_ROOT_PATH . '/core-tests/fuzz/cases/req1.bin');

        Assert::eq($client->send(substr($req, 0, OFFSET)), OFFSET);
        usleep(10000);
        Assert::eq($client->send(substr($req, OFFSET)), strlen($req) - OFFSET);
        usleep(10000);
        $resp = '';
        $length = 0;
        $header = '';

        while (true) {
            $data = $client->recv();
            if ($data == false) {
                throw new RuntimeException("recv failed, error: " . $client->errMsg.", resp: ".$resp);
            }
            $resp .= $data;
            if ($length == 0) {
                $crlf_pos = strpos($resp, "\r\n\r\n");
                if ($crlf_pos === false) {
                    continue;
                }
                $header = substr($resp, 0, $crlf_pos);
                if (!preg_match('#Content-Length:\s(\d+)#i', $header, $match)) {
                    throw new RuntimeException("no match Content-Length");
                }
                $length = strlen($header) + 4 + $match[1];
            }
            if (strlen($resp) == $length) {
                break;
            }
        }
        Assert::assert($header);
        $body = substr($resp, strlen($header) + 4);
        if (!$body) {
            var_dump($header);
        }
        Assert::assert($body);
        $data = json_decode($body);
        Assert::assert(is_object($data));
        Assert::minLength($data->test, 80);
        Assert::minLength($data->hello, 120);
        Assert::minLength($data->world, 1024);
        $client->close();
    });
    $pm->kill();
    echo "DONE\n";
}
