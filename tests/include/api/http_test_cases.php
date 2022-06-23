<?php

use Swoole\Coroutine\Socket;
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
                throw new RuntimeException("recv failed, error: " . $client->errMsg . ", resp: " . $resp);
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

function getHttpBody(string $s): string
{
    return str_replace(EOF, '', explode("\r\n\r\n", $s)[1] ?? '');
}

function generateChunkBody(array $a): string
{
    $s = '';
    foreach ($a as $c) {
        $s .= dechex(strlen($c)) . "\r\n" . $c . "\r\n";
    }
    return $s . "0\r\n";
}

function chunked_request(ProcessManager $pm)
{
    Swoole\Coroutine\run(function () use ($pm) {
        $request_empty_chunked =
            "DELETE /locks?password=9c1858261b4337b49af4fb8c57a9ec98&lock_id=1&amount=1.2&c=6331b32ac32f4c128ce0016114e11dbd&lang=zh_CN HTTP/1.1\r\n" .
            "x-real-ip: 10.2.100.1\r\n" .
            "x-forwarded-server: kitchen.pool-x.net\r\n" .
            "accept: application/json\r\n" .
            "origin: http://pool-x.net\r\n" .
            "user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36\r\n" .
            "sec-fetch-site: cross-site\r\n" .
            "sec-fetch-mode: cors\r\n" .
            "referer: http://pool-x.net/assets/staking\r\n" .
            "accept-encoding: gzip, deflate, br\r\n" .
            "accept-language: zh-CN,zh;q=0.9,be;q=0.8,ru;q=0.7\r\n" .
            "cookie: gr_user_id=1696256d-0a68-486f-a507-74191e74dbc6; grwng_uid=2682d2d1-4de3-407d-9946-5df333a44bef; _ga=GA1.2.224995769.1577363886; X-TRACE=w60NOEhe/g1irg2+SHF63xNYUS2H/vJUtP40DAUMqGQ=; a46016b4ef684522_gr_last_sent_cs1=265sy72; a46016b4ef684522_gr_session_id=45d1c2ec-dd54-4005-af9e-a01ccad4473b; a46016b4ef684522_gr_last_sent_sid_with_cs1=45d1c2ec-dd54-4005-af9e-a01ccad4473b; a46016b4ef684522_gr_session_id_45d1c2ec-dd54-4005-af9e-a01ccad4473b=true; SESSION=ZGExNmI1ODYtZTQzNi00MWQ0LTk1NzAtNzYzOTE3NDFjZDc5; _gid=GA1.2.951149480.1577691293; a46016b4ef684522_gr_cs1=265sy72\r\n" .
            "x-domain: kitchen.pool-x.net\r\n" .
            "x-session-id: da16b586-e436-41d4-9570-76391741cd79\r\n" .
            "x-device-id: \r\n" .
            "x-origin-domain-id: pool\r\n" .
            "x-forwarded-proto: http\r\n" .
            "uber-trace-id: ffaf3497a6deee40%3A8afa1564e1e0783f%3Affaf3497a6deee40%3A1\r\n" .
            "x-forwarded-port: 80\r\n" .
            "x-forwarded-for: 127.0.0.1\r\n" .
            "x-user-id: 5dd5fbc9e316c178d6930678\r\n" .
            "x-domain-id: pool\r\n" .
            "kyc-country: \r\n" .
            "kyc-status: \r\n" .
            "x-forwarded-host: kitchen.pool-x.net\r\n" .
            "x-forwarded-prefix: /pool-staking\r\n" .
            "gateway-type: WEB\r\n" .
            "lang: zh_CN\r\n" .
            "Transfer-Encoding: chunked\r\n" .
            "Host: 10.2.1.51:9526\r\n" .
            "Connection: Keep-Alive\r\n" .
            "\r\n" .
            "0\r\n" .
            "\r\n";
        $request_zero_length =
            "GET /locks?currency=&start_at=1576771200000&end_at=1577721599999&pageSize=20&page=1&c=6331b32ac32f4c128ce0016114e11dbd&lang=zh_CN&_t=1577694714586 HTTP/1.1\r\n" .
            "x-real-ip: 10.2.100.1\r\n" .
            "x-forwarded-server: kitchen.pool-x.net\r\n" .
            "accept: application/json\r\n" .
            "origin: http://pool-x.net\r\n" .
            "user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36\r\n" .
            "sec-fetch-site: cross-site\r\n" .
            "sec-fetch-mode: cors\r\n" .
            "referer: http://pool-x.net/assets/staking\r\n" .
            "accept-encoding: gzip, deflate, br\r\n" .
            "accept-language: zh-CN,zh;q=0.9,be;q=0.8,ru;q=0.7\r\n" .
            "cookie: gr_user_id=1696256d-0a68-486f-a507-74191e74dbc6; grwng_uid=2682d2d1-4de3-407d-9946-5df333a44bef; _ga=GA1.2.224995769.1577363886; X-TRACE=w60NOEhe/g1irg2+SHF63xNYUS2H/vJUtP40DAUMqGQ=; a46016b4ef684522_gr_last_sent_cs1=265sy72; a46016b4ef684522_gr_session_id=45d1c2ec-dd54-4005-af9e-a01ccad4473b; a46016b4ef684522_gr_last_sent_sid_with_cs1=45d1c2ec-dd54-4005-af9e-a01ccad4473b; a46016b4ef684522_gr_session_id_45d1c2ec-dd54-4005-af9e-a01ccad4473b=true; SESSION=ZGExNmI1ODYtZTQzNi00MWQ0LTk1NzAtNzYzOTE3NDFjZDc5; _gid=GA1.2.951149480.1577691293; a46016b4ef684522_gr_cs1=265sy72\r\n" .
            "x-domain: kitchen.pool-x.net\r\n" .
            "x-session-id: da16b586-e436-41d4-9570-76391741cd79\r\n" .
            "x-device-id: \r\n" .
            "x-origin-domain-id: pool\r\n" .
            "x-forwarded-proto: http\r\n" .
            "uber-trace-id: df854c374e6d4fde%3Ada6b1dc2e4e112b5%3Adf854c374e6d4fde%3A0\r\n" .
            "x-forwarded-port: 80\r\n" .
            "x-forwarded-for: 127.0.0.1\r\n" .
            "x-user-id: 5dd5fbc9e316c178d6930678\r\n" .
            "x-domain-id: pool\r\n" .
            "kyc-country: \r\n" .
            "kyc-status: \r\n" .
            "x-forwarded-host: kitchen.pool-x.net\r\n" .
            "x-forwarded-prefix: /pool-staking\r\n" .
            "gateway-type: WEB\r\n" .
            "lang: zh_CN\r\n" .
            "Content-Length: 0\r\n" .
            "Host: 10.2.1.51:9526\r\n" .
            "Connection: Keep-Alive\r\n" .
            "\r\n";
        $request_chunked_body_array = ['FOO', 'BAR', 'CHAR', str_repeat('Z', mt_rand(10, 1000))];
        $request_chunked_body = generateChunkBody($request_chunked_body_array);
        $request_chunked = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n{$request_chunked_body}\r\n";
        $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        Assert::true($socket->connect('127.0.0.1', $pm->getFreePort()));
        Assert::true($socket->setProtocol([
            'open_eof_check' => true,
            'package_eof' => EOF
        ]));
        /* chunked */
        $ret = $socket->sendAll($request_empty_chunked);
        Assert::same($ret, strlen($request_empty_chunked));
        $ret = $socket->recvPacket();
        Assert::isEmpty(getHttpBody($ret));
        /* pipeline */
        for ($n = MAX_REQUESTS_LOW; $n--;) {
            $ret = $socket->sendAll($request_zero_length);
            Assert::same($ret, strlen($request_zero_length));
        }
        for ($n = MAX_REQUESTS_LOW; $n--;) {
            $ret = $socket->recvPacket();
            Assert::same(getHttpBody($ret), getHttpBody($request_zero_length));
        }
        /* chunked */
        for ($n = MAX_REQUESTS_LOW; $n--;) {
            $ret = $socket->sendAll($request_chunked);
            Assert::same($ret, strlen($request_chunked));
            $ret = $socket->recvPacket();
            Assert::same(getHttpBody($ret), implode('', $request_chunked_body_array));
        }
    });
    echo "SUCCESS\n";
    $pm->kill();
}
