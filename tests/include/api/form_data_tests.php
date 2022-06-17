<?php

use Swoole\Coroutine\Client;

function form_data_test_1(ProcessManager $pm)
{
    Swoole\Coroutine\run(function () use ($pm) {
        $client = new Client(SWOOLE_SOCK_TCP);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort()));
        $req = file_get_contents(SOURCE_ROOT_PATH . '/core-tests/fuzz/cases/req1.txt');

        $client->send(substr($req, 0, OFFSET));
        usleep(10000);
        $client->send(substr($req, OFFSET));

        $resp = $client->recv();
        [$header, $json] = explode("\r\n\r\n", $resp);
        Assert::assert($json);
        $data = json_decode($json);
        Assert::assert(is_object($data));
        Assert::minLength($data->test, 80);
        Assert::minLength($data->hello, 120);
        Assert::minLength($data->world, 1024);
        $client->close();
    });
    $pm->kill();
    echo "DONE\n";
}
