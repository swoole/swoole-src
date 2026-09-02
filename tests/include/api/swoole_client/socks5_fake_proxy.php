<?php

function socks5_read_exact($socket, int $length, string $description): string
{
    $data = '';
    while (strlen($data) < $length) {
        $chunk = fread($socket, $length - strlen($data));
        if ($chunk === false || $chunk === '') {
            $state = stream_get_meta_data($socket);
            $reason = $state['timed_out'] ? 'timed out' : 'connection closed';
            throw new RuntimeException("{$reason} while waiting for {$description}");
        }
        $data .= $chunk;
    }
    return $data;
}

function socks5_write($socket, string $data): void
{
    Assert::same(fwrite($socket, $data), strlen($data));
}

function socks5_run_proxy(ProcessManager $pm, int $port, bool $fragment = true): void
{
    $server = stream_socket_server('tcp://' . TCP_SERVER_HOST . ":{$port}", $errno, $errstr);
    Assert::notSame($server, false, "{$errstr} ({$errno})");
    $pm->wakeup();

    $socket = stream_socket_accept($server, 5);
    Assert::notSame($socket, false);
    Assert::true(stream_set_timeout($socket, 2));
    Assert::same(socks5_read_exact($socket, 3, 'negotiation request'), "\x05\x01\x00");

    if ($fragment) {
        socks5_write($socket, "\x05");
        usleep(20000);
        socks5_write($socket, "\x00");
    } else {
        socks5_write($socket, "\x05\x00");
    }

    Assert::same(socks5_read_exact($socket, 4, 'CONNECT request header'), "\x05\x01\x00\x03");
    $hostLength = ord(socks5_read_exact($socket, 1, 'CONNECT target length'));
    Assert::same($hostLength, 18);
    Assert::same(socks5_read_exact($socket, $hostLength, 'CONNECT target'), 'socks5-target.test');
    Assert::same(unpack('n', socks5_read_exact($socket, 2, 'CONNECT target port'))[1], 80);

    $response = "\x05\x00\x00\x01\x7f\x00\x00\x01\x1f\x90";
    if ($fragment) {
        for ($i = 0; $i < strlen($response) - 1; $i++) {
            socks5_write($socket, $response[$i]);
            usleep(20000);
        }
        socks5_write($socket, $response[strlen($response) - 1] . "SOCKS5 READY\n");
    } else {
        socks5_write($socket, $response . "SOCKS5 READY\n");
    }

    fclose($socket);
    fclose($server);
}
