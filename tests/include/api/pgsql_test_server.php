<?php
/**
 * Minimal PostgreSQL protocol fixtures for deterministic I/O regression tests.
 */

function pgsql_test_packet(string $type, string $payload): string
{
    return $type . pack('N', strlen($payload) + 4) . $payload;
}

function pgsql_test_read_exact($client, int $length)
{
    $buffer = '';
    while (strlen($buffer) < $length) {
        $data = fread($client, $length - strlen($buffer));
        if ($data === false || $data === '') {
            return false;
        }
        $buffer .= $data;
    }
    return $buffer;
}

function pgsql_test_read_message($client)
{
    $header = pgsql_test_read_exact($client, 5);
    if ($header === false) {
        return false;
    }
    $length = unpack('N', substr($header, 1))[1] - 4;
    $payload = pgsql_test_read_exact($client, $length);
    return $payload === false ? false : [$header[0], $payload];
}

function pgsql_test_accept($server, int $delay = 0)
{
    $client = stream_socket_accept($server, 5);
    Assert::notEmpty($client);
    stream_set_timeout($client, 5);
    $length = unpack('N', pgsql_test_read_exact($client, 4))[1];
    Assert::notSame(pgsql_test_read_exact($client, $length - 4), false);
    if ($delay > 0) {
        usleep($delay);
    }
    $startup = pgsql_test_packet('R', pack('N', 0))
        . pgsql_test_packet('S', "server_version\00016.0\0")
        . pgsql_test_packet('S', "client_encoding\0UTF8\0")
        . pgsql_test_packet('K', pack('NN', 1234, 5678))
        . pgsql_test_packet('Z', 'I');
    Assert::same(fwrite($client, $startup), strlen($startup));
    return $client;
}

function pgsql_test_result(): string
{
    return pgsql_test_packet('T', pack('n', 1) . "value\0" . pack('NnNnNn', 0, 0, 23, 4, 0xFFFFFFFF, 0))
        . pgsql_test_packet('D', pack('nN', 1, 1) . '1')
        . pgsql_test_packet('C', "SELECT 1\0");
}

function pgsql_test_dsn(int $port): string
{
    return "pgsql:host=127.0.0.1;port={$port};dbname=test;sslmode=disable;gssencmode=disable";
}
