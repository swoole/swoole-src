--TEST--
swoole_pdo_pgsql: other coroutines run while a query waits for the end of its reply
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_pgsql.inc';

const HOLD = 1.0;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $pdo = new PDO('pgsql:host=127.0.0.1;port=' . $pm->getFreePort() . ';dbname=' . PGSQL_DBNAME . ';sslmode=disable;gssencmode=disable', PGSQL_USER, PGSQL_PASSWORD);
        $gap = 0;
        $last = microtime(true);
        $stop = false;
        go(function () use (&$gap, &$last, &$stop) {
            while (!$stop) {
                Co::sleep(0.01);
                $now = microtime(true);
                $gap = max($gap, $now - $last);
                $last = $now;
            }
        });
        Assert::eq($pdo->query('SELECT 1')->fetchColumn(), 1);
        $stop = true;
        Assert::lessThan($gap, HOLD / 2);
    });
    $pm->kill();
    echo "Done\n";
};

// a relay that holds every ReadyForQuery after the start-up for HOLD seconds
$pm->childFunc = function () use ($pm) {
    $listen = stream_socket_server('tcp://127.0.0.1:' . $pm->getFreePort());
    $pm->wakeup();
    $client = stream_socket_accept($listen, 10);
    $server = stream_socket_client('tcp://' . PGSQL_HOST . ':' . PGSQL_PORT);
    $buffer = '';
    $queue = [];
    $started = false;
    while (true) {
        $read = [$client, $server];
        $write = $except = null;
        stream_select($read, $write, $except, 0, 10000);
        foreach ($read as $socket) {
            $data = fread($socket, 65536);
            if ($data === '' || $data === false) {
                return;
            }
            if ($socket === $client) {
                fwrite($server, $data);
                continue;
            }
            $buffer .= $data;
            while (strlen($buffer) >= 5 && strlen($buffer) >= 1 + unpack('N', substr($buffer, 1, 4))[1]) {
                $length = 1 + unpack('N', substr($buffer, 1, 4))[1];
                $at = $buffer[0] === 'Z' && $started ? microtime(true) + HOLD : 0;
                $started = $started || $buffer[0] === 'Z';
                $queue[] = [$at, substr($buffer, 0, $length)];
                $buffer = substr($buffer, $length);
            }
        }
        while ($queue && $queue[0][0] <= microtime(true)) {
            fwrite($client, array_shift($queue)[1]);
        }
    }
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
Done
