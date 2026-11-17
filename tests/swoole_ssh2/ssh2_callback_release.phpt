--TEST--
SSH2 session teardown releases callback state
--SKIPIF--
<?php
require_once 'ssh2_skip.inc';
ssh2t_needs_auth();
?>
--INI--
report_memleaks=1
--FILE--
<?php
require __DIR__ . '/ssh2_test.inc';

Co\run(function (): void {
    $callback = static function (): void {};
    $callbacks = [
        'ignore' => $callback,
        'debug' => $callback,
        'macerror' => $callback,
        'disconnect' => $callback,
    ];

    $release = static function () use ($callbacks): void {
        $session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT, null, $callbacks);
        if ($session === false || !ssh2t_auth($session)) {
            throw new RuntimeException('Failed to connect to the SSH fixture.');
        }
        ssh2_disconnect($session);
        unset($session);
    };

    $release();
    gc_collect_cycles();
    $baseline = memory_get_usage();

    for ($i = 0; $i < 20; $i++) {
        $release();
    }

    gc_collect_cycles();
    var_dump(memory_get_usage() - $baseline < 512);

    $server = new Co\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (!$server->bind('127.0.0.1', 0) || !$server->listen()) {
        throw new RuntimeException('Failed to create the invalid SSH fixture.');
    }

    $address = $server->getsockname();
    if (!isset($address['port'])) {
        throw new RuntimeException('Failed to resolve the invalid SSH fixture port.');
    }

    go(static function () use ($server): void {
        $client = $server->accept();
        if ($client === false) {
            throw new RuntimeException('Failed to accept the invalid SSH connection.');
        }
        $banner = "not an SSH server\r\n";
        if ($client->sendAll($banner) !== strlen($banner)) {
            throw new RuntimeException('Failed to write the invalid SSH banner.');
        }
        $client->close();
        $server->close();
    });

    $failedCallback = static function (): void {};
    $callbackReference = WeakReference::create($failedCallback);
    $failedCallbacks = ['disconnect' => $failedCallback];
    unset($failedCallback);

    $session = @ssh2_connect('127.0.0.1', $address['port'], null, $failedCallbacks);
    var_dump($session === false);

    unset($failedCallbacks, $session);
    gc_collect_cycles();
    var_dump($callbackReference->get() === null);
});
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
