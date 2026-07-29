--TEST--
SSH2 authentication parameters publish sensitive metadata and redact traces
--SKIPIF--
<?php
if (!function_exists('ssh2_auth_password')) {
    echo 'skip SSH2 support is not enabled';
}
?>
--INI--
zend.exception_ignore_args=0
--FILE--
<?php
$sensitiveParameters = [
    ['ssh2_auth_password', 'password'],
    ['ssh2_auth_pubkey_file', 'passphrase'],
    ['ssh2_auth_pubkey', 'privkey'],
    ['ssh2_auth_pubkey', 'passphrase'],
    ['ssh2_auth_hostbased_file', 'passphrase'],
];

foreach ($sensitiveParameters as [$function, $parameter]) {
    $reflectionParameter = new ReflectionParameter($function, $parameter);

    printf(
        "%s:%s sensitive: %s\n",
        $function,
        $parameter,
        count($reflectionParameter->getAttributes(SensitiveParameter::class)) === 1 ? 'true' : 'false',
    );
}

$ordinaryParameters = [
    ['ssh2_auth_password', 'username'],
    ['ssh2_auth_pubkey', 'pubkey'],
    ['ssh2_auth_hostbased_file', 'privkeyfile'],
];

foreach ($ordinaryParameters as [$function, $parameter]) {
    $reflectionParameter = new ReflectionParameter($function, $parameter);

    printf(
        "%s:%s sensitive: %s\n",
        $function,
        $parameter,
        $reflectionParameter->getAttributes(SensitiveParameter::class) === [] ? 'false' : 'true',
    );
}

try {
    ssh2_auth_password(null, 'trace-user', 'trace-secret');
} catch (Throwable $exception) {
    $arguments    = $exception->getTrace()[0]['args'];
    $printedTrace = print_r($exception->getTrace(), true);

    printf("trace username: %s\n", $arguments[1]);
    printf("trace password wrapped: %s\n", $arguments[2] instanceof SensitiveParameterValue ? 'true' : 'false');
    printf("trace contains secret: %s\n", str_contains($printedTrace, 'trace-secret') ? 'true' : 'false');
}
?>
--EXPECT--
ssh2_auth_password:password sensitive: true
ssh2_auth_pubkey_file:passphrase sensitive: true
ssh2_auth_pubkey:privkey sensitive: true
ssh2_auth_pubkey:passphrase sensitive: true
ssh2_auth_hostbased_file:passphrase sensitive: true
ssh2_auth_password:username sensitive: false
ssh2_auth_pubkey:pubkey sensitive: false
ssh2_auth_hostbased_file:privkeyfile sensitive: false
trace username: trace-user
trace password wrapped: true
trace contains secret: false
