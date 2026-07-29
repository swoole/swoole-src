--TEST--
Raw host-key metadata and SHA-256 fingerprints describe the same server key
--SKIPIF--
<?php require_once 'ssh2_skip.inc'; ?>
--FILE--
<?php
require_once 'ssh2_test.inc';

Co\run(function () {
    $ssh         = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
    $hostKey     = ssh2_hostkey($ssh);
    $fingerprint = ssh2_fingerprint($ssh, SSH2_FINGERPRINT_SHA256 | SSH2_FINGERPRINT_RAW);

    var_dump(is_array($hostKey));
    var_dump(is_string($hostKey['key']));
    var_dump($hostKey['key'] !== '');
    var_dump(is_int($hostKey['type']));
    var_dump($hostKey['type'] !== SSH2_HOSTKEY_TYPE_UNKNOWN);
    var_dump(strlen($fingerprint));
    var_dump($fingerprint === hash('sha256', $hostKey['key'], true));

    ssh2_disconnect($ssh);
});
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
int(32)
bool(true)
