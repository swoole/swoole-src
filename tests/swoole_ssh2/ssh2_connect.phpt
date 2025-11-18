--TEST--
ssh2_connect() Basic connection and pre-authentication
--SKIPIF--
<?php require_once('ssh2_skip.inc'); ?>
--FILE--
<?php require_once('ssh2_test.inc');

echo "**Connect\n";
$ssh = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
var_dump(is_resource($ssh));
var_dump(get_resource_type($ssh));

echo "**Fingerprint MD5\n";
$md5 = ssh2_fingerprint($ssh);
var_dump(is_string($md5));
var_dump(strlen($md5));
var_dump(ctype_xdigit($md5));

echo "**Fingerprint SHA1\n";
$sha1 = ssh2_fingerprint($ssh, SSH2_FINGERPRINT_SHA1 | SSH2_FINGERPRINT_HEX);
var_dump(is_string($sha1));
var_dump(strlen($sha1));
var_dump(ctype_xdigit($sha1));

function ssh2t_strset($v) {
  return is_string($v) && (strlen($v) > 0);
}

echo "**Negotiation\n";
$mn = ssh2_methods_negotiated($ssh);
var_dump(ssh2t_strset($mn['kex']));
var_dump(ssh2t_strset($mn['hostkey']));
foreach(array('client_to_server', 'server_to_client') as $direction) {
  $mnd = $mn[$direction];
  var_dump(ssh2t_strset($mnd['crypt']));
  var_dump(ssh2t_strset($mnd['comp']));
  var_dump(ssh2t_strset($mnd['mac']));
}
?>
--EXPECT--
**Connect
bool(true)
string(12) "SSH2 Session"
**Fingerprint MD5
bool(true)
int(32)
bool(true)
**Fingerprint SHA1
bool(true)
int(40)
bool(true)
**Negotiation
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)

