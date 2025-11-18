<?php

function ssh2t_getenv($env, $def=false) {
  $v = getenv($env);
  return ($v === false) ? $def : $v;
}

function ssh2t_defenv($env, $def=false, $name=null) {
  define(($name === null) ? $env : $name, ssh2t_getenv($env, $def));
}

ssh2t_defenv('TEST_SSH2_HOSTNAME');
ssh2t_defenv('TEST_SSH2_PORT', 22);
ssh2t_defenv('TEST_SSH2_USER');
ssh2t_defenv('TEST_SSH2_PASS');
ssh2t_defenv('TEST_SSH2_TEMPDIR', '/tmp');
ssh2t_defenv('TEST_SSH2_AUTH', TEST_SSH2_PASS ? 'password' : 'none');
ssh2t_defenv('TEST_SSH2_PUB_KEY', dirname(__FILE__) . "/testkey_rsa.pub");
ssh2t_defenv('TEST_SSH2_PRIV_KEY', dirname(__FILE__) . "/testkey_rsa");

function ssh2t_auth($ssh) {
  if (!TEST_SSH2_USER) {
    return false;
  }

  switch (TEST_SSH2_AUTH) {
    case 'none':     return (ssh2_auth_none($ssh, TEST_SSH2_USER) === true) ? true : false;
    case 'agent':    return ssh2_auth_agent($ssh, TEST_SSH2_USER);
    case 'password': return ssh2_auth_password($ssh, TEST_SSH2_USER, TEST_SSH2_PASS);
  }

  return false;
}

function ssh2t_tempnam($escape = false) {
  $fn = TEST_SSH2_TEMPDIR . '/php-ssh2-test-' . uniqid();
  return $escape ? escapeshellarg($fn) : $fn;
}
