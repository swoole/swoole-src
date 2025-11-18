<?php
  require_once('ssh2_test.inc');

  if (!extension_loaded("ssh2")) print "skip extension not loaded";
  if (TEST_SSH2_HOSTNAME === false) print "skip TEST_SSH2_HOSTNAME not set";

function ssh2t_needs_auth() {
  if (TEST_SSH2_AUTH == 'none') {
    print "skip TEST_SSH2_AUTH == 'none'";
  }
}

function ssh2t_writes_remote() {
  if (!TEST_SSH2_TEMPDIR) {
    print "skip TEST_SSH2_TEMPDIR is empty";
  }
}
