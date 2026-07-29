--TEST--
ssh2_exec() publishes nullable PTY and environment metadata
--SKIPIF--
<?php require_once 'ssh2_skip.inc'; ?>
--FILE--
<?php
$parameters  = (new ReflectionFunction('ssh2_exec'))->getParameters();
$pty         = $parameters[2];
$environment = $parameters[3];

printf("pty name: %s\n", $pty->getName());
printf("pty type: %s\n", (string) $pty->getType());
printf("pty allows null: %s\n", $pty->getType()->allowsNull() ? 'true' : 'false');
printf("pty default available: %s\n", $pty->isDefaultValueAvailable() ? 'true' : 'false');
printf("pty default is null: %s\n", $pty->getDefaultValue() === null ? 'true' : 'false');
printf("env name: %s\n", $environment->getName());
printf("env type: %s\n", (string) $environment->getType());
printf("env allows null: %s\n", $environment->getType()->allowsNull() ? 'true' : 'false');
printf("env default is null: %s\n", $environment->getDefaultValue() === null ? 'true' : 'false');
?>
--EXPECT--
pty name: pty
pty type: ?string
pty allows null: true
pty default available: true
pty default is null: true
env name: env
env type: ?array
env allows null: true
env default is null: true
