<?php
/**
 * This file is part of Swoole.
 *
 * @link     https://www.swoole.com
 * @contact  team@swoole.com
 * @license  https://github.com/swoole/library/blob/master/LICENSE
 */

/**
 * Connect to an SSH server
 * @param string $host The hostname or IP address to connect to
 * @param int $port [optional] The port number to connect on
 * @param array $methods [optional] Methods to use for the connection
 * @param array $callbacks [optional] Callbacks for the connection
 * @return resource|false Returns an SSH session resource on success, or false on failure
 */
function ssh2_connect(string $host, int $port = 22, ?array $methods = null, ?array $callbacks = null) {}

/**
 * Disconnect from an SSH server
 * @param resource $session The SSH session to disconnect from
 * @return bool Returns true on success or false on failure
 */
function ssh2_disconnect($session): bool {}

/**
 * Return list of negotiated methods
 * @param resource $session The SSH session to list methods for
 * @return array Returns an associative array of negotiated methods
 */
function ssh2_methods_negotiated($session): array {}

/**
 * Retrieve fingerprint of remote server
 * @param resource $session The SSH session
 * @param int $flags [optional] Flags for the fingerprint
 * @return string Returns the fingerprint as a string on success, or false on failure
 */
function ssh2_fingerprint($session, int $flags = 0) {}

/**
 * Authenticate as "none"
 * @param resource $session The SSH session
 * @param string $username The username to authenticate as
 * @return bool Returns true on success or false on failure
 */
function ssh2_auth_none($session, string $username): bool {}

/**
 * Authenticate over SSH using a password
 * @param resource $session The SSH session
 * @param string $username The username to authenticate as
 * @param string $password The password to use for authentication
 * @return bool Returns true on success or false on failure
 */
function ssh2_auth_password($session, string $username, string $password): bool {}

/**
 * Authenticate using a public key
 * @param resource $session The SSH session
 * @param string $username The username to authenticate as
 * @param string $pubkeyfile The path to the public key file
 * @param string $privkeyfile The path to the private key file
 * @param string $passphrase [optional] The passphrase for the private key
 * @return bool Returns true on success or false on failure
 */
function ssh2_auth_pubkey_file($session, string $username, string $pubkeyfile, string $privkeyfile, ?string $passphrase = null): bool {}

/**
 * Authenticate using a public key
 * @param resource $session The SSH session
 * @param string $username The username to authenticate as
 * @param string $pubkey The public key
 * @param string $privkey The private key
 * @param string $passphrase [optional] The passphrase for the private key
 * @return bool Returns true on success or false on failure
 */
function ssh2_auth_pubkey($session, string $username, string $pubkey, string $privkey, ?string $passphrase = null): bool {}

/**
 * Authenticate using a public hostkey
 * @param resource $session The SSH session
 * @param string $username The username to authenticate as
 * @param string $hostname The hostname
 * @param string $pubkeyfile The path to the public key file
 * @param string $privkeyfile The path to the private key file
 * @param string $passphrase [optional] The passphrase for the private key
 * @param string $local_username [optional] The local username
 * @return bool Returns true on success or false on failure
 */
function ssh2_auth_hostbased_file($session, string $username, string $hostname, string $pubkeyfile, string $privkeyfile, ?string $passphrase = null, ?string $local_username = null): bool {}

/**
 * Request SSH port forwarding
 * @param resource $session The SSH session
 * @param int $port The port to listen on
 * @param string $host [optional] The host to forward to
 * @param int $max_connections [optional] The maximum number of connections
 * @return resource|false Returns a listener resource on success, or false on failure
 */
function ssh2_forward_listen($session, int $port, string $host = '127.0.0.1', int $max_connections = 1): resource|false {}

/**
 * Accept a connection created by ssh2_forward_listen
 */
function ssh2_forward_accept(resource $listener, ?string &$host = null, ?int &$port = null): resource|false {}

/**
 * Request an interactive shell
 * @param resource $session The SSH session
 * @param string $termtype [optional] The terminal type
 * @param array $env [optional] Environment variables
 * @param int $width [optional] Width of the terminal
 * @param int $height [optional] Height of the terminal
 * @param int $width_height_type [optional] Type of width/height measurement
 * @return resource|false Returns a stream resource on success, or false on failure
 */
function ssh2_shell($session, string $termtype = 'vanilla', ?array $env = null, int $width = 80, int $height = 25, int $width_height_type = 0) {}

/**
 * Resize an interactive shell
 * @param resource $session The SSH session
 * @param int $width The new width
 * @param int $height The new height
 * @return bool Returns true on success or false on failure
 */
function ssh2_shell_resize($session, int $width, int $height): bool {}

/**
 * Execute a command on a remote server
 * @param resource $session The SSH session
 * @param string $command The command to execute
 * @param bool $pty [optional] Whether to allocate a pseudo-terminal
 * @param array $env [optional] Environment variables
 * @param int $width [optional] Width of the terminal
 * @param int $height [optional] Height of the terminal
 * @param int $width_height_type [optional] Type of width/height measurement
 * @return resource|false Returns a stream resource on success, or false on failure
 */
function ssh2_exec($session, string $command, bool $pty = false, ?array $env = null, int $width = 80, int $height = 25, int $width_height_type = 0) {}

/**
 * Open a tunnel through a remote server
 * @param resource $session The SSH session
 * @param string $host The host to connect to
 * @param int $port The port to connect to
 * @return resource|false Returns a stream resource on success, or false on failure
 */
function ssh2_tunnel($session, string $host, int $port) {}

/**
 * Request a file via SCP
 * @param resource $session The SSH session
 * @param string $remote_file The remote file path
 * @param string $local_file The local file path
 * @return bool Returns true on success or false on failure
 */
function ssh2_scp_recv($session, string $remote_file, string $local_file): bool {}

/**
 * Send a file via SCP
 * @param resource $session The SSH session
 * @param string $local_file The local file path
 * @param string $remote_file The remote file path
 * @param int $create_mode [optional] The file creation mode
 * @return bool Returns true on success or false on failure
 */
function ssh2_scp_send($session, string $local_file, string $remote_file, int $create_mode = 0644): bool {}

/**
 * Fetch an extended data stream
 * @param resource $channel The channel resource
 * @param int $streamid The stream ID
 * @return resource|false Returns a stream resource on success, or false on failure
 */
function ssh2_fetch_stream($channel, int $streamid) {}

/**
 * Send EOF to a channel
 * @param resource $channel The channel resource
 * @return bool Returns true on success or false on failure
 */
function ssh2_send_eof($channel): bool {}

/**
 * Initialize SFTP subsystem
 * @param resource $session The SSH session
 * @return resource|false Returns an SSH2 SFTP resource on success, or false on failure
 */
function ssh2_sftp($session) {}

/**
 * Rename a remote file
 * @param resource $sftp The SSH2 SFTP resource
 * @param string $from The source file path
 * @param string $to The destination file path
 * @return bool Returns true on success or false on failure
 */
function ssh2_sftp_rename($sftp, string $from, string $to): bool {}

/**
 * Delete a file
 * @param resource $sftp The SSH2 SFTP resource
 * @param string $filename The file path to delete
 * @return bool Returns true on success or false on failure
 */
function ssh2_sftp_unlink($sftp, string $filename): bool {}

/**
 * Create a directory
 * @param resource $sftp The SSH2 SFTP resource
 * @param string $dirname The directory path to create
 * @param int $mode [optional] The directory permissions
 * @param bool $recursive [optional] Whether to create directories recursively
 * @return bool Returns true on success or false on failure
 */
function ssh2_sftp_mkdir($sftp, string $dirname, int $mode = 0777, bool $recursive = false): bool {}

/**
 * Remove a directory
 * @param resource $sftp The SSH2 SFTP resource
 * @param string $dirname The directory path to remove
 * @return bool Returns true on success or false on failure
 */
function ssh2_sftp_rmdir($sftp, string $dirname): bool {}

/**
 * Changes file mode
 * @param resource $sftp The SSH2 SFTP resource
 * @param string $filename The file path
 * @param int $mode The new file mode
 * @return bool Returns true on success or false on failure
 */
function ssh2_sftp_chmod($sftp, string $filename, int $mode): bool {}

/**
 * Stat a file on a remote filesystem
 * @param resource $sftp The SSH2 SFTP resource
 * @param string $path The file path to stat
 * @return array|false Returns an array of file stats on success, or false on failure
 */
function ssh2_sftp_stat($sftp, string $path) {}

/**
 * Stat a symbolic link on the remote filesystem
 * @param resource $sftp The SSH2 SFTP resource
 * @param string $path The link path to stat
 * @return array|false Returns an array of file stats on success, or false on failure
 */
function ssh2_sftp_lstat($sftp, string $path) {}

/**
 * Create a symlink
 * @param resource $sftp The SSH2 SFTP resource
 * @param string $target The target path
 * @param string $link The link path
 * @return bool Returns true on success or false on failure
 */
function ssh2_sftp_symlink($sftp, string $target, string $link): bool {}

/**
 * Read the target of a symlink
 * @param resource $sftp The SSH2 SFTP resource
 * @param string $link The link path
 * @return string|false Returns the target path on success, or false on failure
 */
function ssh2_sftp_readlink($sftp, string $link) {}

/**
 * Resolve the realpath of a filename
 * @param resource $sftp The SSH2 SFTP resource
 * @param string $filename The filename to resolve
 * @return string|false Returns the real path on success, or false on failure
 */
function ssh2_sftp_realpath($sftp, string $filename) {}

/**
 * Initialize Publickey subsystem
 * @param resource $session The SSH session
 * @return resource|false Returns an SSH2 Publickey resource on success, or false on failure
 */
function ssh2_publickey_init($session) {}

/**
 * Add an authorized publickey
 * @param resource $pkey The SSH2 Publickey resource
 * @param string $algoname The algorithm name
 * @param string $blob The public key blob
 * @param bool $overwrite [optional] Whether to overwrite existing key
 * @param array $attributes [optional] Attributes for the key
 * @return bool Returns true on success or false on failure
 */
function ssh2_publickey_add($pkey, string $algoname, string $blob, bool $overwrite = false, ?array $attributes = null): bool {}

/**
 * Remove an authorized publickey
 * @param resource $pkey The SSH2 Publickey resource
 * @param string $algoname The algorithm name
 * @param string $blob The public key blob
 * @return bool Returns true on success or false on failure
 */
function ssh2_publickey_remove($pkey, string $algoname, string $blob): bool {}

/**
 * List currently authorized publickeys
 * @param resource $pkey The SSH2 Publickey resource
 * @return array|false Returns an array of public keys on success, or false on failure
 */
function ssh2_publickey_list($pkey) {}

/**
 * Authenticate using ssh-agent
 * @param resource $session The SSH session
 * @param string $username The username to authenticate as
 * @return bool Returns true on success or false on failure
 */
function ssh2_auth_agent($session, string $username): bool {}
