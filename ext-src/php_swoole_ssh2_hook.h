#define SSH2_ASYNC_CALL(session, libssh2_func, ...)                                                                    \
    ssh2_async_call(session, [&](void) { return libssh2_func(__VA_ARGS__); })

#define SSH2_ASYNC_CALL_EX(T, session, libssh2_func, ...)                                                              \
    ssh2_async_call_ex<T>(session, [&](void) -> T * { return libssh2_func(__VA_ARGS__); })

#define libssh2_session_handshake(session, sockfd) SSH2_ASYNC_CALL(session, libssh2_session_handshake, session, sockfd)

#undef libssh2_session_disconnect
#define libssh2_session_disconnect(session, description)                                                               \
    SSH2_ASYNC_CALL(session, libssh2_session_disconnect_ex, (session), SSH_DISCONNECT_BY_APPLICATION, (description), "")

#undef libssh2_channel_open_session
#define libssh2_channel_open_session(session)                                                                          \
    SSH2_ASYNC_CALL_EX(LIBSSH2_CHANNEL,                                                                                \
                       session,                                                                                        \
                       libssh2_channel_open_ex,                                                                        \
                       (session),                                                                                      \
                       "session",                                                                                      \
                       sizeof("session") - 1,                                                                          \
                       LIBSSH2_CHANNEL_WINDOW_DEFAULT,                                                                 \
                       LIBSSH2_CHANNEL_PACKET_DEFAULT,                                                                 \
                       NULL,                                                                                           \
                       0)

#define libssh2_channel_setenv_ex(channel, name, name_len, value, value_len)                                           \
    SSH2_ASYNC_CALL(session, libssh2_channel_setenv_ex, channel, name, name_len, value, value_len)

#define libssh2_channel_request_pty_ex(channel, term, term_len, modes, modes_len, width, height, width_px, height_px)  \
    SSH2_ASYNC_CALL(session,                                                                                           \
                    libssh2_channel_request_pty_ex,                                                                    \
                    channel,                                                                                           \
                    term,                                                                                              \
                    term_len,                                                                                          \
                    modes,                                                                                             \
                    modes_len,                                                                                         \
                    width,                                                                                             \
                    height,                                                                                            \
                    width_px,                                                                                          \
                    height_px)

#undef libssh2_channel_shell
#define libssh2_channel_shell(channel)                                                                                 \
    SSH2_ASYNC_CALL(session, libssh2_channel_process_startup, channel, "shell", sizeof("shell") - 1, NULL, 0)

#undef libssh2_channel_exec
#define libssh2_channel_exec(channel, command)                                                                         \
    SSH2_ASYNC_CALL(session,                                                                                           \
                    libssh2_channel_process_startup,                                                                   \
                    channel,                                                                                           \
                    "exec",                                                                                            \
                    sizeof("exec") - 1,                                                                                \
                    (command),                                                                                         \
                    (unsigned int) strlen(command))

#define libssh2_channel_flush_ex(channel, streamid)                                                                    \
    SSH2_ASYNC_CALL(session, libssh2_channel_flush_ex, (channel), (streamid))

#define libssh2_channel_read_ex(channel, streamid, buf, len)                                                           \
    SSH2_ASYNC_CALL(session, libssh2_channel_read_ex, channel, streamid, buf, len)

#undef libssh2_channel_write_ex
#define libssh2_channel_write_ex(channel, streamid, buf, len)                                                          \
    SSH2_ASYNC_CALL(session, libssh2_channel_write_ex, channel, streamid, buf, len)

#undef libssh2_channel_read
#define libssh2_channel_read(channel, buf, buflen) libssh2_channel_read_ex((channel), 0, (buf), (buflen))

#undef libssh2_channel_write
#define libssh2_channel_write(channel, buf, buflen) libssh2_channel_write_ex((channel), 0, (buf), (buflen))

#undef libssh2_channel_eof
#define libssh2_channel_eof(channel) SSH2_ASYNC_CALL(session, libssh2_channel_eof, channel)

#undef libssh2_channel_close
#define libssh2_channel_close(channel) SSH2_ASYNC_CALL(session, libssh2_channel_close, channel)

#undef libssh2_channel_send_eof
#define libssh2_channel_send_eof(channel) SSH2_ASYNC_CALL(session, libssh2_channel_send_eof, channel)

#undef libssh2_channel_get_exit_status
#define libssh2_channel_get_exit_status(channel) SSH2_ASYNC_CALL(session, libssh2_channel_get_exit_status, channel)

#undef libssh2_channel_request_pty_size_ex
#define libssh2_channel_request_pty_size_ex(channel, width, height, width_px, height_px)                               \
    SSH2_ASYNC_CALL(session, libssh2_channel_request_pty_size_ex, channel, width, height, width_px, height_px)

#undef libssh2_channel_forward_listen_ex
#define libssh2_channel_forward_listen_ex(session, host, port, addr, num_connections)                                  \
    SSH2_ASYNC_CALL_EX(                                                                                                \
        LIBSSH2_LISTENER, session, libssh2_channel_forward_listen_ex, session, host, port, addr, num_connections)

#undef libssh2_channel_forward_accept
#define libssh2_channel_forward_accept(listener)                                                                       \
    SSH2_ASYNC_CALL_EX(LIBSSH2_CHANNEL, session, libssh2_channel_forward_accept, listener)

#undef libssh2_channel_forward_cancel
#define libssh2_channel_forward_cancel(listener) SSH2_ASYNC_CALL(session, libssh2_channel_forward_cancel, listener)

#undef libssh2_channel_direct_tcpip
#define libssh2_channel_direct_tcpip(session, host, port)                                                              \
    SSH2_ASYNC_CALL_EX(                                                                                                \
        LIBSSH2_CHANNEL, session, libssh2_channel_direct_tcpip_ex, (session), (host), (port), "127.0.0.1", 22)

#undef libssh2_sftp_fstat
#define libssh2_sftp_fstat(handle, attrs) SSH2_ASYNC_CALL(session, libssh2_sftp_fstat_ex, handle, attrs, 0)

#define libssh2_sftp_stat_ex(sftp, path, path_len, stat_type, attrs)                                                   \
    SSH2_ASYNC_CALL(session, libssh2_sftp_stat_ex, sftp, path, path_len, stat_type, attrs)

#define libssh2_sftp_symlink_ex(sftp, path, path_len, target, target_len, link_type)                                   \
    SSH2_ASYNC_CALL(session, libssh2_sftp_symlink_ex, sftp, path, path_len, target, target_len, link_type)

#undef libssh2_sftp_open
#define libssh2_sftp_open(sftp, filename, flags, mode)                                                                 \
    SSH2_ASYNC_CALL_EX(LIBSSH2_SFTP_HANDLE,                                                                            \
                       session,                                                                                        \
                       libssh2_sftp_open_ex,                                                                           \
                       (sftp),                                                                                         \
                       (filename),                                                                                     \
                       strlen(filename),                                                                               \
                       (flags),                                                                                        \
                       (mode),                                                                                         \
                       LIBSSH2_SFTP_OPENFILE)

#undef libssh2_sftp_opendir
#define libssh2_sftp_opendir(sftp, path)                                                                               \
    SSH2_ASYNC_CALL_EX(                                                                                                \
        LIBSSH2_SFTP_HANDLE, session, libssh2_sftp_open_ex, (sftp), (path), strlen(path), 0, 0, LIBSSH2_SFTP_OPENDIR)

#undef libssh2_sftp_readdir
#define libssh2_sftp_readdir(handle, buffer, buffer_maxlen, attrs)                                                     \
    SSH2_ASYNC_CALL(session, libssh2_sftp_readdir_ex, (handle), (buffer), (buffer_maxlen), NULL, 0, (attrs))

#undef libssh2_sftp_tell
#define libssh2_sftp_tell(handle) SSH2_ASYNC_CALL(session, libssh2_sftp_tell, handle)

#undef libssh2_sftp_read
#define libssh2_sftp_read(handle, buffer, count)                                                                       \
    SSH2_ASYNC_CALL(session, libssh2_sftp_read, (handle), (buffer), (count))

#undef libssh2_sftp_write
#define libssh2_sftp_write(handle, buffer, count)                                                                      \
    SSH2_ASYNC_CALL(session, libssh2_sftp_write, (handle), (buffer), (count))

#define libssh2_sftp_init(session) SSH2_ASYNC_CALL_EX(LIBSSH2_SFTP, session, libssh2_sftp_init, session)

#undef libssh2_scp_recv
#define libssh2_scp_recv(session, path, stat)                                                                          \
    SSH2_ASYNC_CALL_EX(LIBSSH2_CHANNEL, session, libssh2_scp_recv, session, path, stat)

#undef libssh2_scp_send_ex
#define libssh2_scp_send_ex(session, path, mode, size, atime, mtime)                                                   \
    SSH2_ASYNC_CALL_EX(LIBSSH2_CHANNEL, session, libssh2_scp_send_ex, session, path, mode, size, atime, mtime)

#undef libssh2_sftp_close
#define libssh2_sftp_close(handle) SSH2_ASYNC_CALL(session, libssh2_sftp_close_handle, handle)

#define libssh2_sftp_unlink_ex(sftp, filename, filename_len)                                                           \
    SSH2_ASYNC_CALL(session, libssh2_sftp_unlink_ex, (sftp), (filename), filename_len)

#undef libssh2_sftp_unlink
#define libssh2_sftp_unlink(sftp, filename) libssh2_sftp_unlink_ex((sftp), (filename), strlen(filename))

#define libssh2_sftp_rename_ex(sftp, source_filename, srouce_filename_len, dest_filename, dest_filename_len, flags)    \
    SSH2_ASYNC_CALL(session,                                                                                           \
                    libssh2_sftp_rename_ex,                                                                            \
                    sftp,                                                                                              \
                    source_filename,                                                                                   \
                    srouce_filename_len,                                                                               \
                    dest_filename,                                                                                     \
                    dest_filename_len,                                                                                 \
                    flags)

#undef libssh2_sftp_rename
#define libssh2_sftp_rename(sftp, sourcefile, destfile)                                                                \
    libssh2_sftp_rename_ex((sftp),                                                                                     \
                           (sourcefile),                                                                               \
                           strlen(sourcefile),                                                                         \
                           (destfile),                                                                                 \
                           strlen(destfile),                                                                           \
                           LIBSSH2_SFTP_RENAME_OVERWRITE | LIBSSH2_SFTP_RENAME_ATOMIC | LIBSSH2_SFTP_RENAME_NATIVE)

#define libssh2_sftp_mkdir_ex(sftp, path, path_len, mode)                                                              \
    SSH2_ASYNC_CALL(session, libssh2_sftp_mkdir_ex, (sftp), (path), path_len, (mode))

#undef libssh2_sftp_mkdir
#define libssh2_sftp_mkdir(sftp, path, mode) libssh2_sftp_mkdir_ex((sftp), (path), strlen(path), (mode))

#define libssh2_sftp_rmdir_ex(sftp, path, path_len)                                                                    \
    SSH2_ASYNC_CALL(session, libssh2_sftp_rmdir_ex, (sftp), (path), path_len)

#undef libssh2_sftp_rmdir
#define libssh2_sftp_rmdir(sftp, path) libssh2_sftp_rmdir_ex((sftp), (path), strlen(path))

/* Agent related functions */
#undef libssh2_agent_connect
#define libssh2_agent_connect(agent) SSH2_ASYNC_CALL(session, libssh2_agent_connect, agent)

#undef libssh2_agent_list_identities
#define libssh2_agent_list_identities(agent) SSH2_ASYNC_CALL(session, libssh2_agent_list_identities, agent)

#undef libssh2_agent_get_identity
#define libssh2_agent_get_identity(agent, identity, prev_identity)                                                     \
    SSH2_ASYNC_CALL(session, libssh2_agent_get_identity, agent, identity, prev_identity)

#undef libssh2_agent_userauth
#define libssh2_agent_userauth(agent, username, identity)                                                              \
    SSH2_ASYNC_CALL(session, libssh2_agent_userauth, agent, username, identity)

#undef libssh2_agent_disconnect
#define libssh2_agent_disconnect(agent) SSH2_ASYNC_CALL(session, libssh2_agent_disconnect, agent)

/* libssh2_agent_free is just memory operation, no network IO, so don't async it */

/* User authentication functions */
#undef libssh2_userauth_list
#define libssh2_userauth_list(session, username, username_len)                                                         \
    SSH2_ASYNC_CALL_EX(char, session, libssh2_userauth_list, session, username, username_len)

#undef libssh2_userauth_password_ex
#define libssh2_userauth_password_ex(session, username, username_len, password, password_len, change_cb)               \
    SSH2_ASYNC_CALL(                                                                                                   \
        session, libssh2_userauth_password_ex, session, username, username_len, password, password_len, change_cb)

#undef libssh2_userauth_publickey_fromfile_ex
#define libssh2_userauth_publickey_fromfile_ex(session, username, username_len, publickey, privatekey, passphrase)     \
    SSH2_ASYNC_CALL(session,                                                                                           \
                    libssh2_userauth_publickey_fromfile_ex,                                                            \
                    (session),                                                                                         \
                    (username),                                                                                        \
                    (username_len),                                                                                    \
                    (publickey),                                                                                       \
                    (privatekey),                                                                                      \
                    (passphrase))

#undef libssh2_userauth_publickey_fromfile
#define libssh2_userauth_publickey_fromfile(session, username, publickey, privatekey, passphrase)                      \
    libssh2_userauth_publickey_fromfile_ex(                                                                            \
        (session), (username), (unsigned int) strlen(username), (publickey), (privatekey), (passphrase))

#undef libssh2_userauth_publickey_frommemory
#define libssh2_userauth_publickey_frommemory(                                                                         \
    session, username, username_len, pubkeydata, pubkeydata_len, privkeydata, privkeydata_len, passphrase)             \
    SSH2_ASYNC_CALL(session,                                                                                           \
                    libssh2_userauth_publickey_frommemory,                                                             \
                    session,                                                                                           \
                    username,                                                                                          \
                    username_len,                                                                                      \
                    pubkeydata,                                                                                        \
                    pubkeydata_len,                                                                                    \
                    privkeydata,                                                                                       \
                    privkeydata_len,                                                                                   \
                    passphrase)

#undef libssh2_userauth_hostbased_fromfile_ex
#define libssh2_userauth_hostbased_fromfile_ex(session,                                                                \
                                               username,                                                               \
                                               username_len,                                                           \
                                               pubkeyfile,                                                             \
                                               privkeyfile,                                                            \
                                               passphrase,                                                             \
                                               hostname,                                                               \
                                               hostname_len,                                                           \
                                               local_username,                                                         \
                                               local_username_len)                                                     \
    SSH2_ASYNC_CALL(session,                                                                                           \
                    libssh2_userauth_hostbased_fromfile_ex,                                                            \
                    session,                                                                                           \
                    username,                                                                                          \
                    username_len,                                                                                      \
                    pubkeyfile,                                                                                        \
                    privkeyfile,                                                                                       \
                    passphrase,                                                                                        \
                    hostname,                                                                                          \
                    hostname_len,                                                                                      \
                    local_username,                                                                                    \
                    local_username_len)

#undef libssh2_userauth_keyboard_interactive
#define libssh2_userauth_keyboard_interactive(session, username, response_callback)                                    \
    SSH2_ASYNC_CALL(session,                                                                                           \
                    libssh2_userauth_keyboard_interactive_ex,                                                          \
                    (session),                                                                                         \
                    (username),                                                                                        \
                    (unsigned int) strlen(username),                                                                   \
                    (response_callback))

#undef libssh2_userauth_authenticated
#define libssh2_userauth_authenticated(session) SSH2_ASYNC_CALL(session, libssh2_userauth_authenticated, session)