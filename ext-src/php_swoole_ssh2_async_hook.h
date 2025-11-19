#define SSH2_ASYNC_CALL(session, libssh2_func, ...)                                                                    \
    ssh2_async_call(session, [&](void) { return libssh2_func(__VA_ARGS__); })

#define SSH2_ASYNC_CALL_EX(T, session, libssh2_func, ...)                                                              \
    ssh2_async_call_ex<T>(session, [&](void) -> T * { return libssh2_func(__VA_ARGS__); })

#define libssh2_session_handshake(session, sockfd) SSH2_ASYNC_CALL(session, libssh2_session_handshake, session, sockfd)

#undef libssh2_session_disconnect
#define libssh2_session_disconnect(session, description)                                                               \
    SSH2_ASYNC_CALL(session, libssh2_session_disconnect_ex, (session), SSH_DISCONNECT_BY_APPLICATION, (description), "")

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

#undef libssh2_sftp_close
#define libssh2_sftp_close(handle) SSH2_ASYNC_CALL(session, libssh2_sftp_close_handle, handle)

#undef libssh2_sftp_unlink
#define libssh2_sftp_unlink(sftp, filename)                                                                            \
    SSH2_ASYNC_CALL(session, libssh2_sftp_unlink_ex, (sftp), (filename), strlen(filename))

#undef libssh2_sftp_rename
#define libssh2_sftp_rename(sftp, sourcefile, destfile)                                                                \
    SSH2_ASYNC_CALL(session,                                                                                           \
                    libssh2_sftp_rename_ex,                                                                            \
                    (sftp),                                                                                            \
                    (sourcefile),                                                                                      \
                    strlen(sourcefile),                                                                                \
                    (destfile),                                                                                        \
                    strlen(destfile),                                                                                  \
                    LIBSSH2_SFTP_RENAME_OVERWRITE | LIBSSH2_SFTP_RENAME_ATOMIC | LIBSSH2_SFTP_RENAME_NATIVE)

#undef libssh2_sftp_mkdir
#define libssh2_sftp_mkdir(sftp, path, mode)                                                                           \
    SSH2_ASYNC_CALL(session, libssh2_sftp_mkdir_ex, (sftp), (path), strlen(path), (mode))

#undef libssh2_sftp_rmdir
#define libssh2_sftp_rmdir(sftp, path) SSH2_ASYNC_CALL(session, libssh2_sftp_rmdir_ex, (sftp), (path), strlen(path))

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

#undef libssh2_userauth_publickey_fromfile
#define libssh2_userauth_publickey_fromfile(session, username, publickey, privatekey, passphrase)                      \
    SSH2_ASYNC_CALL(session,                                                                                           \
                    libssh2_userauth_publickey_fromfile_ex,                                                            \
                    (session),                                                                                         \
                    (username),                                                                                        \
                    (unsigned int) strlen(username),                                                                   \
                    (publickey),                                                                                       \
                    (privatekey),                                                                                      \
                    (passphrase))

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
