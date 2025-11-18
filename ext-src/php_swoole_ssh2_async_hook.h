#define SSH2_ASYNC_CALL(session, libssh2_func, ...) \
    ssh2_async_call(session, [&](swoole::coroutine::Socket *sock, LIBSSH2_SESSION *s) { \
        return libssh2_func(__VA_ARGS__); \
    })

#define libssh2_channel_setenv_ex(channel, name, name_len, value, value_len) \
    SSH2_ASYNC_CALL(session, libssh2_channel_setenv_ex, channel, name, name_len, value, value_len)

#define libssh2_channel_request_pty_ex(channel, term, term_len, modes, modes_len, width, height, width_px, height_px) \
    SSH2_ASYNC_CALL(session, libssh2_channel_request_pty_ex, channel, term, term_len, modes, modes_len, width, height, width_px, height_px)

#undef libssh2_channel_shell
#define libssh2_channel_shell(channel) \
    SSH2_ASYNC_CALL(session, libssh2_channel_process_startup, channel, "shell", sizeof("shell") - 1, NULL, 0)

#undef libssh2_channel_exec
#define libssh2_channel_exec(channel, command) \
    SSH2_ASYNC_CALL(session, libssh2_channel_process_startup, channel, "exec", sizeof("exec") - 1,   (command), (unsigned int)strlen(command))

#define libssh2_channel_flush_ex(channel, streamid) \
	SSH2_ASYNC_CALL(session, libssh2_channel_flush_ex, (channel), (streamid))

#undef libssh2_sftp_fstat
#define libssh2_sftp_fstat(handle, attrs) \
    SSH2_ASYNC_CALL(session, libssh2_sftp_fstat_ex, handle, attrs, 0)

#define libssh2_sftp_stat_ex(sftp, path, path_len, stat_type, attrs) \
    SSH2_ASYNC_CALL(session, libssh2_sftp_stat_ex, sftp, path, path_len, stat_type, attrs)

#define libssh2_sftp_symlink_ex(sftp, path, path_len, target, target_len, link_type) \
    SSH2_ASYNC_CALL(session, libssh2_sftp_symlink_ex, sftp, path, path_len, target, target_len, link_type)

#undef libssh2_sftp_open
#define libssh2_sftp_open(sftp, filename, flags, mode) \
    sw_libssh2_sftp_open_ex(session, (sftp), (filename), strlen(filename), (flags), (mode), LIBSSH2_SFTP_OPENFILE)

static inline LIBSSH2_SFTP_HANDLE *sw_libssh2_sftp_open_ex(LIBSSH2_SESSION *session,
		LIBSSH2_SFTP *sftp,
        const char *filename,
        unsigned int filename_len,
        unsigned long flags,
        long mode, int open_type) {
	auto event = ssh2_get_event_type(session);
	auto socket = ssh2_get_socket(session);

	LIBSSH2_SFTP_HANDLE *handle;
	while (1) {
		handle = libssh2_sftp_open_ex((sftp), (filename), strlen(filename), (flags), (mode), LIBSSH2_SFTP_OPENFILE);
		if (handle) {
			return handle;
		}
		if (libssh2_session_last_errno(session) == LIBSSH2_ERROR_EAGAIN) {
			if (!socket->poll(event)) {
				return nullptr;
			}
			continue;
		}
		break;
	}
	return nullptr;
}

#undef libssh2_sftp_opendir
#define libssh2_sftp_opendir(sftp, path) sw_libssh2_sftp_open_ex(session, (sftp), (path), strlen(path), 0, 0, LIBSSH2_SFTP_OPENDIR)

#undef libssh2_sftp_readdir
#define libssh2_sftp_readdir(handle, buffer, buffer_maxlen, attrs) \
    SSH2_ASYNC_CALL(session, libssh2_sftp_readdir_ex, (handle), (buffer), (buffer_maxlen), NULL, 0, \
                            (attrs))

#undef libssh2_sftp_close
#define libssh2_sftp_close(handle) \
    SSH2_ASYNC_CALL(session, libssh2_sftp_close_handle, handle)

#undef libssh2_sftp_unlink
#define libssh2_sftp_unlink(sftp, filename) \
    SSH2_ASYNC_CALL(session,   libssh2_sftp_unlink_ex, (sftp), (filename), strlen(filename))

#undef libssh2_sftp_rename
#define libssh2_sftp_rename(sftp, sourcefile, destfile) \
    SSH2_ASYNC_CALL(session, libssh2_sftp_rename_ex, (sftp), (sourcefile), strlen(sourcefile), \
                           (destfile), strlen(destfile),                \
                           LIBSSH2_SFTP_RENAME_OVERWRITE | \
                           LIBSSH2_SFTP_RENAME_ATOMIC | \
                           LIBSSH2_SFTP_RENAME_NATIVE)

#undef libssh2_sftp_mkdir
#define libssh2_sftp_mkdir(sftp, path, mode) \
    SSH2_ASYNC_CALL(session,  libssh2_sftp_mkdir_ex, (sftp), (path), strlen(path), (mode))

#undef libssh2_sftp_rmdir
#define libssh2_sftp_rmdir(sftp, path) \
    SSH2_ASYNC_CALL(session,  libssh2_sftp_rmdir_ex, (sftp), (path), strlen(path))
