#include "php_sockets_cxx.h"

#include <Zend/zend_llist.h>
#include <zend_smart_str.h>

# include <sys/types.h>
# include <sys/socket.h>
# include <arpa/inet.h>
# include <netinet/in.h>
# include <sys/un.h>
# include <sys/ioctl.h>
# include <net/if.h>

#include <limits.h>
#include <stdarg.h>
#include <stddef.h>

#define MAX_USER_BUFF_SIZE ((size_t)(100*1024*1024))
#define DEFAULT_BUFF_SIZE 8192

struct _ser_context
{
    HashTable params; /* stores pointers; has to be first */
    struct err_s err;
    zend_llist keys,
    /* common part to res_context ends here */
    allocations;
    swoole::Socket *sock;
};

struct _res_context
{
    HashTable params; /* stores pointers; has to be first */
    struct err_s err;
    zend_llist keys;
};

typedef struct {
	/* zval info */
	const char *name;
	unsigned name_size;
	int required;

	/* structure info */
	size_t field_offset; /* 0 to pass full structure, e.g. when more than
							one field is to be changed; in that case the
							callbacks need to know the name of the fields */

	/* callbacks */
	from_zval_write_field *from_zval;
	to_zval_read_field *to_zval;
} field_descriptor;

const struct key_value empty_key_value_list[] = {{0}};

/* ERRORS */
static void do_from_to_zval_err(struct err_s *err,
								zend_llist *keys,
								const char *what_conv,
								const char *fmt,
								va_list ap)
{
	smart_str			path = {0};
	const char			**node;
	char				*user_msg;
	int					user_msg_size;
	zend_llist_position	pos;

	if (err->has_error) {
		return;
    }

    for (node = (const char **) zend_llist_get_first_ex(keys, &pos); node != NULL; node =
            (const char **) zend_llist_get_next_ex(keys, &pos))
    {
        smart_str_appends(&path, *node);
        smart_str_appends(&path, " > ");
    }

	if (path.s && ZSTR_LEN(path.s) > 3) {
		ZSTR_LEN(path.s) -= 3;
	}
	smart_str_0(&path);

	user_msg_size = vspprintf(&user_msg, 0, fmt, ap);

	err->has_error = 1;
	err->level = E_WARNING;
	spprintf(&err->msg, 0, "error converting %s data (path: %s): %.*s",
			what_conv,
			path.s && *ZSTR_VAL(path.s) != '\0' ? ZSTR_VAL(path.s) : "unavailable",
			user_msg_size, user_msg);
	err->should_free = 1;

	efree(user_msg);
	smart_str_free(&path);
}

ZEND_ATTRIBUTE_FORMAT(printf, 2 ,3)

static void do_from_zval_err(ser_context *ctx, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	do_from_to_zval_err(&ctx->err, &ctx->keys, "user", fmt, ap);
	va_end(ap);
}
ZEND_ATTRIBUTE_FORMAT(printf, 2 ,3)

static void do_to_zval_err(res_context *ctx, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	do_from_to_zval_err(&ctx->err, &ctx->keys, "native", fmt, ap);
	va_end(ap);
}

void err_msg_dispose(struct err_s *err)
{
	if (err->msg != NULL) {
		php_error_docref0(NULL, err->level, "%s", err->msg);
		if (err->should_free) {
			efree(err->msg);
		}
	}
}
void allocations_dispose(zend_llist **allocations)
{
	zend_llist_destroy(*allocations);
	efree(*allocations);
	*allocations = NULL;
}

static unsigned from_array_iterate(const zval *arr,
								   void (*func)(zval *elem, unsigned i, void **args, ser_context *ctx),
								   void **args,
								   ser_context *ctx)
{
	unsigned		i;
	zval			*elem;
	char			buf[sizeof("element #4294967295")];
	char			*bufp = buf;

	/* Note i starts at 1, not 0! */
	i = 1;
	ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(arr), elem) {
		if ((size_t)snprintf(buf, sizeof(buf), "element #%u", i) >= sizeof(buf)) {
			memcpy(buf, "element", sizeof("element"));
		}
		zend_llist_add_element(&ctx->keys, &bufp);

		func(elem, i, args, ctx);

		zend_llist_remove_tail(&ctx->keys);
		if (ctx->err.has_error) {
			break;
		}
		i++;
    } ZEND_HASH_FOREACH_END();

    return i -1;
}

/* Generic Aggregated conversions */
static void from_zval_write_aggregation(const zval *container,
										char *structure,
										const field_descriptor *descriptors,
										ser_context *ctx)
{
	const field_descriptor	*descr;
	zval					*elem;

	if (Z_TYPE_P(container) != IS_ARRAY) {
		do_from_zval_err(ctx, "%s", "expected an array here");
	}

	for (descr = descriptors; descr->name != NULL && !ctx->err.has_error; descr++) {
		if ((elem = zend_hash_str_find(Z_ARRVAL_P(container),
				descr->name, descr->name_size - 1)) != NULL) {

			if (descr->from_zval == NULL) {
				do_from_zval_err(ctx, "No information on how to convert value "
						"of key '%s'", descr->name);
				break;
			}

			zend_llist_add_element(&ctx->keys, (void*)&descr->name);
			descr->from_zval(elem, ((char*)structure) + descr->field_offset, ctx);
			zend_llist_remove_tail(&ctx->keys);

		} else if (descr->required) {
			do_from_zval_err(ctx, "The key '%s' is required", descr->name);
			break;
		}
	}
}
static void to_zval_read_aggregation(const char *structure,
									 zval *zarr, /* initialized array */
									 const field_descriptor *descriptors,
									 res_context *ctx)
{
	const field_descriptor	*descr;

	assert(Z_TYPE_P(zarr) == IS_ARRAY);
	assert(Z_ARRVAL_P(zarr) != NULL);

	for (descr = descriptors; descr->name != NULL && !ctx->err.has_error; descr++) {
		zval *new_zv, tmp;

		if (descr->to_zval == NULL) {
			do_to_zval_err(ctx, "No information on how to convert native "
					"field into value for key '%s'", descr->name);
			break;
		}

		ZVAL_NULL(&tmp);
		new_zv = zend_symtable_str_update(Z_ARRVAL_P(zarr), descr->name, descr->name_size - 1, &tmp);

		zend_llist_add_element(&ctx->keys, (void*)&descr->name);
		descr->to_zval(structure + descr->field_offset, new_zv, ctx);
		zend_llist_remove_tail(&ctx->keys);
	}
}

/* CONVERSIONS for integers */
static zend_long from_zval_integer_common(const zval *arr_value, ser_context *ctx)
{
	zend_long ret = 0;
	zval lzval;

	ZVAL_NULL(&lzval);
	if (Z_TYPE_P(arr_value) != IS_LONG) {
		ZVAL_COPY(&lzval, (zval *)arr_value);
		arr_value = &lzval;
	}

	switch (Z_TYPE_P(arr_value)) {
	case IS_LONG:
long_case:
		ret = Z_LVAL_P(arr_value);
		break;

	/* if not long we're operating on lzval */
	case IS_DOUBLE:
double_case:
		convert_to_long(&lzval);
		goto long_case;

	case IS_OBJECT:
	case IS_STRING: {
		zend_long lval;
		double dval;

		convert_to_string(&lzval);

		switch (is_numeric_string(Z_STRVAL(lzval), Z_STRLEN(lzval), &lval, &dval, 0)) {
		case IS_DOUBLE:
		    zval_dtor(&lzval);
			ZVAL_DOUBLE(&lzval, dval);
			goto double_case;

		case IS_LONG:
		    zval_dtor(&lzval);
			ZVAL_LONG(&lzval, lval);
			goto long_case;
		}

		/* if we get here, we don't have a numeric string */
		do_from_zval_err(ctx, "expected an integer, but got a non numeric "
				"string (possibly from a converted object): '%s'", Z_STRVAL_P(arr_value));
		break;
	}

	default:
		do_from_zval_err(ctx, "%s", "expected an integer, either of a PHP "
				"integer type or of a convertible type");
		break;
	}

	zval_ptr_dtor(&lzval);

	return ret;
}
void from_zval_write_int(const zval *arr_value, char *field, ser_context *ctx)
{
	zend_long lval;
	int ival;

	lval = from_zval_integer_common(arr_value, ctx);
	if (ctx->err.has_error) {
		return;
	}

	if (lval > INT_MAX || lval < INT_MIN) {
		do_from_zval_err(ctx, "%s", "given PHP integer is out of bounds "
				"for a native int");
		return;
	}

	ival = (int)lval;
	memcpy(field, &ival, sizeof(ival));
}
static void from_zval_write_pid_t(const zval *arr_value, char *field, ser_context *ctx)
{
	zend_long lval;
	pid_t ival;

	lval = from_zval_integer_common(arr_value, ctx);
	if (ctx->err.has_error) {
		return;
	}

	if (lval < 0 || (pid_t)lval != lval) { /* pid_t is signed */
		do_from_zval_err(ctx, "%s", "given PHP integer is out of bounds "
				"for a pid_t value");
		return;
	}

	ival = (pid_t)lval;
	memcpy(field, &ival, sizeof(ival));
}
static void from_zval_write_uid_t(const zval *arr_value, char *field, ser_context *ctx)
{
	zend_long lval;
	uid_t ival;

	lval = from_zval_integer_common(arr_value, ctx);
	if (ctx->err.has_error) {
		return;
	}

	/* uid_t can be signed or unsigned (generally unsigned) */
	if ((uid_t)-1 > (uid_t)0) {
		if (sizeof(zend_long) > sizeof(uid_t) && (lval < 0 || (uid_t)lval != lval)) {
			do_from_zval_err(ctx, "%s", "given PHP integer is out of bounds "
					"for a uid_t value");
			return;
		}
	} else {
		if (sizeof(zend_long) > sizeof(uid_t) && (uid_t)lval != lval) {
			do_from_zval_err(ctx, "%s", "given PHP integer is out of bounds "
					"for a uid_t value");
			return;
		}
	}

	ival = (uid_t)lval;
	memcpy(field, &ival, sizeof(ival));
}

void to_zval_read_int(const char *data, zval *zv, res_context *ctx)
{
	int ival;
	memcpy(&ival, data, sizeof(ival));

	ZVAL_LONG(zv, (zend_long)ival);
}
static void to_zval_read_unsigned(const char *data, zval *zv, res_context *ctx)
{
	unsigned ival;
	memcpy(&ival, data, sizeof(ival));

	ZVAL_LONG(zv, (zend_long)ival);
}


static void to_zval_read_pid_t(const char *data, zval *zv, res_context *ctx)
{
	pid_t ival;
	memcpy(&ival, data, sizeof(ival));

	ZVAL_LONG(zv, (zend_long)ival);
}
static void to_zval_read_uid_t(const char *data, zval *zv, res_context *ctx)
{
	uid_t ival;
	memcpy(&ival, data, sizeof(ival));

	ZVAL_LONG(zv, (zend_long)ival);
}

static void from_zval_write_sin6_addr(const zval *zaddr_str, char *addr6, ser_context *ctx)
{
	int					res;
	struct sockaddr_in6	saddr6 = {0};
	zend_string			*addr_str;

	addr_str = zval_get_string((zval *) zaddr_str);
	res = php_set_inet6_addr(&saddr6, ZSTR_VAL(addr_str), ctx->sock);
	if (res) {
		memcpy(addr6, &saddr6.sin6_addr, sizeof saddr6.sin6_addr);
	} else {
		/* error already emitted, but let's emit another more relevant */
		do_from_zval_err(ctx, "could not resolve address '%s' to get an AF_INET6 "
				"address", Z_STRVAL_P(zaddr_str));
	}

	zend_string_release(addr_str);
}

static void to_zval_read_sin6_addr(const char *data, zval *zv, res_context *ctx)
{
	const struct in6_addr *addr = (const struct in6_addr *)data;
	socklen_t size = INET6_ADDRSTRLEN;
	zend_string *str = zend_string_alloc(size - 1, 0);

	memset(ZSTR_VAL(str), '\0', size);

	ZVAL_NEW_STR(zv, str);

	if (inet_ntop(AF_INET6, addr, Z_STRVAL_P(zv), size) == NULL) {
		do_to_zval_err(ctx, "could not convert IPv6 address to string "
				"(errno %d)", errno);
		return;
	}

	Z_STRLEN_P(zv) = strlen(Z_STRVAL_P(zv));
}


/* CONVERSIONS for if_index */
static void from_zval_write_ifindex(const zval *zv, char *uinteger, ser_context *ctx)
{
	unsigned ret = 0;

	if (Z_TYPE_P(zv) == IS_LONG) {
		if (Z_LVAL_P(zv) < 0 || (zend_ulong)Z_LVAL_P(zv) > UINT_MAX) { /* allow 0 (unspecified interface) */
			do_from_zval_err(ctx, "the interface index cannot be negative or "
					"larger than %u; given " ZEND_LONG_FMT, UINT_MAX, Z_LVAL_P(zv));
		} else {
			ret = (unsigned)Z_LVAL_P(zv);
		}
	} else {
		zend_string *str;

		str = zval_get_string((zval *) zv);

#if HAVE_IF_NAMETOINDEX
		ret = if_nametoindex(ZSTR_VAL(str));
		if (ret == 0) {
			do_from_zval_err(ctx, "no interface with name \"%s\" could be found", ZSTR_VAL(str));
		}
#elif defined(SIOCGIFINDEX)
		{
			struct ifreq ifr;
			if (strlcpy(ifr.ifr_name, ZSTR_VAL(str), sizeof(ifr.ifr_name))
					>= sizeof(ifr.ifr_name)) {
				do_from_zval_err(ctx, "the interface name \"%s\" is too large ", ZSTR_VAL(str));
			} else if (ioctl(ctx->sock->get_fd(), SIOCGIFINDEX, &ifr) < 0) {
				if (errno == ENODEV) {
					do_from_zval_err(ctx, "no interface with name \"%s\" could be "
							"found", ZSTR_VAL(str));
				} else {
					do_from_zval_err(ctx, "error fetching interface index for "
							"interface with name \"%s\" (errno %d)",
							ZSTR_VAL(str), errno);
				}
			} else {
				ret = (unsigned)ifr.ifr_ifindex;
			}
		}
#else
		do_from_zval_err(ctx,
				"this platform does not support looking up an interface by "
				"name, an integer interface index must be supplied instead");
#endif

		zend_string_release(str);
	}

	if (!ctx->err.has_error) {
		memcpy(uinteger, &ret, sizeof(ret));
	}
}

/* CONVERSIONS for struct in6_pktinfo */
#if defined(IPV6_PKTINFO) && HAVE_IPV6
static const field_descriptor descriptors_in6_pktinfo[] = {
		{"addr", sizeof("addr"), 1, offsetof(struct in6_pktinfo, ipi6_addr), from_zval_write_sin6_addr, to_zval_read_sin6_addr},
		{"ifindex", sizeof("ifindex"), 1, offsetof(struct in6_pktinfo, ipi6_ifindex), from_zval_write_ifindex, to_zval_read_unsigned},
		{0}
};
void from_zval_write_in6_pktinfo(const zval *container, char *in6_pktinfo_c, ser_context *ctx)
{
	from_zval_write_aggregation(container, in6_pktinfo_c, descriptors_in6_pktinfo, ctx);
}
void to_zval_read_in6_pktinfo(const char *data, zval *zv, res_context *ctx)
{
	array_init_size(zv, 2);

	to_zval_read_aggregation(data, zv, descriptors_in6_pktinfo, ctx);
}
#endif

/* CONVERSIONS for struct ucred */
#ifdef SO_PASSCRED
static const field_descriptor descriptors_ucred[] = {
		{"pid", sizeof("pid"), 1, offsetof(struct ucred, pid), from_zval_write_pid_t, to_zval_read_pid_t},
		{"uid", sizeof("uid"), 1, offsetof(struct ucred, uid), from_zval_write_uid_t, to_zval_read_uid_t},
		/* assume the type gid_t is the same as uid_t: */
		{"gid", sizeof("gid"), 1, offsetof(struct ucred, gid), from_zval_write_uid_t, to_zval_read_uid_t},
		{0}
};
void from_zval_write_ucred(const zval *container, char *ucred_c, ser_context *ctx)
{
	from_zval_write_aggregation(container, ucred_c, descriptors_ucred, ctx);
}
void to_zval_read_ucred(const char *data, zval *zv, res_context *ctx)
{
	array_init_size(zv, 3);

	to_zval_read_aggregation(data, zv, descriptors_ucred, ctx);
}
#endif

/* CONVERSIONS for SCM_RIGHTS */
#ifdef SCM_RIGHTS
size_t calculate_scm_rights_space(const zval *arr, ser_context *ctx)
{
	int num_elems;

	if (Z_TYPE_P(arr) != IS_ARRAY) {
		do_from_zval_err(ctx, "%s", "expected an array here");
		return (size_t)-1;
	}

	num_elems = zend_hash_num_elements(Z_ARRVAL_P(arr));
	if (num_elems == 0) {
		do_from_zval_err(ctx, "%s", "expected at least one element in this array");
		return (size_t)-1;
	}

	return zend_hash_num_elements(Z_ARRVAL_P(arr)) * sizeof(int);
}

static void from_zval_write_fd_array_aux(zval *elem, unsigned i, void **args, ser_context *ctx)
{
    int *iarr = (int *) args[0];

	if (Z_TYPE_P(elem) == IS_RESOURCE) {
		php_stream *stream;
		swoole::Socket *sock;

		sock = (swoole::Socket *)zend_fetch_resource_ex(elem, NULL, php_sockets_le_socket());
		if (sock) {
			iarr[i] = sock->get_fd();
			return;
		}

		stream = (php_stream *)zend_fetch_resource2_ex(elem, NULL, php_file_le_stream(), php_file_le_pstream());
		if (stream == NULL) {
			do_from_zval_err(ctx, "resource is not a stream or a socket");
			return;
		}

		if (php_stream_cast(stream, PHP_STREAM_AS_FD, (void **)&iarr[i - 1],
				REPORT_ERRORS) == FAILURE) {
			do_from_zval_err(ctx, "cast stream to file descriptor failed");
			return;
		}
	} else {
		do_from_zval_err(ctx, "expected a resource variable");
	}
}
void from_zval_write_fd_array(const zval *arr, char *int_arr, ser_context *ctx)
{
	if (Z_TYPE_P(arr) != IS_ARRAY) {
		do_from_zval_err(ctx, "%s", "expected an array here");
		return;
	}

   from_array_iterate(arr, &from_zval_write_fd_array_aux, (void**)&int_arr, ctx);
}

#endif

/* ENTRY POINT for conversions */
static void free_from_zval_allocation(void *alloc_ptr_ptr)
{
	efree(*(void**)alloc_ptr_ptr);
}


void *from_zval_run_conversions(const zval *container, swoole::Socket *sock, from_zval_write_field *writer,
        size_t struct_size, const char *top_name, zend_llist **allocations /* out */, struct err_s *err /* in/out */)
{
	ser_context ctx;
	char *structure;

	*allocations = NULL;

	if (err->has_error) {
		return NULL;
	}

	memset(&ctx, 0, sizeof(ctx));
	zend_hash_init(&ctx.params, 8, NULL, NULL, 0);
	zend_llist_init(&ctx.keys, sizeof(const char *), NULL, 0);
	zend_llist_init(&ctx.allocations, sizeof(void *), &free_from_zval_allocation, 0);
	ctx.sock = sock;

    structure = (char *) ecalloc(1, struct_size);

	zend_llist_add_element(&ctx.keys, &top_name);
	zend_llist_add_element(&ctx.allocations, &structure);

	/* main call */
	writer(container, structure, &ctx);

    if (ctx.err.has_error)
    {
        zend_llist_destroy(&ctx.allocations); /* deallocates structure as well */
        structure = NULL;
        *err = ctx.err;
    }
    else
    {
        *allocations = (zend_llist *) emalloc(sizeof **allocations);
        **allocations = ctx.allocations;
    }

	zend_llist_destroy(&ctx.keys);
	zend_hash_destroy(&ctx.params);

	return structure;
}
zval *to_zval_run_conversions(const char *structure,
							  to_zval_read_field *reader,
							  const char *top_name,
							  const struct key_value *key_value_pairs,
							  struct err_s *err, zval *zv)
{
	res_context				ctx;
	const struct key_value	*kv;

	if (err->has_error) {
		return NULL;
	}

	memset(&ctx, 0, sizeof(ctx));
	zend_llist_init(&ctx.keys, sizeof(const char *), NULL, 0);
	zend_llist_add_element(&ctx.keys, &top_name);

	zend_hash_init(&ctx.params, 8, NULL, NULL, 0);
	for (kv = key_value_pairs; kv->key != NULL; kv++) {
		zend_hash_str_update_ptr(&ctx.params, kv->key, kv->key_size - 1, kv->value);
	}

	ZVAL_NULL(zv);
	/* main call */
	reader(structure, zv, &ctx);

	if (ctx.err.has_error) {
		zval_ptr_dtor(zv);
		ZVAL_UNDEF(zv);
		*err = ctx.err;
	}

	zend_llist_destroy(&ctx.keys);
	zend_hash_destroy(&ctx.params);

	return Z_ISUNDEF_P(zv)? NULL : zv;
}
