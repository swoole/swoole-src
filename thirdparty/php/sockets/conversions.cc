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
    Socket *sock;
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

const struct key_value sw_empty_key_value_list[] = {{0}};

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
		php_error_docref(NULL, err->level, "%s", err->msg);
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

static void to_zval_read_unsigned(const char *data, zval *zv, res_context *ctx)
{
	unsigned ival;
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
#if defined(IPV6_PKTINFO)
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

/* ENTRY POINT for conversions */
static void free_from_zval_allocation(void *alloc_ptr_ptr)
{
	efree(*(void**)alloc_ptr_ptr);
}

void *from_zval_run_conversions(const zval *container, Socket *sock, from_zval_write_field *writer,
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
