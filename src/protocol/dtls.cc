#include "server.h"

#ifdef SW_USE_OPENSSL

#if OPENSSL_VERSION_NUMBER < 0x10100000L

static BIO_METHOD *BIO_meth_new(int type, const char *name)
{
    BIO_METHOD *method = (BIO_METHOD *) sw_calloc(1, sizeof(*method));

    if (method != NULL)
    {
        method->type = type;
        method->name = name;
    }

    return method;
}

static void BIO_meth_free(BIO_METHOD *method)
{
    sw_free(method);
}

#define BIO_meth_set_write(b, f) (b)->bwrite = (f)
#define BIO_meth_set_read(b, f) (b)->bread = (f)
#define BIO_meth_set_ctrl(b, f) (b)->ctrl = (f)
#define BIO_meth_set_create(b, f) (b)->create = (f)
#define BIO_meth_set_destroy(b, f) (b)->destroy = (f)

#define BIO_set_init(b, val) (b)->init = (val)
#define BIO_set_data(b, val) (b)->ptr = (val)
#define BIO_set_shutdown(b, val) (b)->shutdown = (val)
#define BIO_get_init(b) (b)->init
#define BIO_get_data(b) (b)->ptr
#define BIO_get_shutdown(b) (b)->shutdown

#endif

namespace swoole { namespace dtls {
//-------------------------------------------------------------------------------

int BIO_write_ex(BIO *b, const char *data, size_t dlen, size_t *written)
{
    swWarn("BIO_s_custom_write_ex(BIO[0x%016lX], data[0x%016lX], dlen[%ld], *written[%ld])\n", b, data, dlen, *written);

    return -1;
}

int BIO_read_ex(BIO *b, char *data, size_t dlen, size_t *readbytes)
{
    swWarn("BIO_read_ex(BIO[0x%016lX], data[0x%016lX], dlen[%ld], *readbytes[%ld])\n", b, data, dlen, *readbytes);

    return -1;
}

int BIO_write(BIO *b, const char *data, int dlen)
{
    swTrace("BIO_write(%d)", dlen);

    Session *session = (Session *) BIO_get_data(b);
    return write(session->socket->fd, data, dlen);
}

int BIO_read(BIO *b, char *data, int len)
{
    int ret;
    Session *session = (Session *) BIO_get_data(b);
    Buffer *buffer;

    ret = -1;

    if (!session->rxqueue.empty())
    {
        buffer = session->rxqueue.front();

        swTrace("BIO_read(%d, peek=%d)=%d", len, session->peek_mode, buffer->length);

        ret = (buffer->length <= len) ? buffer->length : len;
        memmove(data, buffer->data, ret);

        if (!session->peek_mode)
        {
            session->rxqueue.pop_front();
            sw_free(buffer);
        }
    }

    return ret;
}

long BIO_ctrl(BIO *b, int cmd, long larg, void *pargs)
{
    long ret = 0;

    swTrace("BIO_ctrl(BIO[0x%016lX], cmd[%d], larg[%ld], pargs[0x%016lX])\n", b, cmd, larg, pargs);

    switch (cmd)
    {
    case BIO_CTRL_FLUSH:
    case BIO_CTRL_DGRAM_SET_CONNECTED:
    case BIO_CTRL_DGRAM_SET_PEER:
    case BIO_CTRL_DGRAM_GET_PEER:
        ret = 1;
        break;
    case BIO_CTRL_WPENDING:
        ret = 0;
        break;
    case BIO_CTRL_DGRAM_QUERY_MTU:
    case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
        ret = 1500;
        break;
    case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
        ret = 96; // random guess
        break;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    case BIO_CTRL_DGRAM_SET_PEEK_MODE:
        ((Session *) BIO_get_data(b))->peek_mode = !!larg;
        ret = 1;
        break;
#endif
    case BIO_CTRL_PUSH:
    case BIO_CTRL_POP:
    case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
        ret = 0;
        break;
    default:
        swWarn("unknown cmd: %d", cmd);
        ret = 0;
        break;
    }

    return ret;
}

int BIO_create(BIO *b)
{
    return 1;
}

int BIO_destroy(BIO *b)
{
    swTrace("BIO_destroy(BIO[0x%016lX])\n", b);
    return 1;
}

static BIO_METHOD *_bio_methods = nullptr;
static int dtls_session_index = 0;

BIO_METHOD *BIO_get_methods(void)
{
    if (_bio_methods)
    {
        return _bio_methods;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    dtls_session_index = 0;
#else
    dtls_session_index = BIO_get_new_index();
#endif
    _bio_methods = BIO_meth_new(dtls_session_index | BIO_TYPE_SOURCE_SINK, "swoole_dtls_bio");

    BIO_meth_set_write(_bio_methods, BIO_write);
    BIO_meth_set_read(_bio_methods, BIO_read);
    BIO_meth_set_ctrl(_bio_methods, BIO_ctrl);
    BIO_meth_set_create(_bio_methods, BIO_create);
    BIO_meth_set_destroy(_bio_methods, BIO_destroy);

    return _bio_methods;
}

void BIO_meth_free(void)
{
    if (_bio_methods)
    {
        BIO_meth_free(_bio_methods);
    }

    _bio_methods = nullptr;
}

void Session::append(const char* data, ssize_t len)
{
    Buffer *buffer = (Buffer *) sw_malloc(sizeof(*buffer) + len);
    buffer->length = len;
    memcpy(buffer->data, data, buffer->length);
    rxqueue.push_back(buffer);
}

bool Session::init()
{
    if (socket->ssl)
    {
        return false;
    }
    if (swSSL_create(socket, ctx, 0) < 0)
    {
        return false;
    }
    socket->dtls = 1;

    BIO *bio = BIO_new(BIO_get_methods());
    BIO_set_data(bio, (void *) this);
    BIO_set_init(bio, 1);
    SSL_set_bio(socket->ssl, bio, bio);

    return true;
}

bool Session::listen()
{
    if (listened)
    {
        return false;
    }

    ERR_clear_error();

    int retval = DTLSv1_listen(socket->ssl, NULL);

    if (retval == 0)
    {
        int reason = ERR_GET_REASON(ERR_peek_error());
        swWarn(
            "DTLSv1_listen() failed, client[%s:%d], reason=%d, error_string=%s",
            swSocket_get_ip(socket->socket_type, &socket->info),
            swSocket_get_port(socket->socket_type, &socket->info),
            reason, swSSL_get_error()
        );
        return false;
    }
    else if (retval < 0)
    {
        return ERR_get_error() == 0;
    }
    else
    {
        listened = true;
    }

    return true;
}

//-------------------------------------------------------------------------------
}}

#endif
