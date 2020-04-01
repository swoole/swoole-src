#include "server.h"

#ifdef SW_SUPPORT_DTLS

namespace swoole { namespace dtls {
//-------------------------------------------------------------------------------

int BIO_write(BIO *b, const char *data, int dlen)
{
    swTraceLog(SW_TRACE_SSL, "BIO_write(%d)", dlen);

    Session *session = (Session *) BIO_get_data(b);
    return write(session->socket->fd, data, dlen);
}

int BIO_read(BIO *b, char *data, int len)
{
    Session *session = (Session *) BIO_get_data(b);
    Buffer *buffer;
    BIO_clear_retry_flags(b);

    if (!session->rxqueue.empty())
    {
        buffer = session->rxqueue.front();

        swTrace("BIO_read(%d, peek=%d)=%d", len, session->peek_mode, buffer->length);

        int n = (buffer->length <= len) ? buffer->length : len;
        memmove(data, buffer->data, n);

        if (!session->peek_mode)
        {
            session->rxqueue.pop_front();
            sw_free(buffer);
        }

        return n;
    }
    else
    {
        BIO_set_retry_read(b);
        return -1;
    }
}

long BIO_ctrl(BIO *b, int cmd, long lval, void *ptrval)
{
    long retval = 0;
    Session *session = (Session *) BIO_get_data(b);

    swTraceLog(SW_TRACE_SSL, "BIO_ctrl(BIO[0x%016lX], cmd[%d], lval[%ld], ptrval[0x%016lX])", b, cmd, lval, ptrval);

    switch (cmd)
    {
    case BIO_CTRL_EOF:
            return session->rxqueue.empty();
        case BIO_CTRL_GET_CLOSE:
            return BIO_get_shutdown(b);
        case BIO_CTRL_SET_CLOSE:
            BIO_set_shutdown(b, (int) lval);
            break;
        case BIO_CTRL_WPENDING:
            return 0;
        case BIO_CTRL_PENDING:
            return (long) session->get_buffer_length();

    case BIO_CTRL_FLUSH:
    case BIO_CTRL_DGRAM_SET_CONNECTED:
    case BIO_CTRL_DGRAM_SET_PEER:
        retval = 1;
        break;
    case BIO_CTRL_DGRAM_GET_PEER:
        if (ptrval)
        {
            memcpy(ptrval, &session->socket->info, sizeof(session->socket->info.addr));
        }
        retval = 1;
        break;
    case BIO_CTRL_DGRAM_QUERY_MTU:
    case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
        retval = 1500;
        break;
    case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
        retval = 96; // random guess
        break;
    case BIO_CTRL_DGRAM_SET_PEEK_MODE:
        ((Session *) BIO_get_data(b))->peek_mode = !!lval;
        retval = 1;
        break;
    case BIO_CTRL_PUSH:
    case BIO_CTRL_POP:
    case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
        retval = 0;
        break;
    default:
        swWarn("unknown cmd: %d", cmd);
        retval = 0;
        break;
    }

    return retval;
}

int BIO_create(BIO *b)
{
    return 1;
}

int BIO_destroy(BIO *b)
{
    swTraceLog(SW_TRACE_SSL, "BIO_destroy(BIO[0x%016lX])\n", b);
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

    dtls_session_index = BIO_get_new_index();
    _bio_methods = BIO_meth_new(dtls_session_index | BIO_TYPE_SOURCE_SINK, "swoole_dtls_bio");

    BIO_meth_set_write(_bio_methods, BIO_write);
    BIO_meth_set_read(_bio_methods, BIO_read);
    BIO_meth_set_ctrl(_bio_methods, BIO_ctrl);
    BIO_meth_set_create(_bio_methods, BIO_create);
    BIO_meth_set_destroy(_bio_methods, BIO_destroy);
    BIO_meth_set_callback_ctrl(_bio_methods, BIO_callback_ctrl);

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
    if (swSSL_create(socket, ctx, SW_SSL_SERVER) < 0)
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
        return true;
    }
    else if (retval < 0)
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
    else
    {
        listened = true;
    }

    return true;
}

//-------------------------------------------------------------------------------
}}

#endif
