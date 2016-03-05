#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <nghttp2/nghttp2.h>

int inflate_header_block(nghttp2_hd_inflater *inflater, uint8_t *in, size_t inlen, int final);

int main(int argc, char **argv)
{
    nghttp2_hd_inflater *inflater;
    int rv = nghttp2_hd_inflate_new(&inflater);

    if (rv != 0)
    {
        fprintf(stderr, "nghttp2_hd_inflate_init failed with error: %s\n", nghttp2_strerror(rv));
        exit(EXIT_FAILURE);
    }

    printf("\n\nInflate:\n\n");

    int fp = open("data.txt", O_RDONLY);
    if (fp < 0)
    {
        printf("open() fail, err: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    char buf[4096];
    int len = read(fp, buf, sizeof(buf));
    if (len < 0)
    {
        printf("read() fail, err: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    rv = inflate_header_block(inflater, buf + 6, len - 6, 1);

    if (rv != 0)
    {
        exit(EXIT_FAILURE);
    }

    printf("\n-----------------------------------------------------------"
            "--------------------\n");

    return 0;
}

int inflate_header_block(nghttp2_hd_inflater *inflater, uint8_t *in, size_t inlen, int final)
{
    ssize_t rv;

    for (;;)
    {
        nghttp2_nv nv;
        int inflate_flags = 0;
        size_t proclen;

        rv = nghttp2_hd_inflate_hd(inflater, &nv, &inflate_flags, in, inlen, final);

        if (rv < 0)
        {
            fprintf(stderr, "inflate failed with error code %zd", rv);
            return -1;
        }

        proclen = (size_t) rv;

        in += proclen;
        inlen -= proclen;

        if (inflate_flags & NGHTTP2_HD_INFLATE_EMIT)
        {
            fwrite(nv.name, nv.namelen, 1, stderr);
            fprintf(stderr, ": ");
            fwrite(nv.value, nv.valuelen, 1, stderr);
            fprintf(stderr, "\n");
        }

        if (inflate_flags & NGHTTP2_HD_INFLATE_FINAL)
        {
            nghttp2_hd_inflate_end_headers(inflater);
            break;
        }

        if ((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 && inlen == 0)
        {
            break;
        }
    }

    return 0;
}
