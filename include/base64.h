#ifndef __BASE64_H__
#define __BASE64_H__
enum {BASE64_OK = 0, BASE64_INVALID};
#define BASE64_ENCODE_OUT_SIZE(s) (((s) + 2) / 3 * 4)
#define BASE64_DECODE_OUT_SIZE(s) (((s)) / 4 * 3)
int
        swBase64_encode(unsigned char *in, int inlen, char *out);
int
        swBase64_decode(char *in, int inlen, unsigned char *out);
#endif /* __BASE64_H__ */