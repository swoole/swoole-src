#include "test_core.h"

namespace swoole {
namespace test {
void printAllSubjectEntries(X509_NAME *name) {
    if (!name) return;

    int entry_count = X509_NAME_entry_count(name);

    for (int i = 0; i < entry_count; ++i) {
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, i);
        ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(entry);
        ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);

        // 获取字段的短名称（如 CN、O、ST 等）
        char obj_txt[80] = {0};
        OBJ_obj2txt(obj_txt, sizeof(obj_txt), obj, 0);

        // 获取字段的值
        unsigned char *utf8 = nullptr;
        int length = ASN1_STRING_to_UTF8(&utf8, data);
        if (length >= 0 && utf8) {
            sw_printf("%s: %.*s\n", obj_txt, length, utf8);
            OPENSSL_free(utf8);
        }
    }
}

void printX509Info(X509 *cert) {
    X509_NAME *subject_name = X509_get_subject_name(cert);
    printAllSubjectEntries(subject_name);

    char *subject = X509_NAME_oneline(subject_name, 0, 0);
    if (subject) {
        sw_printf("Peer certificate subject: %s\n", subject);
        OPENSSL_free(subject);
    }

    X509_NAME *issuer_name = X509_get_issuer_name(cert);
    printAllSubjectEntries(issuer_name);

    // 获取证书有效期
    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);

    BIO *bio = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio, not_before);
    char buf[256] = {0};
    int len = BIO_read(bio, buf, sizeof(buf) - 1);
    buf[len] = 0;
    sw_printf("Validity Not Before:  %s\n", buf);

    ASN1_TIME_print(bio, not_after);
    len = BIO_read(bio, buf, sizeof(buf) - 1);
    buf[len] = 0;
    sw_printf("Validity Not After:   %s\n", buf);

    BIO_free(bio);

    // 获取公钥
    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    if (pubkey) {
        sw_printf("Public key type: %d\n", EVP_PKEY_id(pubkey));
        EVP_PKEY_free(pubkey);
    }
}

int dump_cert_info(const char *data, size_t len) {
    BIO *bio = BIO_new_mem_buf(data, (int) len);
    if (!bio) {
        std::cerr << "Failed to create BIO" << std::endl;
        return 1;
    }

    // 从 BIO 中读取证书
    X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (!cert) {
        std::cerr << "Failed to parse X509 certificate" << std::endl;
        BIO_free(bio);
        return 1;
    }

    // 打印证书信息
    printX509Info(cert);

    // 释放资源
    X509_free(cert);
    BIO_free(bio);
    EVP_cleanup();

    return 0;
}
}  // namespace test
}  // namespace swoole
