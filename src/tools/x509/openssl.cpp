#include "openssl.h"

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)

EVP_PKEY* load_private_key_from_store_uri(const char* uri)
{
    EVP_PKEY*     pkey = NULL;
    OSSL_STORE_CTX*   st   = NULL;
    OSSL_STORE_INFO* info = NULL;

    /* Create a new store to read the private key */
    st = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
    if (st == NULL) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    /* Read the private key from the store */
    while ((info = OSSL_STORE_load(st)) != NULL) {
        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
            pkey = OSSL_STORE_INFO_get1_PKEY(info);
            OSSL_STORE_INFO_free(info);
            break;
        }
        OSSL_STORE_INFO_free(info);
    }
    OSSL_STORE_close(st);
    return pkey;
}
#endif // OPENSSL_VERSION_NUMBER
