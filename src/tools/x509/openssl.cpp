#include <string>
#include <cctype>
#include "openssl.h"

bool isWindowsDrivePath(const std::string& path)
{
    return (path.size() >= 2) && std::isalpha(static_cast<unsigned char>(path[0])) && (path[1] == ':')
           && ((path.size() == 2) || (path[2] == '\\') || (path[2] == '/'));
}

namespace ocpp
{
namespace x509
{
namespace openssl
{
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)

EVP_PKEY* loadPrivateKeyFromStore(const std::string& uri)
{
    EVP_PKEY*     pkey = NULL;
    OSSL_STORE_CTX*   st   = NULL;
    OSSL_STORE_INFO* info = NULL;

    /* Create a new store to read the private key */
    st = OSSL_STORE_open(uri.c_str(), NULL, NULL, NULL, NULL);
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

bool isStoreUri(const std::string& path)
{
    if (path.empty() || isWindowsDrivePath(path) || !std::isalpha(static_cast<unsigned char>(path[0])))
    {
        return false;
    }

    const size_t scheme_end = path.find(':');
    if ((scheme_end == std::string::npos) || (scheme_end == 0))
    {
        return false;
    }

    for (size_t i = 1; i < scheme_end; ++i)
    {
        const unsigned char ch = static_cast<unsigned char>(path[i]);
        if (!std::isalnum(ch) && (ch != '+') && (ch != '-') && (ch != '.'))
        {
            return false;
        }
    }

    return true;
}

} // namespace openssl
} // namespace x509
} // namespace ocpp
