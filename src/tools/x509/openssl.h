/*
Copyright (c) 2020 Cedric Jimenez
This file is part of OpenOCPP.

OpenOCPP is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 2.1 of the License, or
(at your option) any later version.

OpenOCPP is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with OpenOCPP. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OPENOCPP_OPENSSL_H
#define OPENOCPP_OPENSSL_H

// Disable MSVC warnings
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4191)
#endif // _MSC_VER

// Include OpenSSL's headers
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
// OpenSSL 3.x
#include <openssl/core_names.h>
#include <openssl/store.h>
#endif // OPENSSL_VERSION_NUMBER

namespace ocpp
{namespace x509
{namespace openssl
{
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
/** @brief Load private key from URI
 * @param uri URI to load the private key from
 * @return EVP_PKEY* pointer to the loaded private key, or NULL on failure
 * @note The caller is responsible for freeing the returned EVP_PKEY* using EVP_PKEY_free() when it is no longer needed
 * @note This function requires OpenSSL 3.0 or higher
 * @note The URI should be in a format supported by OpenSSL's OSSL_STORE, such as "pkcs11:", "engine:", "provider:", etc.
 * @note If the URI is not a valid store URI or if the private key cannot be loaded, the function will return NULL and print the OpenSSL error stack to stderr
*/
EVP_PKEY* loadPrivateKeyFromStore(const std::string& uri);
#endif // OPENSSL_VERSION_NUMBER

/** @brief Check if a given path is a store URI
 * A store URI is a string that starts with a valid scheme followed by a colon
 * and does not look like a Windows drive path (e.g., "C:\")
 * or a regular file path. Valid schemes consist of alphanumeric characters, plus (+), minus (-), or dot (.)
 * @param path Path to check
 * @return true if the path is a store URI, false otherwise
 */
bool isStoreUri(const std::string& path);


} // namespace openssl
} // namespace x509
} // namespace ocpp

// Restore MSVC warnings
#ifdef _MSC_VER
#pragma warning(pop)
#endif // _MSC_VER

#endif // OPENOCPP_OPENSSL_H
