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

#ifndef OPENOCPP_X509DOCUMENT_H
#define OPENOCPP_X509DOCUMENT_H

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace ocpp
{
namespace x509
{

/** @brief Base class for X509 encoded document manipulation */
class X509Document
{
  public:
    /** @brief Contains subject information */
    struct Subject
    {
        /** @brief Country */
        std::string country;
        /** @brief State */
        std::string state;
        /** @brief Location */
        std::string location;
        /** @brief Organization */
        std::string organization;
        /** @brief Organization unit */
        std::string organization_unit;
        /** @brief Common name */
        std::string common_name;
        /** @brief E-mail address */
        std::string email_address;
    };

    /** @brief Contains Basic Constraint extension data */
    struct BasicConstraints
    {
        /** @brief Constructor */
        BasicConstraints() : present(false), is_ca(false), path_length(0) { }

        /** @brief Indicate if the extension is present */
        bool present;
        /** @brief Indicate if CA = true */
        bool is_ca;
        /** @brief Path length */
        unsigned int path_length;
    };

    /** @brief Contains Key Usage extension data */
    struct KeyUsage
    {
        /** @brief Constructor */
        KeyUsage() : present(false), digital_signature(false), key_agreement(false), key_encipherment(false),
                     data_encipherment(false), key_cert_sign(false), crl_sign(false), encipher_only(false),
                     decipher_only(false) { }

        /** @brief Indicate if the extension is present */
        bool present;
        /** @brief Digital signature */
        bool digital_signature;
        /** @brief Key agreement */
        bool key_agreement;
        /** @brief Key encipherment */
        bool key_encipherment;
        /** @brief Data encipherment */
        bool data_encipherment;
        /** @brief Certificate signing */
        bool key_cert_sign;
        /** @brief CRL signing */
        bool crl_sign;
        /** @brief Encipher only */
        bool encipher_only;
        /** @brief Decipher only */
        bool decipher_only;
    };

    /** @brief Contains Extended Key Usage extension data */
    struct ExtendedKeyUsage
    {
        /** @brief Constructor */
        ExtendedKeyUsage() : present(false), server_auth(false), client_auth(false), code_signing(false),
                             email_protection(false), time_stamping(false), ocsp_signing(false) { }

        /** @brief Indicate if the extension is present */
        bool present;
        /** @brief TLS server authentication */
        bool server_auth;
        /** @brief TLS client authentication */
        bool client_auth;
        /** @brief Code signing */
        bool code_signing;
        /** @brief Email protection */
        bool email_protection;
        /** @brief Time stamping */
        bool time_stamping;
        /** @brief OCSP signing */
        bool ocsp_signing;
    };

    /** @brief Contains X509v3 extensions */
    struct Extensions
    {
        /** @brief Basic constraints */
        BasicConstraints basic_constraints;
        /** @brief Key usage */
        KeyUsage key_usage;
        /** @brief Extended key usage */
        ExtendedKeyUsage extended_key_usage;
        /** @brief Issuer alternate names */
        std::vector<std::string> issuer_alternate_names;
        /** @brief Subject alternate names */
        std::vector<std::string> subject_alternate_names;
    };

    /**
     * @brief Constructor from PEM file
     * @param pem_file PEM file to load
     */
    X509Document(const std::filesystem::path& pem_file);

    /**
     * @brief Constructor from PEM data
     * @param pem_data PEM encoded data
     */
    X509Document(const std::string& pem_data);

    /** @brief Destructor */
    virtual ~X509Document();

    /**
     * @brief Save the X509 document as a PEM encoded file
     * @param pem_file Path of the file to generate
     * @return true if the X509 document has been saved, false otherwise
     */
    bool toFile(const std::filesystem::path& pem_file) const;

    /**
     * @brief Indicate if the X509 document is valid
     * @return true if the document is valid, false otherwise
     */
    bool isValid() const { return m_is_valid; }

    /**
     * @brief Get the PEM encoded data representation of the document
     * @return PEM encoded data representation of the document
     */
    const std::string& pem() const { return m_pem; }

    /**
     * @brief Get the subject
     * @return Subject
     */
    const Subject& subject() const { return m_subject; }

    /**
     * @brief Get the subject string
     * @return Subject string
     */
    const std::string& subjectString() const { return m_subject_string; }

    /**
     * @brief Get the subject alternate names
     * @return Subject alternate names
     */
    const std::vector<std::string>& subjectAltNames() const { return m_x509v3_extensions.subject_alternate_names; }

    /**
     * @brief Get the signature algorithm
     * @return Signature algorithm
     */
    const std::string& signatureAlgo() const { return m_sig_algo; }

    /**
     * @brief Get the signature hash
     * @return Signature hash
     */
    const std::string& signatureHash() const { return m_sig_hash; }

    /**
     * @brief Get the public key
     * @return Public key
     */
    const std::vector<uint8_t>& publicKey() const { return m_pub_key; }

    /**
     * @brief Get the public key as string
     * @return Public key as string
     */
    const std::string& publicKeyString() const { return m_pub_key_string; }

    /**
     * @brief Get the size of the public key in bits
     * @return Size of the public key in bits
     */
    unsigned int publicKeySize() const { return m_pub_key_size; }

    /**
     * @brief Get the public key algorithm
     * @return Public key algorithm
     */
    const std::string& publicKeyAlgo() const { return m_pub_key_algo; }

    /**
     * @brief Get the public key algorithm parameter
     * @return Public key algorithm parameter
     */
    const std::string& publicKeyAlgoParam() const { return m_pub_key_algo_param; }

    /**
     * @brief Get the X509v3 extensions
     * @return X509v3 extensions
     */
    const Extensions& x509v3Extensions() const { return m_x509v3_extensions; }

    /**
     * @brief Get the X509v3 extensions names
     * @return X509v3 extensions names
     */
    const std::vector<std::string>& x509v3ExtensionsNames() const { return m_x509v3_extensions_names; }

    /**
     * @brief Get the underlying OpenSSL object
     * @return Underlying SSL object
     */
    const void* object() const { return m_openssl_object; }

  protected:
    /** @brief Indicate if the document is valid */
    bool m_is_valid;
    /** @brief PEM encoded data representation of the document */
    std::string m_pem;

    /** @brief Subject */
    Subject m_subject;
    /** @brief Subject string */
    std::string m_subject_string;
    /** @brief Signature algorithm */
    std::string m_sig_algo;
    /** @brief Signature hash */
    std::string m_sig_hash;
    /** @brief Public key */
    std::vector<uint8_t> m_pub_key;
    /** @brief Public key as hexadecimal string */
    std::string m_pub_key_string;
    /** @brief Size of the public key in bits */
    unsigned int m_pub_key_size;
    /** @brief Public key algorithm */
    std::string m_pub_key_algo;
    /** @brief Public key algorithm parameter */
    std::string m_pub_key_algo_param;
    /** @brief X509v3 extensions */
    Extensions m_x509v3_extensions;
    /** @brief X509v3 extensions names*/
    std::vector<std::string> m_x509v3_extensions_names;

    /** @brief Internal OpenSSL object */
    void* m_openssl_object;

    /** @brief Parse a public key */
    void parsePublicKey(void* ppub_key);

    /** @brief Convert a date in ASN1_TIME format to a standard time_t representation */
    static time_t convertAsn1Time(const void* pasn1_time);
    /** @brief Convert a string in ASN1_STRING format to a standard string representation */
    static std::string convertAsn1String(const void* pasn1_string);
    /** @brief Convert a string in X509_NAME format to a standard string representation */
    static std::string convertX509Name(const void* px509_name);
    /** @brief Convert a list of strings in GENERAL_NAMES format to a standard vector of strings representation */
    static std::vector<std::string> convertGeneralNames(void* pgeneral_names);
    /** @brief Parse a subject's string */
    static void parseSubjectString(const void* px509_name, Subject& subject);
};

} // namespace x509
} // namespace ocpp

#endif // OPENOCPP_X509DOCUMENT_H
