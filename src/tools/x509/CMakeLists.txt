
# X509 library
include_directories(impl)
add_library(x509 STATIC
    Base64.cpp
    Certificate.cpp
    CertificateRequest.cpp
    PrivateKey.cpp
    Sha2.cpp
    X509Document.cpp

    impl/sign.cpp
 )
target_include_directories(x509 PUBLIC .)
target_link_libraries(x509 PUBLIC helpers OpenSSL::SSL OpenSSL::Crypto)
set_target_properties(x509 PROPERTIES OUTPUT_NAME "open-ocpp_static_x509")
