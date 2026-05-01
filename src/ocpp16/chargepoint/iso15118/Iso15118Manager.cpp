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

#include "Iso15118Manager.h"
#include "CertificateRequest.h"
#include "CertificateSigned.h"
#include "DeleteCertificate.h"
#include "Get15118EVCertificate.h"
#include "GetCertificateStatus.h"
#include "IAuthentManager.h"
#include "IChargePointEventsHandler.h"
#include "IOcppConfig.h"
#include "ISecurityManager.h"
#include "ITimerPool.h"
#include "Iso15118Authorize.h"
#include "Iso15118GetInstalledCertificateIds.h"
#include "Iso15118InstallCertificate.h"
#include "Iso15118TriggerMessage.h"
#include "SecurityEvent.h"
#include "SignCertificate.h"
#include "WorkerThreadPool.h"

#include <thread>
#include <vector>

using namespace ocpp::x509;
using namespace ocpp::messages;
using namespace ocpp::messages::ocpp16;
using namespace ocpp::types;
using namespace ocpp::types::ocpp16;

namespace ocpp
{
namespace chargepoint
{

/** @brief Constructor */
Iso15118Manager::Iso15118Manager(ocpp::config::IOcppConfig&                      ocpp_config,
                                 IChargePointEventsHandler&                      events_handler,
                                 ocpp::helpers::ITimerPool&                      timer_pool,
                                 ocpp::helpers::WorkerThreadPool&                worker_pool,
                                 const ocpp::messages::GenericMessagesConverter& messages_converter,
                                 ocpp::messages::GenericMessageSender&           msg_sender,
                                 IAuthentManager&                                authent_manager,
                                 IDataTransferManager&                           datatransfer_manager,
                                 ISecurityManager&                               security_manager)
    : m_ocpp_config(ocpp_config),
      m_events_handler(events_handler),
      m_worker_pool(worker_pool),
      m_messages_converter(messages_converter),
      m_msg_sender(msg_sender),
      m_authent_manager(authent_manager),
      m_security_manager(security_manager),
      m_last_csr(),
      m_csr_sign_retries(0),
      m_csr_timer(timer_pool, "ISO15118 CSR timer")
{
    datatransfer_manager.registerHandler(ISO15118_VENDOR_ID, *this);
}

/** @brief Destructor */
Iso15118Manager::~Iso15118Manager() { }

/** @brief Authorize an ISO15118 transaction */
ocpp::types::ocpp16::AuthorizationStatus Iso15118Manager::authorize(
    const ocpp::x509::Certificate&                                                  certificate,
    const std::string&                                                              id_token,
    const std::vector<ocpp::types::ocpp16::OcspRequestDataType>&                    cert_hash_data,
    ocpp::types::Optional<ocpp::types::ocpp16::AuthorizeCertificateStatusEnumType>& cert_status)
{
    LOG_INFO << "[ISO15118] Authorize : token = " << id_token;

    AuthorizationStatus status = AuthorizationStatus::Invalid;

    // Check certificate
    bool cert_valid = false;
    cert_valid      = m_events_handler.iso15118CheckEvCertificate(certificate);
    if (!cert_valid)
    {
        LOG_WARNING << "EV certificate couldn't be verified";
    }

    // Check offline status
    if (m_msg_sender.isConnected())
    {
        // Check if the certificate must be check by the Central System
        if (cert_valid || (!cert_valid && m_ocpp_config.centralContractValidationAllowed()))
        {
            // Prepare request
            Iso15118AuthorizeReq request;
            if (!cert_valid)
            {
                request.certificate.value().assign(certificate.pem());
            }
            request.idToken.assign(id_token);
            request.iso15118CertificateHashData = cert_hash_data;

            // Send request
            Iso15118AuthorizeConf response;
            if (send("Iso15118Authorize", ISO15118_AUTHORIZE_ACTION, request, response))
            {
                // Extract response
                cert_status = response.certificateStatus;
                status      = response.idTokenInfo.status;

                // Update cache
                m_authent_manager.iso15118Update(id_token, response.idTokenInfo);
            }
        }
    }
    else
    {
        // Check if offline validation is enabled
        if (m_ocpp_config.contractValidationOffline())
        {
            // Offline check
            status = m_authent_manager.iso15118Authorize(id_token);
        }
    }

    LOG_INFO << "[ISO15118] Authorize : " << AuthorizationStatusHelper.toString(status);

    return status;
}

/** @brief Get or update an ISO15118 EV certificate */
ocpp::types::ocpp16::Iso15118EVCertificateStatusEnumType Iso15118Manager::get15118EVCertificate(
    const std::string&                             iso15118_schema_version,
    ocpp::types::ocpp16::CertificateActionEnumType action,
    const std::string&                             exi_request,
    std::string&                                   exi_response)
{
    LOG_INFO << "[ISO15118] Get EV certificate : schema version = " << iso15118_schema_version
             << " - action = " << CertificateActionEnumTypeHelper.toString(action);

    Iso15118EVCertificateStatusEnumType result = Iso15118EVCertificateStatusEnumType::Failed;

    // Prepare request
    Get15118EVCertificateReq request;
    request.iso15118SchemaVersion.assign(iso15118_schema_version);
    request.action = action;
    request.exiRequest.assign(exi_request);

    // Send request
    Get15118EVCertificateConf response;
    if (send("Get15118EVCertificate", GET_15118_EV_CERTIFICATE_ACTION, request, response))
    {
        // Extract response
        exi_response = response.exiResponse;
        result       = response.status;
    }

    LOG_INFO << "[ISO15118] Get EV certificate : " << Iso15118EVCertificateStatusEnumTypeHelper.toString(result);

    return result;
}

/** @brief Get the status of an ISO15118 certificate */
ocpp::types::ocpp16::GetCertificateStatusEnumType Iso15118Manager::getCertificateStatus(
    const ocpp::types::ocpp16::OcspRequestDataType& ocsp_request, std::string& ocsp_result)
{
    LOG_INFO << "[ISO15118] Get certificate status : serial number = " << ocsp_request.serialNumber.c_str()
             << " - responder = " << ocsp_request.responderURL.c_str();

    GetCertificateStatusEnumType result = GetCertificateStatusEnumType::Failed;

    // Prepare request
    GetCertificateStatusReq request;
    request.ocspRequestData = ocsp_request;

    // Send request
    GetCertificateStatusConf response;
    if (send("GetCertificateStatus", GET_CERTIFICATE_STATUS_ACTION, request, response))
    {
        // Extract response
        ocsp_result = response.ocspResult.value();
        result      = response.status;
    }

    LOG_INFO << "[ISO15118] Get certificate status : " << GetCertificateStatusEnumTypeHelper.toString(result);

    return result;
}

/** @brief Send a CSR request to sign an ISO15118 certificate */
bool Iso15118Manager::signCertificate(const ocpp::x509::CertificateRequest& csr)
{
    LOG_INFO << "Sign certificate : valid = " << csr.isValid() << " - subject = " << csr.subjectString();

    // Reset retry counter
    m_last_csr         = csr.pem();
    m_csr_sign_retries = 0;
    m_csr_timer.stop();

    // Send request
    return sendSignCertificate();
}

// IDataTransferManager::IDataTransferHandler interface

/** @copydoc ocpp::types::ocpp16::DataTransferStatus IDataTransferHandler::onDataTransferRequest(const std::string&,
                                                                                         const std::string&,
                                                                                            const std::string&,
                                                                                            std::string&) */
ocpp::types::ocpp16::DataTransferStatus Iso15118Manager::onDataTransferRequest(const std::string& vendor_id,
                                                                               const std::string& message_id,
                                                                               const std::string& request_data,
                                                                               std::string&       response_data)
{
    (void)vendor_id;
    (void)request_data;
    (void)response_data;

    DataTransferStatus status = DataTransferStatus::Accepted;

    // Check if ISO15518 support is enabled
    if (m_ocpp_config.iso15118PnCEnabled())
    {
        // Known messages
        if (message_id == CERTIFICATE_SIGNED_ACTION)
        {
            // CertificateSigned
            status = handle<CertificateSignedReq, CertificateSignedConf>("CertificateSigned", request_data, response_data);
        }
        else if (message_id == DELETE_CERTIFICATE_ACTION)
        {
            // DeleteCertificate
            status = handle<DeleteCertificateReq, DeleteCertificateConf>("DeleteCertificate", request_data, response_data);
        }
        else if (message_id == ISO15118_GET_INSTALLED_CERTIFICATE_IDS_ACTION)
        {
            // GetInstalledCertificateIds
            status = handle<Iso15118GetInstalledCertificateIdsReq, Iso15118GetInstalledCertificateIdsConf>(
                "Iso15118GetInstalledCertificateIds", request_data, response_data);
        }
        else if (message_id == ISO15118_INSTALL_CERTIFICATE_ACTION)
        {
            // InstallCertificate
            status = handle<Iso15118InstallCertificateReq, Iso15118InstallCertificateConf>(
                "Iso15118InstallCertificate", request_data, response_data);
        }
        else if (message_id == ISO15118_TRIGGER_MESSAGE_ACTION)
        {
            // TriggerMessage
            status = handle<Iso15118TriggerMessageReq, Iso15118TriggerMessageConf>("Iso15118TriggerMessage", request_data, response_data);
        }
        else
        {
            // Unknown message
            LOG_WARNING << "[ISO15118] Unknown message : " << message_id << ", forwarding to user";
            status = m_events_handler.dataTransferRequested(vendor_id, message_id, request_data, response_data);
        }
    }
    else
    {
        // Not supported
        LOG_ERROR << "[ISO15118] Not supported : message_id = " << message_id;
        status = DataTransferStatus::UnknownVendorId;
    }

    return status;
}

/** @brief Handle a CertificateSigned request */
void Iso15118Manager::handle(const ocpp::messages::ocpp16::CertificateSignedReq& request,
                             ocpp::messages::ocpp16::CertificateSignedConf&      response)
{
    LOG_INFO << "[ISO15118] Certificate signed message received : certificate size = " << request.certificateChain.size();

    // Prepare response
    bool send_security_event = true;
    response.status          = CertificateSignedStatusEnumType::Rejected;

    // Check certificate's size
    if (request.certificateChain.size() < m_ocpp_config.certificateSignedMaxChainSize())
    {
        std::vector<Certificate> certificates;
        if (extractCertificates(request.certificateChain, certificates) && verifyCertificateChain(certificates))
        {
            // Notify new certificate
            if (m_events_handler.iso15118ChargePointCertificateReceived(certificates))
            {
                // Stop timeout timer
                m_csr_timer.stop();
                send_security_event = false;
                response.status     = CertificateSignedStatusEnumType::Accepted;
            }
        }
    }

    // Triggers a security event
    if (send_security_event)
    {
        m_security_manager.logSecurityEvent(SECEVT_INVALID_CHARGE_POINT_CERT, "");
    }

    LOG_INFO << "[ISO15118] Certificate signed message : " << CertificateSignedStatusEnumTypeHelper.toString(response.status);
}

/** @brief Handle a DeleteCertificate request */
void Iso15118Manager::handle(const ocpp::messages::ocpp16::DeleteCertificateReq& request,
                             ocpp::messages::ocpp16::DeleteCertificateConf&      response)
{
    LOG_INFO << "[ISO15118] Delete certificate request received : hashAlgorithm = "
             << HashAlgorithmEnumTypeHelper.toString(request.certificateHashData.hashAlgorithm)
             << " - issuerKeyHash = " << request.certificateHashData.issuerKeyHash.str()
             << " - issuerNameHash = " << request.certificateHashData.issuerNameHash.str()
             << " - serialNumber = " << request.certificateHashData.serialNumber.str();

    // Notify handler to delete the certificate
    response.status = m_events_handler.iso15118DeleteCertificate(request.certificateHashData.hashAlgorithm,
                                                                 request.certificateHashData.issuerNameHash,
                                                                 request.certificateHashData.issuerKeyHash,
                                                                 request.certificateHashData.serialNumber);

    LOG_INFO << "[ISO15118] Delete certificate : " << DeleteCertificateStatusEnumTypeHelper.toString(response.status);
}

/** @brief Handle an Iso15118GetInstalledCertificateIds request */
void Iso15118Manager::handle(const ocpp::messages::ocpp16::Iso15118GetInstalledCertificateIdsReq& request,
                             ocpp::messages::ocpp16::Iso15118GetInstalledCertificateIdsConf&      response)
{
    LOG_INFO << "[ISO15118] Get installed certificate ids request received : certificateType count = " << request.certificateType.size();

    // Prepare response
    response.status = GetInstalledCertificateStatusEnumType::NotFound;

    // Get certificate types
    bool v2g_root_certificate  = false;
    bool mo_root_certificate   = false;
    bool v2g_certificate_chain = false;
    bool oem_root_certificate  = false;
    if (request.certificateType.empty())
    {
        // All types requested
        v2g_root_certificate  = true;
        mo_root_certificate   = true;
        v2g_certificate_chain = true;
        oem_root_certificate  = true;
    }
    else
    {
        // Check selected types
        for (const GetCertificateIdUseEnumType& cert_type : request.certificateType)
        {
            switch (cert_type)
            {
                case GetCertificateIdUseEnumType::V2GRootCertificate:
                    v2g_root_certificate = true;
                    break;
                case GetCertificateIdUseEnumType::MORootCertificate:
                    mo_root_certificate = true;
                    break;
                case GetCertificateIdUseEnumType::OEMRootCertificate:
                    oem_root_certificate = true;
                    break;
                case GetCertificateIdUseEnumType::V2GCertificateChain:
                // Intended fallthrough
                default:
                    v2g_certificate_chain = true;
                    break;
            }
        }
    }

    // Notify handler to get the list of installed certificates
    std::vector<std::tuple<GetCertificateIdUseEnumType, Certificate, std::vector<Certificate>>> certificates;
    m_events_handler.iso15118GetInstalledCertificates(
        v2g_root_certificate, mo_root_certificate, v2g_certificate_chain, oem_root_certificate, certificates);
    if (!certificates.empty())
    {
        // Build an issuer lookup pool from all installed certificates returned by the handler.
        std::vector<const Certificate*> issuer_candidates;
        issuer_candidates.reserve(certificates.size() * 2u);
        for (const auto& [cert_type, certificate, child_certificates] : certificates)
        {
            (void)cert_type;
            if (certificate.isValid())
            {
                issuer_candidates.push_back(&certificate);
            }
            for (const auto& child_cert : child_certificates)
            {
                if (child_cert.isValid())
                {
                    issuer_candidates.push_back(&child_cert);
                }
            }
        }

        // Compute hashes for each certificate
        for (const auto& [cert_type, certificate, child_certificates] : certificates)
        {
            if (certificate.isValid())
            {
                response.certificateHashDataChain.emplace_back();
                CertificateHashDataChainType& hash_data = response.certificateHashDataChain.back();
                hash_data.certificateType               = cert_type;

                // Prefer explicit next cert in chain, otherwise resolve issuer from installed certificates.
                const Certificate* leaf_issuer = !child_certificates.empty() ? &child_certificates.front()
                                                                              : findIssuerCertificate(certificate, issuer_candidates);
                fillHashInfo(certificate, (leaf_issuer != nullptr) ? *leaf_issuer : certificate, hash_data.certificateHashData);

                for (std::size_t i = 0; i < child_certificates.size(); ++i)
                {
                    const Certificate& cert = child_certificates[i];
                    const Certificate* issuer_cert = (i + 1u < child_certificates.size())
                                                         ? &child_certificates[i + 1u]
                                                         : findIssuerCertificate(cert, issuer_candidates);
                    hash_data.childCertificateHashData.emplace_back();
                    fillHashInfo(cert, (issuer_cert != nullptr) ? *issuer_cert : cert, hash_data.childCertificateHashData.back());
                }
            }
        }
        if (!response.certificateHashDataChain.empty())
        {
            response.status = GetInstalledCertificateStatusEnumType::Accepted;
        }
    }

    LOG_INFO << "[ISO15118] Get installed certificate ids : status = "
             << GetInstalledCertificateStatusEnumTypeHelper.toString(response.status)
             << " - count = " << response.certificateHashDataChain.size();
}

/** @brief Handle an InstallCertificate request */
void Iso15118Manager::handle(const ocpp::messages::ocpp16::Iso15118InstallCertificateReq& request,
                             ocpp::messages::ocpp16::Iso15118InstallCertificateConf&      response)
{
    LOG_INFO << "[ISO15118] Install certificate request received : certificateType = "
             << InstallCertificateUseEnumTypeHelper.toString(request.certificateType)
             << " - certificate size = " << request.certificate.size();

    // Prepare response
    response.status = InstallCertificateStatusEnumType::Rejected;

    // Check certificate
    Certificate certificate(request.certificate.str());
    if (certificate.isValid())
    {
        // Notify new certificate
        response.status = m_events_handler.iso15118CertificateReceived(request.certificateType, certificate);
    }

    LOG_INFO << "Install certificate : " << InstallCertificateStatusEnumTypeHelper.toString(response.status);
}

/** @brief Handle a TriggerMessage request */
void Iso15118Manager::handle(const ocpp::messages::ocpp16::Iso15118TriggerMessageReq& request,
                             ocpp::messages::ocpp16::Iso15118TriggerMessageConf&      response)
{
    (void)request;

    m_worker_pool.run<void>(
        [this]
        {
            // To let some time for the trigger message reply
            std::this_thread::sleep_for(std::chrono::milliseconds(100u));

            // Notify application to generate a CSR
            std::string csr_pem;
            m_events_handler.iso15118GenerateCsr(csr_pem);

            // Create request
            CertificateRequest csr(csr_pem);

            // Send the request
            signCertificate(csr);
        });

    response.status = TriggerMessageStatusEnumType::Accepted;
}

/** @brief Fill hash information using certificate and its issuer certificate */
void Iso15118Manager::fillHashInfo(const ocpp::x509::Certificate& certificate,
                                   const ocpp::x509::Certificate& issuer_certificate,
                                   ocpp::types::ocpp16::CertificateHashDataType& info)
{
    // Compute hashes with SHA-256 algorithm
    Sha2 sha256;
    info.hashAlgorithm = HashAlgorithmEnumType::SHA256;
    sha256.compute(certificate.issuerDer().data(), certificate.issuerDer().size());
    info.issuerNameHash.assign(sha256.resultString());

    // issuerKeyHash must be computed from issuer certificate public key.
    sha256.compute(issuer_certificate.publicKey().data(), issuer_certificate.publicKey().size());
    info.issuerKeyHash.assign(sha256.resultString());
    info.serialNumber.assign(certificate.serialNumberHexString());
}

/** @brief Send a CSR request to sign an ISO15118 certificate */
bool Iso15118Manager::sendSignCertificate()
{
    LOG_INFO << "Sending sign certificate : retries = " << m_csr_sign_retries;

    GenericStatusEnumType result = GenericStatusEnumType::Rejected;

    // Prepare request
    SignCertificateReq request;
    request.csr.assign(m_last_csr);

    // Send request
    SignCertificateConf response;
    if (send("SignCertificate", SIGN_CERTIFICATE_ACTION, request, response))
    {
        // Extract response
        result = response.status;
        if (result == GenericStatusEnumType::Accepted)
        {
            // Start timer to retry if no response has been received
            if (m_csr_sign_retries < m_ocpp_config.certSigningRepeatTimes())
            {
                m_csr_sign_retries++;
                if (m_ocpp_config.certSigningWaitMinimum().count() != 0)
                {
                    LOG_INFO << "Setting timeout for sign certificate to " << m_ocpp_config.certSigningWaitMinimum().count() << "s";
                    m_csr_timer.setCallback(
                        [this]()
                        {
                            m_worker_pool.run<void>(
                                [this]
                                {
                                    LOG_ERROR << "Sign certificate timeout, triggering retry...";
                                    sendSignCertificate();
                                });
                        });
                    m_csr_timer.start(m_ocpp_config.certSigningWaitMinimum(), true);
                }
            }
            else
            {
                if (m_csr_sign_retries != 0u)
                {
                    LOG_WARNING << "Max sign certificate retries reached : " << m_ocpp_config.certSigningRepeatTimes();
                }
            }
        }
    }

    LOG_INFO << "Sign certificate : " << GenericStatusEnumTypeHelper.toString(result);

    return (result == GenericStatusEnumType::Accepted);
}

/** @brief Extract individual certificates from a PEM chain payload */
bool Iso15118Manager::extractCertificates(const std::string& pem_chain, std::vector<ocpp::x509::Certificate>& certificates)
{
    const std::string begin_marker = "-----BEGIN CERTIFICATE-----";
    const std::string end_marker   = "-----END CERTIFICATE-----";

    size_t pos = 0;
    while (pos < pem_chain.size())
    {
        size_t begin_pos = pem_chain.find(begin_marker, pos);
        if (begin_pos == std::string::npos)
        {
            break;
        }

        size_t end_pos = pem_chain.find(end_marker, begin_pos);
        if (end_pos == std::string::npos)
        {
            LOG_WARNING << "[ISO15118] Invalid certificate chain : missing END CERTIFICATE marker";
            return false;
        }
        end_pos += end_marker.size();

        Certificate certificate(pem_chain.substr(begin_pos, end_pos - begin_pos));
        if (!certificate.isValid())
        {
            LOG_WARNING << "[ISO15118] Invalid certificate found in certificate chain";
            return false;
        }

        certificates.push_back(certificate);
        pos = end_pos;
    }

    if (certificates.empty())
    {
        LOG_WARNING << "[ISO15118] Empty certificate chain";
        return false;
    }

    return true;
}

/** @brief Verify a certificate chain where first cert is leaf and others are CAs */
bool Iso15118Manager::verifyCertificateChain(const std::vector<ocpp::x509::Certificate>& certificates)
{
    if (!certificates.empty())
    {
        for (const auto& cert : certificates)
        {
            if (cert.isValid())
            {
            }
            else
            {
                return false;
            }

        }
    }

    return true;
}

/** @brief Find the issuer certificate by matching subject DN with issuer DN */
const ocpp::x509::Certificate* Iso15118Manager::findIssuerCertificate(const ocpp::x509::Certificate& certificate, const std::vector<const ocpp::x509::Certificate*>& candidates)
{
    for (const ocpp::x509::Certificate* candidate : candidates)
    {
        if ((candidate != nullptr) && (candidate->subjectString() == certificate.issuerString()))
        {
            return candidate;
        }
    }

    return nullptr;
}

} // namespace chargepoint
} // namespace ocpp
