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

#ifndef OPENOCPP_IMESSAGESENDER_H
#define OPENOCPP_IMESSAGESENDER_H

#include "EnumToStringFromString.h"
#include "GenericMessagesConverter.h"
#include "IMessagesValidator.h"
#include "IRequestFifo.h"
#include "IRpc.h"

namespace ocpp
{
namespace messages
{

/** @brief Result of of a call request */
enum class CallResult
{
    /** @brief Message has been sent and a response has been received */
    Ok,
    /** @brief Message will be sent later */
    Delayed,
    /** @brief Message cannot be send or no response has been received */
    Failed,
    /** @brief A call error message has been received */
    Error
};

/** @brief Helper to convert a CallResult enum to string */
extern const ocpp::types::EnumToStringFromString<CallResult> CallResultHelper;

/** @brief Generic message sender with C++ data type to JSON conversion */
class IMessageSender
{
  public:
    /** @brief Destructor */
    virtual ~IMessageSender() { }

    /**
     * @brief Indicate if the connection with the central system is active
     * @return true if the connection is active, false otherwise
     */
    virtual bool isConnected() const = 0;

    /**
     * @brief Set the call request timeout
     * @param timeout New timeout value
     */
    virtual void setTimeout(std::chrono::milliseconds timeout) = 0;
};

} // namespace messages
} // namespace ocpp

#endif // OPENOCPP_GENERICMESSAGESENDER_H

