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

#ifndef OPENOCPP_OCPP20_TXSTARTSTOPTYPE_H
#define OPENOCPP_OCPP20_TXSTARTSTOPTYPE_H

#include "EnumToStringFromString.h"

namespace ocpp
{
namespace types
{
namespace ocpp20
{

/** @brief Points used to marks the start of a transaction */
enum class TxStartStopPointType
{
    /** @brief An object (probably an EV) is detected in the parking/charging bay. */
    ParkingBayOccupancy,
    /**
     * @brief Both ends of the Charging Cable have been connected
     * (if this can be detected, else detection of a cable being plugged into
     * the socket), or for wireless charging:
     * initial communication between EVSE and EV is established.
     */
    EVConnected,
    /**
     * @brief Driver or EV has been authorized, this can also be some form of
     * anonymous authorization like a start button.
     */
    Authorized,
    /**
     * @brief All preconditions for charging have been met, power can flow. This
     * event is the logical AND of EVConnected and Authorized and
     * should be used if a transaction is supposed to start when EV is
     * connected and authorized. Despite its name, this event is not
     * related to the state of the power relay.
     *
     * @note There may be situations where PowerPathClosed does not
     * imply that charging starts at that moment, e.g. because of delayed
     * charging or a battery that is too hot.
     */
    PowerPathClosed,
    /**
     * @brief Energy is being transferred between EV and EVSE.
     * @note Energy is not being transferred between EV and EVSE.
     * This is not recommended to use as a TxStopPoint, because it
     * will stop the transaction as soon as EV or EVSE (temporarily)
     * suspend the charging.
     */
    EnergyTransfer,
    /**
     * @brief The moment when the signed meter value is received from the
     * fiscal meter, that is used in the TransactionEventRequest with
     * context = Transaction.Begin and triggerReason = SignedDataReceived.
     * This TxStartPoint might be applicable when legislation exists that only
     * allows a billable transaction to start when the first signed meter value
     * has been received.
     * @note This condition has no meaning as a TxStopPoint and should not
     * be used as such.
     */
    DataSigned
};

/** @brief Helper to convert a TxStartPointType enum to string */
extern const EnumToStringFromString<TxStartStopPointType> TxStartStopPointTypeHelper;

} // namespace ocpp20
} // namespace types
} // namespace ocpp

#endif // OPENOCPP_OCPP20_TXSTARTSTOPTYPE_H