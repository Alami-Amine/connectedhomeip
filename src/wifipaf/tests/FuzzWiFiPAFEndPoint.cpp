/*
 *    Copyright (c) 2026 Project CHIP Authors
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <utility>

#include <lib/core/CHIPError.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <platform/CHIPDeviceLayer.h>
#include <system/SystemLayer.h>
#include <system/SystemPacketBuffer.h>
#include <wifipaf/WiFiPAFEndPoint.h>
#include <wifipaf/WiFiPAFLayer.h>
#include <wifipaf/WiFiPAFLayerDelegate.h>

namespace chip {
namespace WiFiPAF {

// Reuses the name declared as `friend class TestWiFiPAFLayer` in
// WiFiPAFLayer.h / WiFiPAFEndPoint.h, which grants access to the private
// members needed to set up and tear down an endpoint without going through
// the full handshake. This translation unit links into a separate fuzz
// executable from the unit-test TU of the same class name, so there is no
// ODR collision.
class TestWiFiPAFLayer : public WiFiPAFLayer, private WiFiPAFLayerDelegate
{
public:
    CHIP_ERROR FuzzSetup()
    {
        ReturnErrorOnFailure(Init(&DeviceLayer::SystemLayer()));
        mWiFiPAFTransport = this;
        return CHIP_NO_ERROR;
    }

    void FuzzTeardown()
    {
        // Shutdown must run while mWiFiPAFTransport is still valid: it closes
        // open endpoints, and FinalizeClose dereferences the transport to
        // deliver WiFiPAFCloseSession. Null the transport only afterwards.
        Shutdown();
        mWiFiPAFTransport = nullptr;
    }

    // Work around the fact that WiFiPAFEndPoint::Free() does not clear
    // mWiFiPafLayer, which leaves the pool slot permanently occupied and
    // would cause "endpoint pool FULL" on every subsequent fuzz iteration.
    static void ForceReleaseEndpoint(WiFiPAFEndPoint * ep)
    {
        if (ep != nullptr)
        {
            ep->mWiFiPafLayer = nullptr;
        }
    }

    // Delegate sink: swallow everything, no re-entry into the layer.
    CHIP_ERROR WiFiPAFMessageReceived(WiFiPAFSession &, System::PacketBufferHandle &&) override { return CHIP_NO_ERROR; }
    CHIP_ERROR WiFiPAFMessageSend(WiFiPAFSession &, System::PacketBufferHandle &&) override { return CHIP_NO_ERROR; }
    CHIP_ERROR WiFiPAFCloseSession(WiFiPAFSession &) override { return CHIP_NO_ERROR; }
    bool WiFiPAFResourceAvailable() override { return true; }
};

} // namespace WiFiPAF
} // namespace chip

namespace {

using chip::System::PacketBufferHandle;
using chip::WiFiPAF::kWiFiPafRole_Publisher;
using chip::WiFiPAF::kWiFiPafRole_Subscriber;
using chip::WiFiPAF::PafInfoAccess;
using chip::WiFiPAF::State;
using chip::WiFiPAF::TestWiFiPAFLayer;
using chip::WiFiPAF::WiFiPAFEndPoint;
using chip::WiFiPAF::WiFiPAFSession;

// SystemLayer is needed for the endpoint's timers. Init it once and register
// a Shutdown at process exit; otherwise the state-machine VerifyOrDie fires
// during global destruction (same failure we hit with the TP harness).
bool EnsureInitialized()
{
    static const bool sInitialized = [] {
        VerifyOrDie(chip::Platform::MemoryInit() == CHIP_NO_ERROR);
        VerifyOrDie(chip::DeviceLayer::SystemLayer().Init() == CHIP_NO_ERROR);
        std::atexit([] { chip::DeviceLayer::SystemLayer().Shutdown(); });
        return true;
    }();
    return sInitialized;
}

} // namespace

// Fuzzer input layout:
//   byte 0 : config byte
//              bit 0 -> role (1 = Subscriber, 0 = Publisher)
//              bit 1 -> start state (1 = Ready, 0 = Connected)
//   rest    : sequence of <2-byte BE length><payload> fragments, each fed to
//             WiFiPAFEndPoint::Receive.
//
// Starting in Connected exercises the reassembly / reorder-queue / ack state
// machine. Starting in Ready routes the first fragments through the
// capabilities request/response parsers.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)
{
    (void) EnsureInitialized();

    if (size < 1)
    {
        return 0;
    }

    const uint8_t config     = data[0];
    const auto role          = (config & 0x01) ? kWiFiPafRole_Subscriber : kWiFiPafRole_Publisher;
    const uint8_t startState = (config & 0x02) ? WiFiPAFEndPoint::kState_Ready : WiFiPAFEndPoint::kState_Connected;

    TestWiFiPAFLayer harness;
    if (harness.FuzzSetup() != CHIP_NO_ERROR)
    {
        return 0;
    }

    WiFiPAFSession session = {};
    session.role           = role;
    session.id             = 1;
    session.peer_id        = 1;
    session.nodeId         = 1;
    session.discriminator  = 0xF00;

    WiFiPAFEndPoint * ep = nullptr;
    if (harness.NewEndPoint(&ep, session, role) != CHIP_NO_ERROR || ep == nullptr)
    {
        harness.FuzzTeardown();
        return 0;
    }
    (void) harness.AddPafSession(PafInfoAccess::kAccSessionId, session);
    ep->mState = static_cast<decltype(ep->mState)>(startState);
    harness.SetWiFiPAFState(startState == WiFiPAFEndPoint::kState_Connected ? State::kConnected : State::kInitialized);

    size_t cursor = 1;
    while (cursor + 2 <= size)
    {
        uint16_t fragLen = static_cast<uint16_t>((data[cursor] << 8) | data[cursor + 1]);
        cursor += 2;

        const size_t available = size - cursor;
        if (fragLen > available)
        {
            fragLen = static_cast<uint16_t>(available);
        }

        auto buf = PacketBufferHandle::NewWithData(data + cursor, fragLen);
        cursor += fragLen;
        if (buf.IsNull())
        {
            break;
        }

        (void) ep->Receive(std::move(buf));

        if (ep->mState == WiFiPAFEndPoint::kState_Closed || ep->mState == WiFiPAFEndPoint::kState_Aborting)
        {
            break;
        }
    }

    harness.FuzzTeardown();
    TestWiFiPAFLayer::ForceReleaseEndpoint(ep);
    return 0;
}
