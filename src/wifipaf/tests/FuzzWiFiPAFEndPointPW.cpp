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

#include <cstdint>
#include <utility>
#include <vector>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

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

// Reuses the friended name `TestWiFiPAFLayer` from WiFiPAFLayer.h /
// WiFiPAFEndPoint.h to unlock the private members needed to bring up an
// endpoint without the full handshake. Separate executable from the gtest-
// based TestWiFiPAFLayer TU, so no ODR collision.
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

    // Work around WiFiPAFEndPoint::Free() not clearing mWiFiPafLayer, which
    // would permanently occupy the pool slot across fuzz iterations.
    static void ForceReleaseEndpoint(WiFiPAFEndPoint * ep)
    {
        if (ep != nullptr)
        {
            ep->mWiFiPafLayer = nullptr;
        }
    }

    // Delegate sink: absorb everything, don't reenter the layer.
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
using chip::WiFiPAF::WiFiPafRole;
using chip::WiFiPAF::WiFiPAFSession;

using namespace fuzztest;

// The endpoint's timers live on SystemLayer. Init once, Shutdown at exit;
// same cleanup pattern as FuzzWiFiPAFEndPoint.cpp (libFuzzer variant).
void EnsureInitialized()
{
    static const bool sInitialized = [] {
        VerifyOrDie(chip::Platform::MemoryInit() == CHIP_NO_ERROR);
        VerifyOrDie(chip::DeviceLayer::SystemLayer().Init() == CHIP_NO_ERROR);
        std::atexit([] { chip::DeviceLayer::SystemLayer().Shutdown(); });
        return true;
    }();
    (void) sInitialized;
}

auto AnyRole()
{
    return ElementOf<WiFiPafRole>({ kWiFiPafRole_Publisher, kWiFiPafRole_Subscriber });
}

auto AnyStartState()
{
    return ElementOf<uint8_t>({ static_cast<uint8_t>(WiFiPAFEndPoint::kState_Ready),
                                static_cast<uint8_t>(WiFiPAFEndPoint::kState_Connecting),
                                static_cast<uint8_t>(WiFiPAFEndPoint::kState_Connected) });
}

// Known-valid PAFTP fragments extracted from TestWiFiPAFLayer. FuzzTest uses
// these as corpus starting points and mutates around them — letting the
// fuzzer reach post-handshake code paths far faster than random bytes.
std::vector<std::vector<uint8_t>> CapabilitySeeds()
{
    return {
        { 0x65, 0x6c, 0x04, 0x00, 0x00, 0x00, 0x5e, 0x01, 0x06 }, // cap request
        { 0x65, 0x6c, 0x04, 0x5b, 0x01, 0x06 },                   // cap response
    };
}

std::vector<std::vector<uint8_t>> PaftpSeeds()
{
    return {
        { 0x05, 0x01, 0x01, 0x00, 0x00 }, // start+end, seq 1, ack
        { 0x05, 0x01, 0x03, 0x00, 0x00 }, // out-of-order seq 3
        { 0x01, 0x00, 0x01, 0x00, 0x00 }, // start only, no ack
        { 0x04, 0x01, 0x02, 0x00 },       // end only, seq 2
    };
}

// Property: Receive() must never crash or OOB-access regardless of fragment
// contents, role, session identity, or starting endpoint state. FuzzTest
// mutates each fragment independently and shrinks the failing input down
// to the minimal triggering sequence.
void EndpointReceiveDoesNotCrash(WiFiPafRole role, uint8_t startState, uint32_t sessionId, uint16_t discriminator,
                                 const std::vector<uint8_t> & frag0, const std::vector<uint8_t> & frag1,
                                 const std::vector<uint8_t> & frag2, const std::vector<uint8_t> & frag3)
{
    EnsureInitialized();

    TestWiFiPAFLayer harness;
    ASSERT_EQ(harness.FuzzSetup(), CHIP_NO_ERROR);

    WiFiPAFSession session = {};
    session.role           = role;
    session.id             = sessionId == 0 ? 1 : sessionId;
    session.peer_id        = 1;
    session.nodeId         = 1;
    session.discriminator  = discriminator;

    WiFiPAFEndPoint * ep = nullptr;
    if (harness.NewEndPoint(&ep, session, role) != CHIP_NO_ERROR || ep == nullptr)
    {
        harness.FuzzTeardown();
        return;
    }
    RETURN_SAFELY_IGNORED harness.AddPafSession(PafInfoAccess::kAccSessionId, session);
    ep->mState = static_cast<decltype(ep->mState)>(startState);
    harness.SetWiFiPAFState(startState == WiFiPAFEndPoint::kState_Connected ? State::kConnected : State::kInitialized);

    for (const auto * frag : { &frag0, &frag1, &frag2, &frag3 })
    {
        auto buf = PacketBufferHandle::NewWithData(frag->data(), frag->size());
        if (buf.IsNull())
        {
            continue;
        }
        RETURN_SAFELY_IGNORED ep->Receive(std::move(buf));
        if (ep->mState == WiFiPAFEndPoint::kState_Closed || ep->mState == WiFiPAFEndPoint::kState_Aborting)
        {
            break;
        }
    }

    harness.FuzzTeardown();
    TestWiFiPAFLayer::ForceReleaseEndpoint(ep);
}

FUZZ_TEST(FuzzWiFiPAFEndPointPW, EndpointReceiveDoesNotCrash)
    .WithDomains(
        // role
        AnyRole(),
        // startState (Ready / Connecting / Connected)
        AnyStartState(),
        // sessionId — local routing id
        Arbitrary<uint32_t>(),
        // discriminator — Matter 12-bit discriminator plus slack
        Arbitrary<uint16_t>(),
        // frag0: handshake slot — seeded with capabilities request/response
        Arbitrary<std::vector<uint8_t>>().WithSeeds(CapabilitySeeds()),
        // frag1-3: PAFTP data-phase slots — seeded with real fragment shapes
        Arbitrary<std::vector<uint8_t>>().WithSeeds(PaftpSeeds()),
        Arbitrary<std::vector<uint8_t>>().WithSeeds(PaftpSeeds()),
        Arbitrary<std::vector<uint8_t>>().WithSeeds(PaftpSeeds()));

} // namespace
