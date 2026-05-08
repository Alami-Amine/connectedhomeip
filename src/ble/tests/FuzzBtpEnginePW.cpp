/*
 *
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

/**
 *    @file
 *      Seeded FuzzTest harness for BtpEngine — BTP analogue of the
 *      WiFiPAFTP transport-level fuzzer. Uses real BTP fragment shapes
 *      as seeds so the mutator starts from valid header-flag combinations
 *      and explores the reorder-queue / ack-handling branches instead of
 *      bouncing off the header-validation gate.
 */

#include <cstdint>
#include <utility>
#include <vector>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

#include <ble/Ble.h>
#include <ble/BtpEngine.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <system/SystemPacketBuffer.h>

namespace {

using chip::Ble::BtpEngine;
using chip::Ble::SequenceNumber_t;
using chip::System::PacketBufferHandle;
using namespace fuzztest;

void EnsureInitialized()
{
    static const bool sInitialized = [] {
        VerifyOrDie(chip::Platform::MemoryInit() == CHIP_NO_ERROR);
        return true;
    }();
    (void) sInitialized;
}

// Real BTP fragment shapes covering the most interesting header-flag
// combinations: start, continue, end, start+end, ack-only, plus message-
// length field placement and out-of-order sequence numbers.
std::vector<std::vector<uint8_t>> BtpFragmentSeeds()
{
    return {
        // header flag bits: bit0=Start bit1=Continue bit2=End bit3=Ack
        { 0x05, 0x01, 0x01, 0x00, 0x00, 0xAA },             // start+end, seq 1, ack 0, msg len 5, payload 0xAA
        { 0x01, 0x00, 0x01, 0x00, 0x00, 0xDE, 0xAD },       // start, seq 1, no ack, msg len 0
        { 0x02, 0x02, 0xBE, 0xEF },                         // continue, seq 2
        { 0x04, 0x03, 0xCA, 0xFE },                         // end, seq 3
        { 0x08, 0x02 },                                     // ack-only, ack 2
        { 0x05, 0x01, 0x05, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF }, // start+end, seq 5 (out of order), ack 0
        { 0x09, 0x00, 0x07, 0x00, 0x00, 0x01 },             // start with ack
    };
}

// Property: BtpEngine::HandleCharacteristicReceived must never crash
// regardless of fragment contents or arrival ordering.
void BtpEngineDoesNotCrash(bool expectFirstAck, const std::vector<uint8_t> & frag0,
                           const std::vector<uint8_t> & frag1, const std::vector<uint8_t> & frag2,
                           const std::vector<uint8_t> & frag3)
{
    EnsureInitialized();

    BtpEngine engine;
    if (engine.Init(nullptr, expectFirstAck) != CHIP_NO_ERROR)
    {
        return;
    }

    for (const auto * frag : { &frag0, &frag1, &frag2, &frag3 })
    {
        auto buf = PacketBufferHandle::NewWithData(frag->data(), frag->size());
        if (buf.IsNull())
            continue;

        SequenceNumber_t receivedAck = 0;
        bool didReceiveAck           = false;
        RETURN_SAFELY_IGNORED engine.HandleCharacteristicReceived(std::move(buf), receivedAck, didReceiveAck);

        if (engine.RxState() == BtpEngine::kState_Error)
            break;
    }
}

FUZZ_TEST(FuzzBtpEnginePW, BtpEngineDoesNotCrash)
    .WithDomains(
        Arbitrary<bool>(),
        Arbitrary<std::vector<uint8_t>>().WithSeeds(BtpFragmentSeeds()),
        Arbitrary<std::vector<uint8_t>>().WithSeeds(BtpFragmentSeeds()),
        Arbitrary<std::vector<uint8_t>>().WithSeeds(BtpFragmentSeeds()),
        Arbitrary<std::vector<uint8_t>>().WithSeeds(BtpFragmentSeeds()));

} // namespace
