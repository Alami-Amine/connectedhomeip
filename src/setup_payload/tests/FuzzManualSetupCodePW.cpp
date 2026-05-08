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
 *      Seeded FuzzTest harness for ManualSetupPayloadParser. Combines:
 *      - A seeded `Arbitrary<std::string>` with several real generator-emitted
 *        manual setup codes so the mutator stays close to the digit-pattern grammar
 *      - A property-based generator->parser->equality round-trip driven by structured
 *        domains (passcode, discriminator, vid, pid).
 */

#include <string>
#include <vector>

#include <lib/support/CHIPMem.h>
#include <setup_payload/ManualSetupPayloadGenerator.h>
#include <setup_payload/ManualSetupPayloadParser.h>
#include <setup_payload/SetupPayload.h>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

namespace {

using namespace chip;
using namespace fuzztest;

std::string GenerateManualCode(uint32_t passcode, uint8_t shortDiscrim, uint16_t vid, uint16_t pid)
{
    SetupPayload payload;
    payload.setUpPINCode = passcode & ((1u << 27) - 1);
    payload.discriminator.SetShortValue(shortDiscrim & 0x0F);
    payload.vendorID  = vid;
    payload.productID = pid;
    payload.commissioningFlow = CommissioningFlow::kStandard;

    std::string code;
    if (ManualSetupPayloadGenerator(payload).payloadDecimalStringRepresentation(code) != CHIP_NO_ERROR)
    {
        return {};
    }
    return code;
}

std::vector<std::string> ManualSetupCodeSeeds()
{
    Platform::MemoryInit();
    std::vector<std::string> seeds;

    auto add = [&](std::string s) {
        if (!s.empty())
            seeds.push_back(std::move(s));
    };

    add(GenerateManualCode(20202021, 0xF, 0xFFF1, 0x8001));
    add(GenerateManualCode(11223344, 0x3, 0x1234, 0x5678));
    add(GenerateManualCode(00000000, 0x0, 0x0000, 0x0000));
    add(GenerateManualCode(0x07FFFFFF, 0xF, 0xFFFF, 0xFFFF));
    add(GenerateManualCode(12345678, 0x5, 0xAAAA, 0xBBBB));

    Platform::MemoryShutdown();
    return seeds;
}

void ManualSetupCodeParserFuzz(const std::string & code)
{
    Platform::MemoryInit();
    SetupPayload payload;
    RETURN_SAFELY_IGNORED ManualSetupPayloadParser(code).populatePayload(payload);
    Platform::MemoryShutdown();
}

FUZZ_TEST(ManualSetupCode, ManualSetupCodeParserFuzz)
    .WithDomains(Arbitrary<std::string>().WithSeeds(ManualSetupCodeSeeds()));

// Property-based round-trip: generate a code from structured fields,
// parse it, assert the user-relevant fields survive.
void ManualSetupCodeRoundtripFuzz(uint32_t passcode, uint8_t shortDiscrim, uint16_t vid, uint16_t pid)
{
    Platform::MemoryInit();

    const uint32_t boundedPasscode = passcode & ((1u << 27) - 1);
    const uint8_t boundedDiscrim   = shortDiscrim & 0x0F;

    SetupPayload original;
    original.setUpPINCode = boundedPasscode;
    original.discriminator.SetShortValue(boundedDiscrim);
    original.vendorID  = vid;
    original.productID = pid;
    original.commissioningFlow = CommissioningFlow::kStandard;

    std::string code;
    if (ManualSetupPayloadGenerator(original).payloadDecimalStringRepresentation(code) != CHIP_NO_ERROR)
    {
        Platform::MemoryShutdown();
        return;
    }

    SetupPayload parsed;
    ASSERT_EQ(ManualSetupPayloadParser(code).populatePayload(parsed), CHIP_NO_ERROR);
    ASSERT_EQ(parsed.setUpPINCode, original.setUpPINCode);
    ASSERT_EQ(parsed.discriminator.GetShortValue(), original.discriminator.GetShortValue());

    Platform::MemoryShutdown();
}

FUZZ_TEST(ManualSetupCode, ManualSetupCodeRoundtripFuzz)
    .WithDomains(Arbitrary<uint32_t>(), Arbitrary<uint8_t>(), Arbitrary<uint16_t>(), Arbitrary<uint16_t>());

} // namespace
