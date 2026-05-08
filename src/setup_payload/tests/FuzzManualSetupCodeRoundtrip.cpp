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
 *      Property-based round-trip fuzzer: takes fuzz input as the *fields* of
 *      a SetupPayload, generates the manual setup code, parses it back, and
 *      asserts equality of the user-relevant fields. Catches encoder/decoder
 *      mismatches that pure parsing fuzzers miss.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <setup_payload/ManualSetupPayloadGenerator.h>
#include <setup_payload/ManualSetupPayloadParser.h>
#include <setup_payload/SetupPayload.h>

namespace {

bool EnsureInitialized()
{
    static const bool sInitialized = [] {
        VerifyOrDie(chip::Platform::MemoryInit() == CHIP_NO_ERROR);
        return true;
    }();
    return sInitialized;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t len)
{
    using namespace chip;

    (void) EnsureInitialized();

    // Pull structured fuzz inputs out of the input stream.
    if (len < sizeof(uint32_t) * 2 + 2)
    {
        return 0;
    }

    uint32_t passcode    = 0;
    uint16_t discrim     = 0;
    uint16_t vid         = 0;
    uint16_t pid         = 0;
    uint8_t versionRaw   = 0;
    size_t off           = 0;
    memcpy(&passcode, data + off, sizeof(passcode));
    off += sizeof(passcode);
    memcpy(&discrim, data + off, sizeof(discrim));
    off += sizeof(discrim);
    if (len > off + sizeof(vid))
    {
        memcpy(&vid, data + off, sizeof(vid));
        off += sizeof(vid);
    }
    if (len > off + sizeof(pid))
    {
        memcpy(&pid, data + off, sizeof(pid));
        off += sizeof(pid);
    }
    if (len > off)
    {
        versionRaw = data[off];
    }

    SetupPayload original;
    original.setUpPINCode  = passcode & ((1u << 27) - 1);
    original.discriminator.SetShortValue(discrim & 0x0F);
    original.vendorID      = vid;
    original.productID     = pid;
    original.version       = versionRaw & 0x07;

    std::string code;
    ManualSetupPayloadGenerator generator(original);
    if (generator.payloadDecimalStringRepresentation(code) != CHIP_NO_ERROR)
    {
        return 0;
    }

    SetupPayload parsed;
    ManualSetupPayloadParser parser(code);
    if (parser.populatePayload(parsed) != CHIP_NO_ERROR)
    {
        // Generator produced something the parser cannot read: that itself
        // is a roundtrip bug.
        VerifyOrDie(false);
    }

    // Manual codes carry a subset of fields. Discriminator is short (4-bit).
    VerifyOrDie(parsed.setUpPINCode == original.setUpPINCode);
    VerifyOrDie(parsed.discriminator.GetShortValue() == original.discriminator.GetShortValue());

    return 0;
}
