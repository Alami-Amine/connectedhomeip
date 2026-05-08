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
 *      Fuzzes QRCodeSetupPayloadParser::populatePayload(s) — the full QR-code
 *      pipeline above the Base38 decoder, including TLV optional-data parsing.
 */

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <setup_payload/QRCodeSetupPayloadParser.h>
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
    (void) EnsureInitialized();

    std::string qr(reinterpret_cast<const char *>(data), len);

    {
        chip::QRCodeSetupPayloadParser parser(qr);
        chip::SetupPayload payload;
        (void) parser.populatePayload(payload);
    }
    {
        chip::QRCodeSetupPayloadParser parser(std::move(qr));
        std::vector<chip::SetupPayload> payloads;
        (void) parser.populatePayloads(payloads);
    }

    return 0;
}
