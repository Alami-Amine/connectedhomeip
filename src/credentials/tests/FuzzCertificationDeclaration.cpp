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
 *      Fuzzes the Certification Declaration TLV decoder paths:
 *      DecodeCertificationElements (both PID-list and without-PIDs variants),
 *      CertificationElementsDecoder::IsProductIdIn,
 *      CertificationElementsDecoder::HasAuthorizedPAA. These run on
 *      attacker-controlled CD blob extracted from the attestation elements.
 */

#include <cstddef>
#include <cstdint>

#include <credentials/CertificationDeclaration.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/Span.h>

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
    using namespace chip::Credentials;

    (void) EnsureInitialized();

    ByteSpan span(data, len);

    {
        CertificationElements out{};
        (void) DecodeCertificationElements(span, out);
    }

    {
        CertificationElementsWithoutPIDs out{};
        (void) DecodeCertificationElements(span, out);
    }

    {
        CertificationElementsDecoder dec;
        (void) dec.IsProductIdIn(span, 0xBEEF);
        ByteSpan paa(reinterpret_cast<const uint8_t *>("AUTHORIZED-PAA-PROBE"), 20);
        (void) dec.HasAuthorizedPAA(span, paa);
    }

    return 0;
}
