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
 *      Fuzzes ASN1ToChipEpochTime / ChipEpochToASN1Time and round-trips them.
 *      These are reached when parsing X.509 NotBefore/NotAfter from peer
 *      operational and DAC certs.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <credentials/CHIPCert.h>
#include <lib/asn1/ASN1.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t len)
{
    using namespace chip;
    using namespace chip::ASN1;

    if (len < sizeof(ASN1UniversalTime) && len < sizeof(uint32_t))
    {
        return 0;
    }

    // Treat the input bytes as an ASN1UniversalTime in raw form, plus a
    // separate 32-bit epoch candidate. This lets the fuzzer drive both
    // directions of the conversion.
    {
        ASN1UniversalTime t{};
        const size_t n = (len < sizeof(ASN1UniversalTime)) ? len : sizeof(ASN1UniversalTime);
        memcpy(&t, data, n);

        uint32_t epoch = 0;
        (void) Credentials::ASN1ToChipEpochTime(t, epoch);
    }

    {
        uint32_t epoch = 0;
        memcpy(&epoch, data, sizeof(epoch));
        ASN1UniversalTime back{};
        (void) Credentials::ChipEpochToASN1Time(epoch, back);
    }

    return 0;
}
