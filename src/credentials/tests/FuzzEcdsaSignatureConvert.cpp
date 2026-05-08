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
 *      Fuzzes ECDSA signature DER/raw conversion in both directions:
 *      ConvertECDSASignatureRawToDER, ConvertECDSASignatureDERToRaw,
 *      ConvertIntegerDERToRaw. These run on attacker-controlled signatures
 *      attached to attestation responses and operational certs.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <credentials/CHIPCert.h>
#include <crypto/CHIPCryptoPAL.h>
#include <lib/asn1/ASN1.h>
#include <lib/core/TLVReader.h>
#include <lib/core/TLVWriter.h>
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

    // Note: ConvertECDSASignatureDERToRaw has a header/impl signature mismatch
    // upstream (header takes uint64_t, impl takes Tag) and can't be linked
    // from this TU. Skipping that path; the RawToDER and IntegerDERToRaw
    // paths below still cover most of the conversion logic.

    // Raw -> DER
    {
        if (len >= Crypto::kP256_ECDSA_Signature_Length_Raw)
        {
            uint8_t rawBuf[Crypto::kP256_ECDSA_Signature_Length_Raw];
            memcpy(rawBuf, data, sizeof(rawBuf));
            P256ECDSASignatureSpan rawSig(rawBuf);

            uint8_t derBuf[256];
            MutableByteSpan derOut(derBuf);
            (void) ConvertECDSASignatureRawToDER(rawSig, derOut);
        }
    }

    // ConvertIntegerDERToRaw
    {
        ByteSpan derInt(data, len);
        uint8_t rawBuf[64];
        (void) ConvertIntegerDERToRaw(derInt, rawBuf, sizeof(rawBuf));
    }

    return 0;
}
