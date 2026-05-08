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
 *      Fuzzes the CHIP certificate validation paths that FuzzChipCert does
 *      NOT cover: ValidateChipRCAC, ValidateChipNetworkIdentity,
 *      ConvertChipCertToX509Cert (round-trip back to DER), DecodeChipDN,
 *      and the *FromOpCerts cross-cert helpers. These are reached during
 *      attestation and operational-cert validation.
 */

#include <cstddef>
#include <cstdint>

#include <credentials/CHIPCert.h>
#include <lib/core/TLVReader.h>
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

    (void) ValidateChipRCAC(span);

    {
        uint8_t keyIdBuf[chip::Credentials::kKeyIdentifierLength];
        MutableCertificateKeyId keyId(keyIdBuf);
        (void) ValidateChipNetworkIdentity(span, keyId);
    }

    {
        // Round-trip CHIP cert -> X.509 -> chip cert: stresses both encoder paths.
        uint8_t derBuf[1024];
        MutableByteSpan der(derBuf);
        (void) ConvertChipCertToX509Cert(span, der);
    }

    {
        TLV::TLVReader reader;
        reader.Init(data, len);
        if (reader.Next() == CHIP_NO_ERROR)
        {
            ChipDN dn;
            (void) DecodeChipDN(reader, dn);
        }
    }

    // OpCerts cross-validation: split input bytes between rcac and noc.
    if (len >= 2)
    {
        size_t mid = len / 2;
        ByteSpan rcac(data, mid);
        ByteSpan noc(data + mid, len - mid);

        CompressedFabricId compressedFabricId = 0;
        NodeId nodeId                         = 0;
        FabricId fabricId                     = 0;
        (void) ExtractNodeIdFabricIdCompressedFabricIdFromOpCerts(rcac, noc, compressedFabricId, nodeId, fabricId);
    }

    return 0;
}
