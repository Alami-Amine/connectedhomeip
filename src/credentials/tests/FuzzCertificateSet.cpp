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
 *      Fuzzes ChipCertificateSet::LoadCert — the chain-validation entry point
 *      called by FabricTable when installing operational certs and during
 *      VendorIdVerificationClient. Drives both the ByteSpan and the
 *      TLVReader overloads, with a mix of decode-flag combinations.
 */

#include <cstddef>
#include <cstdint>

#include <credentials/CHIPCertificateSet.h>
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

    if (len < 1)
    {
        return 0;
    }

    // Cycle through all CertDecodeFlags combinations the fuzzer chooses.
    BitFlags<CertDecodeFlags> flags;
    flags.SetRaw(data[0]);

    ByteSpan span(data + 1, len - 1);

    {
        ChipCertificateSet certs;
        if (certs.Init(/* maxCerts */ 4) == CHIP_NO_ERROR)
        {
            (void) certs.LoadCert(span, flags);
            certs.Release();
        }
    }

    {
        ChipCertificateSet certs;
        if (certs.Init(4) == CHIP_NO_ERROR)
        {
            TLV::TLVReader reader;
            reader.Init(span.data(), span.size());
            if (reader.Next() == CHIP_NO_ERROR)
            {
                (void) certs.LoadCert(reader, flags, span);
            }
            certs.Release();
        }
    }

    return 0;
}
