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
 *      Fuzzes the byte-span operational-cert extractors:
 *      ExtractCATsFromOpCert, ExtractFabricIdFromCert, ExtractSubjectDNFromX509Cert,
 *      ExtractSKIDFromChipCert, ExtractAKIDFromChipCert, ExtractPublicKeyFromChipCert.
 *      These are reachable from FabricTable's AddNewFabric path on every NOC the
 *      fabric admin writes — direct attacker-controlled input post-CASE.
 */

#include <cstddef>
#include <cstdint>

#include <credentials/CHIPCert.h>
#include <lib/core/DataModelTypes.h>
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
        FabricId fabricId = 0;
        (void) ExtractFabricIdFromCert(span, &fabricId);
    }

    {
        NodeId nodeId     = 0;
        FabricId fabricId = 0;
        (void) ExtractNodeIdFabricIdFromOpCert(span, &nodeId, &fabricId);
    }

    {
        CATValues cats;
        (void) ExtractCATsFromOpCert(span, cats);
    }

    {
        ChipDN dn;
        (void) ExtractSubjectDNFromX509Cert(span, dn);
    }

    {
        ChipDN dn;
        (void) ExtractSubjectDNFromChipCert(span, dn);
    }

    {
        Credentials::P256PublicKeySpan key;
        (void) ExtractPublicKeyFromChipCert(span, key);
    }

    {
        CertificateKeyId skid;
        (void) ExtractSKIDFromChipCert(span, skid);
    }

    return 0;
}
