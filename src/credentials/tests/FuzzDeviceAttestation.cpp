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
 *      Fuzzes the Device Attestation TLV deconstructors:
 *      DeconstructAttestationElements, DeconstructNOCSRElements,
 *      CountVendorReservedElementsInDA. These run on attacker-controlled
 *      attestation/NOCSR blobs received during commissioning before
 *      attestation signature verification.
 */

#include <cstddef>
#include <cstdint>

#include <credentials/DeviceAttestationConstructor.h>
#include <credentials/DeviceAttestationVendorReserved.h>
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
        ByteSpan certDecl;
        ByteSpan attestationNonce;
        uint32_t timestamp = 0;
        ByteSpan firmwareInfo;
        DeviceAttestationVendorReservedDeconstructor vendorReserved;

        (void) DeconstructAttestationElements(span, certDecl, attestationNonce, timestamp, firmwareInfo, vendorReserved);
    }

    {
        size_t count = 0;
        (void) CountVendorReservedElementsInDA(span, count);
    }

    {
        ByteSpan csr;
        ByteSpan csrNonce;
        ByteSpan vr1, vr2, vr3;
        (void) DeconstructNOCSRElements(span, csr, csrNonce, vr1, vr2, vr3);
    }

    return 0;
}
