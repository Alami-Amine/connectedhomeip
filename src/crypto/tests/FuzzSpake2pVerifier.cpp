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
 *      Fuzzes Spake2pVerifier::Deserialize plus a Serialize round-trip.
 *      The verifier is loaded from the persistence layer during PASE
 *      commissioning; its raw bytes pass through Deserialize.
 */

#include <cstddef>
#include <cstdint>

#include <crypto/CHIPCryptoPAL.h>
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
    using namespace chip::Crypto;

    (void) EnsureInitialized();

    chip::ByteSpan in(data, len);

    Spake2pVerifier verifier;
    if (verifier.Deserialize(in) != CHIP_NO_ERROR)
    {
        return 0;
    }

    // Round-trip: re-serialize and assert equality.
    uint8_t outBuf[kSpake2p_VerifierSerialized_Length];
    chip::MutableByteSpan out(outBuf);
    if (verifier.Serialize(out) != CHIP_NO_ERROR)
    {
        return 0;
    }

    VerifyOrDie(out.size() == kSpake2p_VerifierSerialized_Length);
    if (in.size() >= kSpake2p_VerifierSerialized_Length)
    {
        // The first kSpake2p_VerifierSerialized_Length bytes are what
        // Deserialize honors; they should round-trip identically.
        VerifyOrDie(memcmp(out.data(), data, kSpake2p_VerifierSerialized_Length) == 0);
    }

    return 0;
}
