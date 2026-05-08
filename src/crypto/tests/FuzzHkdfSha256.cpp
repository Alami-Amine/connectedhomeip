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
 *      Fuzzes Crypto::HKDF_sha::HKDF_SHA256 — the foundation of session-key
 *      derivation in CASE/PASE. The salt and info inputs are protocol-derived
 *      and partly attacker-influenced (e.g. peer node ids, exchange ids);
 *      bounds bugs in the backend wrapper would propagate to every session.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include <crypto/CHIPCryptoPAL.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>

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

    // Layout: [1B secretLen][1B saltLen][2B outLen LE]
    //         [secret][salt][info...]
    if (len < 4)
    {
        return 0;
    }

    const size_t secretLen = data[0];
    const size_t saltLen   = data[1];
    uint16_t outLen        = 0;
    memcpy(&outLen, data + 2, sizeof(outLen));
    if (outLen > 4096) // bound to a reasonable test size
    {
        outLen = static_cast<uint16_t>(outLen % 4096);
    }

    const size_t header = 4;
    if (len < header + secretLen + saltLen)
    {
        return 0;
    }

    const uint8_t * secret = data + header;
    const uint8_t * salt   = secret + secretLen;
    const uint8_t * info   = salt + saltLen;
    const size_t infoLen   = len - header - secretLen - saltLen;

    std::vector<uint8_t> out(outLen);

    HKDF_sha hkdf;
    (void) hkdf.HKDF_SHA256(secret, secretLen, salt, saltLen, info, infoLen, out.data(), out.size());

    return 0;
}
