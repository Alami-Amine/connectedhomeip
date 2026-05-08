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
 *      Fuzzes Base64 decoders (Base64Decode, Base64Decode32) and round-trips
 *      Base64Encode -> Base64Decode. Used in PEM cert parsing, attestation
 *      payload tooling, and JSON-form configuration paths.
 */

#include <cstddef>
#include <cstdint>
#include <vector>

#include <lib/support/Base64.h>
#include <lib/support/CodeUtils.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t len)
{
    using namespace chip;

    if (len > UINT16_MAX)
    {
        return 0;
    }

    // Decode path: input bytes treated as a base64 string. Output buffer
    // sized per Base64Decode contract (input length / 4 * 3 + slack).
    {
        std::vector<uint8_t> out(static_cast<size_t>(len) + 4);
        (void) Base64Decode(reinterpret_cast<const char *>(data), static_cast<uint16_t>(len), out.data());
    }
    {
        std::vector<uint8_t> out(static_cast<size_t>(len) + 4);
        (void) Base64Decode32(reinterpret_cast<const char *>(data), static_cast<uint32_t>(len), out.data());
    }

    // Round-trip: Encode -> Decode and verify equality.
    if (len > 0 && len <= 1024)
    {
        std::vector<char> encoded(static_cast<size_t>(len) * 4 / 3 + 8);
        const uint16_t encLen = Base64Encode(data, static_cast<uint16_t>(len), encoded.data());
        std::vector<uint8_t> decoded(static_cast<size_t>(encLen));
        const uint16_t decLen = Base64Decode(encoded.data(), encLen, decoded.data());
        VerifyOrDie(decLen == len);
        for (size_t i = 0; i < len; ++i)
        {
            VerifyOrDie(decoded[i] == data[i]);
        }
    }

    return 0;
}
