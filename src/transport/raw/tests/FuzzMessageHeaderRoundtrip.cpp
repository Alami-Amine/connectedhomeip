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
 *      Property-based round-trip fuzzer for PacketHeader and PayloadHeader.
 *      Decode -> encode -> assert byte equality. Catches encoder/decoder
 *      mismatches that pure decode-only fuzzers miss; these mismatches turn
 *      into protocol confusion or message-tampering windows on the wire.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <lib/support/CodeUtils.h>
#include <transport/raw/MessageHeader.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t len)
{
    using namespace chip;

    {
        PacketHeader header;
        uint16_t consumed = 0;
        if (header.Decode(data, len, &consumed) == CHIP_NO_ERROR)
        {
            uint8_t encoded[128];
            uint16_t encodedLen = 0;
            const uint16_t expectedLen = header.EncodeSizeBytes();
            if (expectedLen <= sizeof(encoded) &&
                header.Encode(encoded, sizeof(encoded), &encodedLen) == CHIP_NO_ERROR)
            {
                // Encoder must produce as many bytes as Decode consumed and as
                // EncodeSizeBytes promised.
                VerifyOrDie(encodedLen == consumed);
                VerifyOrDie(encodedLen == expectedLen);
                // The re-encoded bytes must equal the prefix the decoder
                // consumed from the original input.
                VerifyOrDie(memcmp(encoded, data, encodedLen) == 0);
            }
        }
    }

    {
        PayloadHeader header;
        uint16_t consumed = 0;
        if (header.Decode(data, len, &consumed) == CHIP_NO_ERROR)
        {
            uint8_t encoded[64];
            uint16_t encodedLen = 0;
            const uint16_t expectedLen = header.EncodeSizeBytes();
            if (expectedLen <= sizeof(encoded) &&
                header.Encode(encoded, sizeof(encoded), &encodedLen) == CHIP_NO_ERROR)
            {
                VerifyOrDie(encodedLen == consumed);
                VerifyOrDie(encodedLen == expectedLen);
                VerifyOrDie(memcmp(encoded, data, encodedLen) == 0);
            }
        }
    }

    return 0;
}
