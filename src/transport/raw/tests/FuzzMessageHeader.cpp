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
 *      Fuzzes PacketHeader::Decode, PayloadHeader::Decode, and
 *      MessageAuthenticationCode::Decode — the first parsers that touch every
 *      incoming UDP/TCP/BLE/WiFiPAF packet, before authentication.
 */

#include <cstddef>
#include <cstdint>

#include <transport/raw/MessageHeader.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t len)
{
    using namespace chip;

    {
        PacketHeader header;
        uint16_t consumed = 0;
        (void) header.Decode(data, len, &consumed);

        // After a (possibly failed) decode, also exercise the MAC decode path,
        // which depends on PacketHeader's encryption-type / MIC tag length.
        if (len > 0)
        {
            MessageAuthenticationCode mac;
            uint16_t macConsumed = 0;
            (void) mac.Decode(header, data, len, &macConsumed);
        }
    }

    {
        PayloadHeader header;
        uint16_t consumed = 0;
        (void) header.Decode(data, len, &consumed);
    }

    return 0;
}
