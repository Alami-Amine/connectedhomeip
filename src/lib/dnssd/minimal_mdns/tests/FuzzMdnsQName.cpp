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
 *      Fuzzes mDNS SerializedQNameIterator: the DNS-name decoder that walks
 *      length-prefixed labels and follows compression pointers. Compression
 *      pointers are a classic source of OOB-read and infinite-loop bugs in
 *      DNS parsers. Any inbound mDNS reply hits this code.
 */

#include <cstddef>
#include <cstdint>

#include <lib/dnssd/minimal_mdns/core/BytesRange.h>
#include <lib/dnssd/minimal_mdns/core/QName.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t len)
{
    using namespace mdns::Minimal;

    if (len == 0)
    {
        return 0;
    }

    BytesRange range(data, data + len);

    // Fuzz starting positions across the buffer to exercise the
    // look-behind / pointer-target validation logic.
    const size_t start_step = (len > 8) ? (len / 8) : 1;
    for (size_t off = 0; off < len; off += start_step)
    {
        SerializedQNameIterator iter(range, data + off);
        size_t safety = 0;
        while (iter.Next())
        {
            (void) iter.Value();
            if (++safety > 256)
            {
                break;
            }
        }
        (void) iter.IsValid();
    }

    return 0;
}
