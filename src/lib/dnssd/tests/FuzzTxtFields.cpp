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
 *      Fuzzes FillNodeDataFromTxt — the DNS-SD TXT key/value parser used to
 *      populate CommonResolutionData and CommissionNodeData during
 *      operational and commissionable-node discovery. Reachable from any
 *      mDNS responder on the local network.
 */

#include <cstddef>
#include <cstdint>

#include <lib/dnssd/Resolver.h>
#include <lib/dnssd/TxtFields.h>
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
    using namespace chip::Dnssd;

    (void) EnsureInitialized();

    if (len < 2)
    {
        return 0;
    }

    // Split fuzz input as: 1-byte key length, then key bytes, then value bytes.
    const size_t keyLen = data[0];
    if (keyLen + 1 >= len)
    {
        return 0;
    }
    ByteSpan key(data + 1, keyLen);
    ByteSpan value(data + 1 + keyLen, len - 1 - keyLen);

    {
        CommonResolutionData resolutionData;
        FillNodeDataFromTxt(key, value, resolutionData);
    }
    {
        CommissionNodeData nodeData;
        FillNodeDataFromTxt(key, value, nodeData);
    }

    return 0;
}
