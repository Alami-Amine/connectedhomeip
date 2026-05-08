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
 *      Fuzzes the User Directed Commissioning payload parsers:
 *      IdentificationDeclaration::ReadPayload (received by commissioners on
 *      a well-known UDP port from anyone on the local network) and
 *      CommissionerDeclaration::ReadPayload (received by commissionees).
 *      UDC has no transport-layer auth — every byte parsed here is
 *      attacker-controlled.
 */

#include <cstddef>
#include <cstdint>
#include <vector>

#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <protocols/user_directed_commissioning/UserDirectedCommissioning.h>

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
    using namespace chip::Protocols::UserDirectedCommissioning;

    (void) EnsureInitialized();

    // ReadPayload mutates the buffer in-place during parse, so use a copy.
    std::vector<uint8_t> copy(data, data + len);

    {
        IdentificationDeclaration id;
        (void) id.ReadPayload(copy.data(), copy.size());
    }

    // Reset the copy in case ReadPayload mutated it.
    copy.assign(data, data + len);

    {
        CommissionerDeclaration cd;
        (void) cd.ReadPayload(copy.data(), copy.size());
    }

    return 0;
}
