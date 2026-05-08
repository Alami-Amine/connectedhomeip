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
 *      Fuzzer for the UnauthenticatedSessionTable lifecycle. Drives a
 *      sequence of FindOrAllocateResponder / AllocInitiator / FindInitiator
 *      operations with attacker-controlled ephemeral node IDs, MRP configs,
 *      and peer addresses. The table is hit on every pre-CASE/PASE message
 *      from any peer; reference-counting and eviction bugs here have wide
 *      blast radius. The pool size matches the production default
 *      (`CHIP_CONFIG_UNAUTHENTICATED_CONNECTION_POOL_SIZE`).
 */

#include <cstddef>
#include <cstdint>

#include <inet/IPAddress.h>
#include <lib/core/DataModelTypes.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <messaging/ReliableMessageProtocolConfig.h>
#include <transport/UnauthenticatedSessionTable.h>
#include <transport/raw/PeerAddress.h>

namespace {

using namespace chip;
using namespace chip::Transport;

bool EnsureInitialized()
{
    static const bool sInitialized = [] {
        VerifyOrDie(chip::Platform::MemoryInit() == CHIP_NO_ERROR);
        return true;
    }();
    return sInitialized;
}

PeerAddress MakePeerAddr(uint8_t selector, uint8_t addrSeed, uint16_t port)
{
    Inet::IPAddress ip;
    // Synthesize a deterministic IPv6 address from the seed, then pick a
    // transport type from the selector. Coverage value comes from how the
    // address is *compared* (operator==) and how `kUndefined` etc. propagate.
    uint8_t bytes[16] = { 0 };
    for (size_t i = 0; i < sizeof(bytes); ++i)
    {
        bytes[i] = static_cast<uint8_t>(addrSeed + i);
    }
    static_assert(sizeof(bytes) == sizeof(Inet::IPAddress), "IPAddress is 16 bytes");
    memcpy(&ip, bytes, sizeof(bytes));

    Transport::Type type;
    switch (selector & 0x07)
    {
    case 0: type = Transport::Type::kUdp; break;
    case 1: type = Transport::Type::kTcp; break;
    case 2: type = Transport::Type::kBle; break;
    case 3: type = Transport::Type::kWiFiPAF; break;
    case 4: type = Transport::Type::kNfc; break;
    default: type = Transport::Type::kUndefined; break;
    }

    return PeerAddress(ip, type).SetPort(port);
}

ReliableMessageProtocolConfig MakeMrpConfig(uint16_t idleMs, uint16_t activeMs, uint16_t activeThreshold)
{
    return ReliableMessageProtocolConfig(System::Clock::Milliseconds32(idleMs),
                                          System::Clock::Milliseconds32(activeMs),
                                          System::Clock::Milliseconds16(activeThreshold));
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)
{
    (void) EnsureInitialized();

    constexpr size_t kPoolSize = 4;
    UnauthenticatedSessionTable<kPoolSize> table;

    // Each "step" in the fuzz input is 14 bytes:
    //   1B opcode  | 8B nodeId  | 1B address-type-selector | 1B address-seed
    //   2B port    | 1B mrp-idleMs-low | (idleMs/activeMs/threshold packed in low bytes)
    constexpr size_t kStep = 14;

    for (size_t cursor = 0; cursor + kStep <= size; cursor += kStep)
    {
        const uint8_t * p = data + cursor;

        const uint8_t op = p[0] % 4; // FindOrAllocateResponder / AllocInitiator / FindInitiator / FindEntry
        NodeId nodeId    = 0;
        memcpy(&nodeId, p + 1, sizeof(nodeId));

        const uint8_t addrSel  = p[9];
        const uint8_t addrSeed = p[10];
        uint16_t port          = 0;
        memcpy(&port, p + 11, sizeof(port));

        const uint16_t idleMs   = static_cast<uint16_t>(p[13]) << 8;
        const uint16_t activeMs = static_cast<uint16_t>(p[13]);
        const uint16_t thresh   = static_cast<uint16_t>(p[13] | (p[13] << 4));

        PeerAddress peer    = MakePeerAddr(addrSel, addrSeed, port);
        const auto mrp      = MakeMrpConfig(idleMs, activeMs, thresh);

        switch (op)
        {
        case 0: {
            auto handle = table.FindOrAllocateResponder(nodeId, mrp, peer);
            (void) handle;
            break;
        }
        case 1: {
            auto handle = table.AllocInitiator(nodeId, peer, mrp);
            (void) handle;
            break;
        }
        case 2: {
            auto handle = table.FindInitiator(nodeId, peer);
            (void) handle;
            break;
        }
        default:
            // Drop the next byte to drive a different flag arrangement.
            break;
        }
    }

    return 0;
}
