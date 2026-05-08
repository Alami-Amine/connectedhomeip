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
 *      Fuzzer for SecureSessionTable lifecycle. Drives CreateNewSecureSession
 *      / Activate / FindSecureSessionByLocalKey / Release sequences with
 *      attacker-controlled parameters. Mirrors the UnauthenticatedSessionTable
 *      fuzzer but for the CASE/PASE secure-session pool. Eviction-policy
 *      bugs here have wide blast radius — every commissioned peer holds a
 *      session, and pool exhaustion / mis-eviction is a DoS vector.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include <inet/IPAddress.h>
#include <lib/core/DataModelTypes.h>
#include <lib/core/ScopedNodeId.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <messaging/ReliableMessageProtocolConfig.h>
#include <transport/SecureSession.h>
#include <transport/SecureSessionTable.h>
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

PeerAddress MakePeerAddr(uint8_t addrSeed, uint16_t port)
{
    Inet::IPAddress ip;
    uint8_t bytes[16];
    for (size_t i = 0; i < sizeof(bytes); ++i)
    {
        bytes[i] = static_cast<uint8_t>(addrSeed + i);
    }
    memcpy(&ip, bytes, sizeof(bytes));
    return PeerAddress(ip, Transport::Type::kUdp).SetPort(port);
}

ReliableMessageProtocolConfig MakeMrpConfig(uint16_t idleMs, uint16_t activeMs, uint16_t threshold)
{
    return ReliableMessageProtocolConfig(System::Clock::Milliseconds32(idleMs),
                                          System::Clock::Milliseconds32(activeMs),
                                          System::Clock::Milliseconds16(threshold));
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)
{
    (void) EnsureInitialized();

    SecureSessionTable table;
    table.Init();

    // SessionHandle is move-only and not move-assignable, so wrap each in a
    // unique_ptr so the container can erase elements.
    std::vector<std::unique_ptr<SessionHandle>> handles;

    // Cap below the table's pool size so the harness doesn't hit F-6
    // (SecureSessionTable abort when pool full + all sessions pinned by
    // SessionHandles, upstream issue #19495). The exhaustion path is a real
    // CHIP defect we want to keep documented; capping here lets the fuzzer
    // keep running and find OTHER bugs.
    constexpr size_t kMaxHandles = 2;

    // Each step is 16 bytes: 1B opcode + 1B sessionTypeSel + 2B localId
    //                       + 8B peerNodeId + 1B fabricIndex + 1B addrSeed
    //                       + 2B port
    constexpr size_t kStep = 16;

    for (size_t cursor = 0; cursor + kStep <= size; cursor += kStep)
    {
        const uint8_t * p   = data + cursor;
        const uint8_t op    = p[0];
        const uint8_t typeS = p[1];
        uint16_t localId    = 0;
        memcpy(&localId, p + 2, sizeof(localId));
        NodeId peerNode     = 0;
        memcpy(&peerNode, p + 4, sizeof(peerNode));
        const FabricIndex fab = static_cast<FabricIndex>(p[12] ? p[12] : 1);
        const uint8_t addrSeed = p[13];
        uint16_t port = 0;
        memcpy(&port, p + 14, sizeof(port));

        const auto sessType = (typeS & 0x01) ? SecureSession::Type::kPASE : SecureSession::Type::kCASE;

        switch (op % 5)
        {
        case 0: { // CreateNewSecureSession + Activate
            if (handles.size() >= kMaxHandles)
            {
                // Drop one before allocating to avoid the F-6 abort path.
                handles.erase(handles.begin());
            }
            // Preconditions on SecureSession::Activate:
            //   PASE sessions must use kUndefinedFabricIndex.
            //   CASE sessions must use real fabric AND operational NodeIds
            //     (NodeId.h kMaxOperationalNodeId = 0xFFFF'FFEF'FFFF'FFFF, nonzero).
            const FabricIndex effectiveFab = (sessType == SecureSession::Type::kPASE) ? kUndefinedFabricIndex : fab;
            // Use fixed nonzero operational NodeIds for CASE so we never trip
            // the SecureSession::Activate precondition; the fuzzer still drives
            // localId / fab / addr / refcount lifecycle.
            const NodeId effectivePeer = (sessType == SecureSession::Type::kCASE)
                ? static_cast<NodeId>(0x0000000000000001ULL + (peerNode & 0xFFFF))
                : peerNode;
            const NodeId effectiveLocal = (sessType == SecureSession::Type::kCASE)
                ? static_cast<NodeId>(0x0000000000010000ULL + (peerNode & 0xFFFF))
                : (peerNode + 1);
            ScopedNodeId hint(effectivePeer, effectiveFab);
            auto handle = table.CreateNewSecureSession(sessType, hint);
            if (handle.HasValue())
            {
                auto * ss = handle.Value()->AsSecureSession();
                ss->Activate(ScopedNodeId(effectiveLocal, effectiveFab),
                             ScopedNodeId(effectivePeer, effectiveFab),
                             CATValues(), localId,
                             MakeMrpConfig(0x100, 0x80, 32));
                ss->SetPeerAddress(MakePeerAddr(addrSeed, port));
                handles.push_back(std::make_unique<SessionHandle>(std::move(handle.Value())));
            }
            break;
        }
        case 1: { // FindSecureSessionByLocalKey — pure lookup
            (void) table.FindSecureSessionByLocalKey(localId);
            break;
        }
        case 2: { // Drop one handle (forces eviction if last reference)
            if (!handles.empty())
            {
                const size_t idx = peerNode % handles.size();
                handles.erase(handles.begin() + static_cast<ptrdiff_t>(idx));
            }
            break;
        }
        case 3: { // Drop all handles
            handles.clear();
            break;
        }
        case 4: { // Iteration: visit every session, do nothing
            (void) table.ForEachSession([](SecureSession * session) {
                (void) session;
                return Loop::Continue;
            });
            break;
        }
        }
    }

    handles.clear();
    return 0;
}
