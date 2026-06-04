/*
 *    Copyright (c) 2026 Project CHIP Authors
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

// FuzzTest operation-sequence harness for the SecureSessionTable / SecureSessionPool +
// SessionHolder lifecycle. Targets HIGH (inspection-only) finding 11-F2:
//
//   "SessionHolder x Pool snapshot semantics -- the bitmap pool reads the usage word
//    once per 64-bit chunk (Pool.cpp:112, StaticAllocatorBitmap::ForEachActiveObjectInner).
//    Iteration vs eviction/release can use-after-free."
//
// IMPORTANT ACCURACY NOTE ABOUT 11-F2 AND THIS BUILD:
//   On the Linux host -- the only platform where this target builds --
//   src/platform/Linux/SystemPlatformConfig.h:41 hard-codes
//   CHIP_SYSTEM_CONFIG_POOL_USE_HEAP = 1. So ObjectPool resolves to HeapObjectPool, NOT
//   the inline BitMapObjectPool. The exact bytes 11-F2 cites
//   (StaticAllocatorBitmap::ForEachActiveObjectInner, Pool.cpp:112) are therefore *not
//   compiled* in this configuration. The heap pool instead uses deferred node removal
//   (mIterationDepth / CleanupDeferredReleases) specifically so that releasing an object
//   during ForEach iteration is safe. To exercise the literal bitmap-snapshot path one must
//   build with CHIP_SYSTEM_CONFIG_POOL_USE_HEAP=0 (an embedded/static target). On the host
//   build this harness validates the HEAP pool's release-during-iteration safety; the same
//   .cpp will exercise the bitmap path verbatim when compiled for a POOL_USE_HEAP=0 target.
//
// The harness drives the REAL SecureSessionTable, its real ObjectPool, the real
// SecureSession refcounting, and the real SessionHolder intrusive-list linkage. The only
// Class-A fakes are chip::Platform::MemoryInit() and the monotonic system clock (real
// default). NOTHING in the pool / table / holder path is stubbed -- mocking the pool would
// make 11-F2 unfalsifiable (Class-B forbidden here). Oracle: ASan.

#include <cstddef>
#include <cstdint>
#include <vector>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

#include <lib/core/CHIPConfig.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/ReferenceCountedHandle.h>
#include <messaging/ReliableMessageProtocolConfig.h>
#include <system/SystemClock.h>
#include <transport/SecureSession.h>
#include <transport/SecureSessionTable.h>
#include <transport/SessionHolder.h>

namespace chip {
namespace {

using namespace fuzztest;
using namespace chip::Transport;

constexpr size_t kHolderCount = 6;
constexpr size_t kMaxOps      = 256;

// Minimal byte cursor (no FuzzedDataProvider dependency).
class ByteCursor
{
public:
    ByteCursor(const uint8_t * data, size_t len) : mData(data), mLen(len) {}
    bool AtEnd() const { return mPos >= mLen; }
    uint8_t Next()
    {
        if (mPos >= mLen)
        {
            return 0;
        }
        return mData[mPos++];
    }

private:
    const uint8_t * mData;
    const size_t mLen;
    size_t mPos = 0;
};

Transport::Session & SessionRefOf(const SessionHandle & handle)
{
    return *handle.operator->();
}

// A SessionHolder that ALSO keeps an independent strong SessionHandle, so the harness can
// model "code holds a live handle while iterating/evicting". Dropping the strong handle is
// what can take refcount to 0, free the slot, and arm the UAF oracle.
struct HolderSlot
{
    SessionHolder holder;
    Optional<SessionHandle> strongHandle;

    bool Active() const { return static_cast<bool>(holder); }

    void Adopt(const SessionHandle & handle)
    {
        Transport::Session & session = SessionRefOf(handle);
        ReferenceCountedHandle<Transport::Session> guard(session); // pin across Clear()
        Clear();
        holder.Grab(SessionHandle(session));
        strongHandle.Emplace(session);
    }

    void Clear()
    {
        holder.Release();
        strongHandle.ClearValue();
    }
};

// Allocate a CASE session via the PRODUCTION path (CreateNewSecureSession + Activate).
Optional<SessionHandle> AllocCase(SecureSessionTable & table, ByteCursor & cursor)
{
    const FabricIndex fabric = static_cast<FabricIndex>((cursor.Next() % 3) + 1);
    const NodeId localNode   = static_cast<NodeId>(0x1111000000000000ULL | (cursor.Next() + 1u));
    const NodeId peerNode    = static_cast<NodeId>(0x2222000000000000ULL | (cursor.Next() + 1u));
    const uint16_t peerSess  = static_cast<uint16_t>((cursor.Next() << 8) | cursor.Next());

    Optional<SessionHandle> handle = table.CreateNewSecureSession(SecureSession::Type::kCASE, ScopedNodeId(peerNode, fabric));
    if (handle.HasValue())
    {
        handle.Value()->AsSecureSession()->Activate(
            ScopedNodeId(localNode, fabric), ScopedNodeId(peerNode, fabric), CATValues{}, peerSess,
            ReliableMessageProtocolConfig(System::Clock::Milliseconds32(0), System::Clock::Milliseconds32(0),
                                          System::Clock::Milliseconds16(0)));
    }
    return handle;
}

// Touch a holder so that, if its slot was freed, ASan reports a use-after-free.
void DerefHolder(HolderSlot & slot)
{
    if (!slot.Active())
    {
        return;
    }
    volatile auto peer       = slot.holder->GetPeer();
    volatile bool active     = slot.holder->IsActiveSession();
    volatile auto sessionTyp = slot.holder->GetSessionType();
    (void) peer;
    (void) active;
    (void) sessionTyp;
}

enum class Op : uint8_t
{
    kAlloc         = 0,
    kGrab          = 1,
    kReleaseHolder = 2,
    kEvict         = 3,
    kDefunct       = 4,
    kForceEvict    = 5,
    kIterate       = 6,
    kIterRelease   = 7, // 11-F2 core: release a DIFFERENT slot mid-iteration
    kDerefAll      = 8,
    kMax,
};

// Seeds that drive the under-covered paths: (1) overflow the pool (~50 slots)
// with allocations so CreateNewSecureSession routes into EvictAndAllocate;
// (2) a mix of grab / iterate / iterate-release / evict / derefAll. Each op is
// op,i,j (+ 5 alloc-param bytes for alloc/forceEvict). op = byte % 9:
// 0 alloc, 1 grab, 3 evict, 5 forceEvict, 6 iterate, 7 iterRelease, 8 derefAll.
std::vector<std::vector<std::uint8_t>> SessionSeeds()
{
    std::vector<std::uint8_t> fill;
    auto alloc = [&](uint8_t i, uint8_t j, uint8_t s) {
        fill.insert(fill.end(), { 0, i, j, 1, s, s, s, s });
    };
    for (uint8_t k = 0; k < 60; k++)
    {
        alloc(static_cast<uint8_t>(k % 6), static_cast<uint8_t>((k + 1) % 6), k);
    }

    std::vector<std::uint8_t> mix = fill;
    for (int r = 0; r < 8; r++)
    {
        mix.insert(mix.end(), { 1, 0, 1, 6, 0, 0, 7, 1, 2, 3, 2, 0, 8, 0, 0, 5, 3, 4, 1, 5, 6, 7, 8 });
    }
    return { fill, mix };
}

void SecureSessionPoolOpSequence(const std::vector<std::uint8_t> & bytes)
{
    // One-time allocator bring-up (FuzzTest invokes the property fn many times).
    static const bool kMemReady = (chip::Platform::MemoryInit() == CHIP_NO_ERROR);
    ASSERT_TRUE(kMemReady);

    ByteCursor cursor(bytes.data(), bytes.size());

    // Fresh table per input so pool/refcount state resets between runs.
    SecureSessionTable table;
    table.Init();

    HolderSlot holders[kHolderCount];

    size_t ops = 0;
    while (!cursor.AtEnd() && ops++ < kMaxOps)
    {
        const Op op    = static_cast<Op>(cursor.Next() % static_cast<uint8_t>(Op::kMax));
        const size_t i = cursor.Next() % kHolderCount;
        const size_t j = cursor.Next() % kHolderCount;

        switch (op)
        {
        case Op::kAlloc: {
            holders[i].Clear();
            Optional<SessionHandle> handle = AllocCase(table, cursor);
            if (handle.HasValue())
            {
                holders[i].Adopt(handle.Value());
            }
            break;
        }
        case Op::kGrab: {
            if (holders[i].strongHandle.HasValue())
            {
                holders[j].Adopt(holders[i].strongHandle.Value());
            }
            break;
        }
        case Op::kReleaseHolder:
            holders[j].Clear();
            break;
        case Op::kEvict: {
            if (holders[i].holder)
            {
                SecureSession * s = holders[i].holder->AsSecureSession();
                if (s != nullptr)
                {
                    s->MarkForEviction();
                }
                holders[i].strongHandle.ClearValue();
                DerefHolder(holders[i]);
            }
            break;
        }
        case Op::kDefunct: {
            if (holders[i].holder)
            {
                SecureSession * s = holders[i].holder->AsSecureSession();
                if (s != nullptr && s->IsActiveSession())
                {
                    s->MarkAsDefunct();
                }
            }
            break;
        }
        case Op::kForceEvict: {
            Optional<SessionHandle> evicted = AllocCase(table, cursor);
            if (evicted.HasValue())
            {
                holders[i].Adopt(evicted.Value());
            }
            break;
        }
        case Op::kIterate: {
            table.ForEachSession([&](SecureSession * s) {
                volatile auto peer = s->GetPeer();
                (void) peer;
                return Loop::Continue;
            });
            for (auto & h : holders)
            {
                DerefHolder(h);
            }
            break;
        }
        case Op::kIterRelease: {
            bool releasedOnce = false;
            table.ForEachSession([&](SecureSession * s) {
                volatile auto peer = s->GetPeer();
                (void) peer;
                if (!releasedOnce && holders[j].strongHandle.HasValue())
                {
                    SecureSession * victim = SessionRefOf(holders[j].strongHandle.Value()).AsSecureSession();
                    if (victim != nullptr && victim != s)
                    {
                        victim->MarkForEviction();
                        holders[j].holder.Release();
                        holders[j].strongHandle.ClearValue();
                        releasedOnce = true;
                    }
                }
                return Loop::Continue;
            });
            break;
        }
        case Op::kDerefAll:
            for (auto & h : holders)
            {
                DerefHolder(h);
            }
            break;
        case Op::kMax:
        default:
            break;
        }
    }

    for (auto & h : holders)
    {
        h.Clear();
    }
}
FUZZ_TEST(SecureSessionPool, SecureSessionPoolOpSequence)
    .WithDomains(Arbitrary<std::vector<std::uint8_t>>().WithSeeds(SessionSeeds()));

} // namespace
} // namespace chip
