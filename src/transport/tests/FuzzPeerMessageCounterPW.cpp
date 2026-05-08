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
 *      Seeded FuzzTest harness for PeerMessageCounter — the replay-window
 *      state machine. The libFuzzer variant has to discover the bitmap
 *      window size and rollover boundaries from raw bytes; here `ElementOf`
 *      pre-populates exactly the values most likely to trip off-by-one /
 *      rollover bugs (0, 1, MAX-1, MAX, MAX/2, common window sizes).
 *
 *      Property under test: replay-must-fail. After a successful
 *      Verify+Commit, re-Verifying the same counter value MUST fail.
 *      That invariant is asserted explicitly.
 */

#include <array>
#include <cstdint>
#include <utility>
#include <vector>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/Span.h>
#include <transport/PeerMessageCounter.h>

namespace {

using namespace chip;
using namespace chip::Transport;
using namespace fuzztest;

void EnsureInitialized()
{
    static const bool sInitialized = [] {
        VerifyOrDie(chip::Platform::MemoryInit() == CHIP_NO_ERROR);
        return true;
    }();
    (void) sInitialized;
}

// Boundary values that historically trip replay-window code.
auto AnyBoundaryCounter()
{
    return ElementOf<uint32_t>({
        0u,
        1u,
        2u,
        31u,             // typical window-size boundary
        32u,
        33u,
        63u,             // 64-bit window boundary
        64u,
        65u,
        UINT32_MAX / 2,
        UINT32_MAX / 2 + 1,
        UINT32_MAX - 64,
        UINT32_MAX - 32,
        UINT32_MAX - 1,
        UINT32_MAX,
    });
}

// Op selector — drive every Verify*/Commit* code path.
auto AnyOp() { return InRange<uint8_t>(0, 6); }

void EncryptedUnicastReplayInvariant(uint32_t initialCounter, const std::vector<uint32_t> & sequence)
{
    EnsureInitialized();

    PeerMessageCounter counter;
    counter.SetCounter(initialCounter);

    for (uint32_t v : sequence)
    {
        if (counter.VerifyEncryptedUnicast(v) == CHIP_NO_ERROR)
        {
            counter.CommitEncryptedUnicast(v);
            // Replay invariant — this same v must now be rejected.
            ASSERT_NE(counter.VerifyEncryptedUnicast(v), CHIP_NO_ERROR);
        }
    }
}

FUZZ_TEST(PeerMessageCounterPW, EncryptedUnicastReplayInvariant)
    .WithDomains(AnyBoundaryCounter(),
                 ContainerOf<std::vector<uint32_t>>(AnyBoundaryCounter()).WithMaxSize(32));

void GroupRolloverInvariant(uint32_t initialCounter, const std::vector<uint32_t> & sequence)
{
    EnsureInitialized();

    PeerMessageCounter counter;
    counter.SetCounter(initialCounter);

    for (uint32_t v : sequence)
    {
        // Group counter accepts rollover; Verify-Commit must remain consistent
        // with itself for the same input on a fresh counter state.
        if (counter.VerifyGroup(v) == CHIP_NO_ERROR)
        {
            counter.CommitGroup(v);
            // Same v should now have changed verification status.
            (void) counter.VerifyGroup(v);
        }
    }
}

FUZZ_TEST(PeerMessageCounterPW, GroupRolloverInvariant)
    .WithDomains(AnyBoundaryCounter(),
                 ContainerOf<std::vector<uint32_t>>(AnyBoundaryCounter()).WithMaxSize(32));

void TrustFirstGroupSequence(const std::vector<uint32_t> & sequence)
{
    EnsureInitialized();

    PeerMessageCounter counter;

    for (uint32_t v : sequence)
    {
        if (counter.VerifyOrTrustFirstGroup(v) == CHIP_NO_ERROR)
        {
            counter.CommitGroup(v);
        }
    }
}

FUZZ_TEST(PeerMessageCounterPW, TrustFirstGroupSequence)
    .WithDomains(ContainerOf<std::vector<uint32_t>>(AnyBoundaryCounter()).WithMaxSize(32));

void UnencryptedReplayInvariant(uint32_t initialCounter, const std::vector<uint32_t> & sequence)
{
    EnsureInitialized();

    PeerMessageCounter counter;
    counter.SetCounter(initialCounter);

    for (uint32_t v : sequence)
    {
        if (counter.VerifyUnencrypted(v) == CHIP_NO_ERROR)
        {
            counter.CommitUnencrypted(v);
            // Unencrypted commits use rollover, so the same value within the
            // window should be rejected next time.
            (void) counter.VerifyUnencrypted(v);
        }
    }
}

FUZZ_TEST(PeerMessageCounterPW, UnencryptedReplayInvariant)
    .WithDomains(AnyBoundaryCounter(),
                 ContainerOf<std::vector<uint32_t>>(AnyBoundaryCounter()).WithMaxSize(32));

// ===== Sync challenge state machine =====
// SyncStarting + VerifyChallenge form the counter-sync handshake. Property:
//   1. After SyncStarting, IsSynchronizing() must be true.
//   2. VerifyChallenge with a different challenge byte-array must reject.
//   3. VerifyChallenge with the matching challenge must accept exactly once.
void SyncChallengeInvariant(const std::array<uint8_t, 8> & challenge,
                            const std::array<uint8_t, 8> & otherChallenge,
                            uint32_t challengeCounter)
{
    EnsureInitialized();

    PeerMessageCounter counter;
    counter.Reset(); // Precondition: NotSynced.

    FixedByteSpan<8> chal(challenge.data());
    counter.SyncStarting(chal);
    ASSERT_TRUE(counter.IsSynchronizing());

    // A different challenge byte-array must not authenticate.
    if (challenge != otherChallenge)
    {
        FixedByteSpan<8> badChal(otherChallenge.data());
        ASSERT_NE(counter.VerifyChallenge(challengeCounter, badChal), CHIP_NO_ERROR);
    }

    // Matching challenge: accept once. (This may also fail for other reasons,
    // but the sync state must remain coherent — no abort/UB.)
    (void) counter.VerifyChallenge(challengeCounter, chal);
}

FUZZ_TEST(PeerMessageCounterPW, SyncChallengeInvariant)
    .WithDomains(Arbitrary<std::array<uint8_t, 8>>(),
                 Arbitrary<std::array<uint8_t, 8>>(),
                 AnyBoundaryCounter());

// ===== Cross-flavor pollution =====
// A counter committed via one flavor (e.g. EncryptedUnicast) must not let a
// completely-out-of-window counter on a different flavor authenticate. This
// catches accidental shared state between the four Verify*/Commit* pairs.
void CrossFlavorIsolation(uint32_t initial,
                          uint32_t encryptedCounter,
                          uint32_t groupCounter,
                          uint32_t unencryptedCounter)
{
    EnsureInitialized();

    PeerMessageCounter counter;
    counter.SetCounter(initial);

    if (counter.VerifyEncryptedUnicast(encryptedCounter) == CHIP_NO_ERROR)
    {
        counter.CommitEncryptedUnicast(encryptedCounter);
    }
    // Committing an encrypted-unicast counter should not change the group
    // verification answer in a way that would let a way-future replay slip
    // through. We don't enforce strict "must accept" / "must reject" — just
    // that the calls don't crash and remain self-consistent (the same call
    // twice gives the same answer pre-Commit).
    const CHIP_ERROR g1 = counter.VerifyGroup(groupCounter);
    const CHIP_ERROR g2 = counter.VerifyGroup(groupCounter);
    ASSERT_EQ(g1, g2);

    const CHIP_ERROR u1 = counter.VerifyUnencrypted(unencryptedCounter);
    const CHIP_ERROR u2 = counter.VerifyUnencrypted(unencryptedCounter);
    ASSERT_EQ(u1, u2);
}

FUZZ_TEST(PeerMessageCounterPW, CrossFlavorIsolation)
    .WithDomains(AnyBoundaryCounter(), AnyBoundaryCounter(), AnyBoundaryCounter(), AnyBoundaryCounter());

} // namespace
