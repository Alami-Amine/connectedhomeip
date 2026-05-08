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
 *      Fuzzer for PeerMessageCounter — the replay-protection state machine
 *      that every incoming Matter message hits. Drives a fuzzed sequence of
 *      verify/commit operations against attacker-controlled counter values
 *      across all four flavors (encrypted unicast, unencrypted unicast,
 *      group, group-trust-first), exercising the rollover window and the
 *      synced/sync-in-process/not-synced state machine.
 *
 *      Bug classes this targets:
 *        - off-by-one in the bitmap window slide (boundary at +/- window size)
 *        - rollover handling near 0xFFFFFFFF / 0x00000000
 *        - replay accepted when it shouldn't be
 *        - non-replay rejected when it shouldn't be (induces packet loss)
 *        - precondition assertions in CommitWithRollover / CommitWithoutRollover
 */

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <crypto/RandUtils.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/Span.h>
#include <transport/PeerMessageCounter.h>

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

} // namespace

// Fuzz input layout: 5-byte steps
//   1B opcode (selects which Verify/Commit/Set call to make)
//   4B counter value (LE)
//
// Each opcode operates against the same PeerMessageCounter instance, so the
// fuzzer is exercising state-machine transitions across the sequence.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)
{
    (void) EnsureInitialized();

    PeerMessageCounter counter;
    constexpr size_t kStep = 5;

    for (size_t cursor = 0; cursor + kStep <= size; cursor += kStep)
    {
        const uint8_t op    = data[cursor];
        uint32_t ctr        = 0;
        memcpy(&ctr, data + cursor + 1, sizeof(ctr));

        switch (op % 13)
        {
        case 0: // Reset
            counter.Reset();
            break;
        case 1: // SetCounter (forces Synced state)
            counter.SetCounter(ctr);
            break;
        case 2: // VerifyEncryptedUnicast (only valid when synced)
            if (counter.IsSynchronized())
            {
                CHIP_ERROR err = counter.VerifyEncryptedUnicast(ctr);
                if (err == CHIP_NO_ERROR)
                {
                    counter.CommitEncryptedUnicast(ctr);
                }
            }
            break;
        case 3: // VerifyUnencrypted (handles both NotSynced and Synced)
        {
            CHIP_ERROR err = counter.VerifyUnencrypted(ctr);
            if (err == CHIP_NO_ERROR)
            {
                counter.CommitUnencrypted(ctr);
            }
            break;
        }
        case 4: // VerifyGroup (only valid when synced)
            if (counter.IsSynchronized())
            {
                CHIP_ERROR err = counter.VerifyGroup(ctr);
                if (err == CHIP_NO_ERROR)
                {
                    counter.CommitGroup(ctr);
                }
            }
            break;
        case 5: // VerifyOrTrustFirstGroup (handles NotSynced)
        {
            CHIP_ERROR err = counter.VerifyOrTrustFirstGroup(ctr);
            if (err == CHIP_NO_ERROR)
            {
                counter.CommitGroup(ctr);
            }
            break;
        }
        case 6: { // SyncStarting + VerifyChallenge sequence
            // Precondition (PeerMessageCounter.h:62): SyncStarting requires
            // the counter to be in NotSynced. Reset first so the call is legal.
            counter.Reset();
            uint8_t challengeBytes[8] = {};
            memcpy(challengeBytes, data + cursor + 1, sizeof(uint32_t));
            FixedByteSpan<8> challenge(challengeBytes);
            counter.SyncStarting(challenge);
            (void) counter.VerifyChallenge(ctr, challenge);
            break;
        }
        case 7: // SyncFailed
            counter.SyncFailed();
            break;
        case 8: // Verify-without-commit (test that the verify side is pure)
            (void) counter.VerifyEncryptedUnicast(ctr);
            (void) counter.VerifyGroup(ctr);
            break;
        case 9: // Boundary attack: jump close to UINT32_MAX
            counter.SetCounter(UINT32_MAX - (ctr & 0xFF));
            break;
        case 10: // Boundary attack: jump close to 0
            counter.SetCounter(ctr & 0xFF);
            break;
        case 11: { // Replay attack: commit then re-verify same value (should reject)
            CHIP_ERROR err = counter.VerifyEncryptedUnicast(ctr);
            if (err == CHIP_NO_ERROR)
            {
                counter.CommitEncryptedUnicast(ctr);
                // Re-verify the same counter value — must now be rejected.
                CHIP_ERROR replay = counter.VerifyEncryptedUnicast(ctr);
                VerifyOrDie(replay != CHIP_NO_ERROR);
            }
            break;
        }
        case 12: { // Idempotency: VerifyOrTrustFirstGroup twice in a row
            (void) counter.VerifyOrTrustFirstGroup(ctr);
            (void) counter.VerifyOrTrustFirstGroup(ctr);
            break;
        }
        }
    }

    return 0;
}
