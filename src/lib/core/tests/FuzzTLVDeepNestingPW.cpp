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
 *      Seeded FuzzTest harness that constructs nested TLV from instruction
 *      bytes and walks it recursively. Targets stack-overflow on attacker-
 *      controlled nesting and the saved-context array bounds in TLVReader.
 *
 *      Distinct from FuzzTlvReaderPW (raw-byte fuzz of read side) — this
 *      builds *valid-but-pathological* TLV at runtime so the reader is
 *      always given a well-formed-enough blob to descend into deeply.
 */

#include <cstddef>
#include <cstdint>
#include <vector>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

#include <lib/core/CHIPError.h>
#include <lib/core/TLVReader.h>
#include <lib/core/TLVTags.h>
#include <lib/core/TLVTypes.h>
#include <lib/core/TLVWriter.h>
#include <lib/support/CHIPMem.h>

namespace {

using namespace chip;
using namespace chip::TLV;
using namespace fuzztest;

void EnsureInitialized()
{
    static const bool sInitialized = [] {
        VerifyOrDie(Platform::MemoryInit() == CHIP_NO_ERROR);
        return true;
    }();
    (void) sInitialized;
}

void Walk(TLVReader & reader, int depth, int & remaining)
{
    if (depth > 64)
        return;
    while (reader.Next() == CHIP_NO_ERROR)
    {
        if (--remaining <= 0)
            return;
        const TLVType t = reader.GetType();
        if (t == kTLVType_Structure || t == kTLVType_Array || t == kTLVType_List)
        {
            TLVType outer;
            if (reader.EnterContainer(outer) == CHIP_NO_ERROR)
            {
                Walk(reader, depth + 1, remaining);
                (void) reader.ExitContainer(outer);
            }
        }
        else
        {
            uint64_t u = 0;
            (void) reader.Get(u);
            int64_t s = 0;
            (void) reader.Get(s);
            ByteSpan bs;
            (void) reader.Get(bs);
            CharSpan cs;
            (void) reader.Get(cs);
            bool b = false;
            (void) reader.Get(b);
        }
    }
}

void TLVDeepNestingFuzz(const std::vector<uint8_t> & insn)
{
    EnsureInitialized();
    if (insn.empty() || insn.size() > 1024)
        return;

    std::vector<uint8_t> buf(size_t{ 4096 } + insn.size() * 8);
    TLVWriter writer;
    writer.Init(buf.data(), static_cast<uint32_t>(buf.size()));

    std::vector<TLVType> stack;
    {
        TLVType outer;
        if (writer.StartContainer(AnonymousTag(), kTLVType_Structure, outer) != CHIP_NO_ERROR)
            return;
        stack.push_back(outer);
    }

    uint8_t tagCounter = 0;
    for (size_t i = 0; i < insn.size(); ++i)
    {
        const uint8_t op = insn[i] & 0x03;
        switch (op)
        {
        case 0: { // open Structure
            TLVType outer;
            if (writer.StartContainer(ContextTag(tagCounter++), kTLVType_Structure, outer) != CHIP_NO_ERROR)
                goto finalize;
            stack.push_back(outer);
            break;
        }
        case 1: { // open Array
            TLVType outer;
            if (writer.StartContainer(ContextTag(tagCounter++), kTLVType_Array, outer) != CHIP_NO_ERROR)
                goto finalize;
            stack.push_back(outer);
            break;
        }
        case 2: { // close
            if (stack.size() <= 1)
                break;
            TLVType outer = stack.back();
            stack.pop_back();
            if (writer.EndContainer(outer) != CHIP_NO_ERROR)
                goto finalize;
            break;
        }
        case 3: { // put a small typed element
            const uint8_t variant = (insn[i] >> 2) & 0x07;
            const Tag tag         = (stack.size() > 1 && (variant & 0x4))
                ? AnonymousTag()
                : ContextTag(tagCounter++);
            switch (variant & 0x03)
            {
            case 0:
                (void) writer.Put(tag, static_cast<uint8_t>(i));
                break;
            case 1:
                (void) writer.Put(tag, static_cast<uint64_t>(i));
                break;
            case 2: {
                const uint8_t blob[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
                (void) writer.PutBytes(tag, blob, sizeof(blob));
                break;
            }
            case 3:
                (void) writer.PutString(tag, "fuzz");
                break;
            }
            break;
        }
        }
    }

finalize:
    while (stack.size() > 1)
    {
        TLVType outer = stack.back();
        stack.pop_back();
        if (writer.EndContainer(outer) != CHIP_NO_ERROR)
            return;
    }
    if (writer.EndContainer(stack.front()) != CHIP_NO_ERROR)
        return;
    if (writer.Finalize() != CHIP_NO_ERROR)
        return;

    TLVReader reader;
    reader.Init(buf.data(), writer.GetLengthWritten());
    if (reader.Next() != CHIP_NO_ERROR)
        return;
    TLVType outerR;
    if (reader.EnterContainer(outerR) != CHIP_NO_ERROR)
        return;

    int budget = 4096;
    Walk(reader, 0, budget);
    (void) reader.ExitContainer(outerR);
}

// Seeds: instruction sequences that produce known-interesting TLV shapes
// (deeply nested, mixed primitive/container, balanced/unbalanced).
std::vector<std::vector<uint8_t>> InsnSeeds()
{
    return {
        // Empty struct
        { 2 },
        // 8-deep nested structures (open-open-...-close-close-...)
        { 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2 },
        // Alternating struct/array
        { 0, 1, 0, 1, 0, 1, 2, 2, 2, 2, 2, 2 },
        // Many primitive elements
        { 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3 },
        // Mixed nesting + primitives
        { 0, 3, 3, 1, 3, 3, 2, 3, 2, 3 },
        // Large-ish struct
        { 0, 3, 3, 3, 3, 3, 3, 3, 3, 0, 3, 3, 2, 3, 3, 2 },
    };
}

FUZZ_TEST(TLVDeepNestingPW, TLVDeepNestingFuzz)
    .WithDomains(Arbitrary<std::vector<uint8_t>>().WithSeeds(InsnSeeds()).WithMaxSize(512));

} // namespace
