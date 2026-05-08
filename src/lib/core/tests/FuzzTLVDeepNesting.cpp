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
 *      Fuzzer that drives TLVReader through deeply-nested container chains.
 *      Uses fuzz input bytes as a recipe for opening / closing structures and
 *      arrays, then walks the resulting TLV with a recursive `Iterate` style.
 *      Targets:
 *        - stack-overflow on attacker-controlled nesting depth
 *        - reader's saved-context array bounds
 *        - container-type confusion (struct vs array vs list)
 *
 *      Distinct from the existing FuzzTlvReader which feeds raw bytes.
 *      This harness *constructs* a valid-but-pathological TLV structure
 *      from the fuzz input and then walks it — exercising the recursive
 *      decode path with adversarial-but-well-formed TLV.
 */

#include <cstddef>
#include <cstdint>
#include <vector>

#include <lib/core/CHIPError.h>
#include <lib/core/TLVReader.h>
#include <lib/core/TLVTags.h>
#include <lib/core/TLVTypes.h>
#include <lib/core/TLVWriter.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>

namespace {

using namespace chip;
using namespace chip::TLV;

bool EnsureInitialized()
{
    static const bool sInitialized = [] {
        VerifyOrDie(Platform::MemoryInit() == CHIP_NO_ERROR);
        return true;
    }();
    return sInitialized;
}

// Walk the entire reader structure recursively. Return when we run out of
// elements or hit an error. A safety counter caps total elements visited.
void Walk(TLVReader & reader, int depth, int & remaining)
{
    if (depth > 64)
    {
        return; // hard cap: TLV reader has its own limit, we cap higher
    }
    while (reader.Next() == CHIP_NO_ERROR)
    {
        if (--remaining <= 0)
        {
            return;
        }
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
            // Type-confusion probes — call several Get* with the wrong type
            // to ensure they reject cleanly without dereferencing past the
            // value buffer.
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

} // namespace

// Fuzz input layout:
//   Each byte is an instruction in {0..3}:
//     0 = open Structure
//     1 = open Array
//     2 = close current container
//     3 = put a small typed element (cycled by depth: u8/u16/u32/u64/string/bytes)
extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)
{
    (void) EnsureInitialized();

    if (size == 0 || size > 1024)
    {
        return 0;
    }

    std::vector<uint8_t> buf(size_t{ 4096 } + size * 8);
    TLVWriter writer;
    writer.Init(buf.data(), static_cast<uint32_t>(buf.size()));

    std::vector<TLVType> stack;
    {
        TLVType outer;
        if (writer.StartContainer(AnonymousTag(), kTLVType_Structure, outer) != CHIP_NO_ERROR)
        {
            return 0;
        }
        stack.push_back(outer);
    }

    uint8_t tagCounter = 0;
    for (size_t i = 0; i < size; ++i)
    {
        const uint8_t op = data[i] & 0x03;

        switch (op)
        {
        case 0: { // open Structure
            TLVType outer;
            if (writer.StartContainer(ContextTag(tagCounter++), kTLVType_Structure, outer) != CHIP_NO_ERROR)
            {
                goto finalize;
            }
            stack.push_back(outer);
            break;
        }
        case 1: { // open Array
            TLVType outer;
            if (writer.StartContainer(ContextTag(tagCounter++), kTLVType_Array, outer) != CHIP_NO_ERROR)
            {
                goto finalize;
            }
            stack.push_back(outer);
            break;
        }
        case 2: { // close
            if (stack.size() <= 1)
            {
                break; // never close the outermost
            }
            TLVType outer = stack.back();
            stack.pop_back();
            if (writer.EndContainer(outer) != CHIP_NO_ERROR)
            {
                goto finalize;
            }
            break;
        }
        case 3: { // put a small typed element
            const uint8_t variant = (data[i] >> 2) & 0x07;
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
            return 0;
    }
    if (writer.EndContainer(stack.front()) != CHIP_NO_ERROR)
        return 0;
    if (writer.Finalize() != CHIP_NO_ERROR)
        return 0;

    TLVReader reader;
    reader.Init(buf.data(), writer.GetLengthWritten());
    if (reader.Next() != CHIP_NO_ERROR)
        return 0;

    TLVType outerR;
    if (reader.EnterContainer(outerR) != CHIP_NO_ERROR)
        return 0;

    int budget = 4096;
    Walk(reader, 0, budget);
    (void) reader.ExitContainer(outerR);

    return 0;
}
