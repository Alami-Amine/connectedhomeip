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
 *      Seeded FuzzTest harness for chip::TLV::Utilities. The libFuzzer
 *      variant fuzzes raw bytes; here we seed with valid TLV blobs
 *      constructed at startup (variety of structures, arrays, lists, and
 *      mixed primitive content) so the mutator starts from well-formed
 *      structure and explores the recursive walk + Find paths deeper.
 */

#include <string>
#include <vector>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

#include <lib/core/CHIPError.h>
#include <lib/core/TLVCommon.h>
#include <lib/core/TLVReader.h>
#include <lib/core/TLVTags.h>
#include <lib/core/TLVTypes.h>
#include <lib/core/TLVUtilities.h>
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

// Build a few valid TLV structures of varying shapes for FuzzTest to mutate.
std::vector<std::string> TlvSeeds()
{
    auto build = [](void (*body)(TLVWriter &)) -> std::string {
        EnsureInitialized();
        uint8_t buf[1024];
        TLVWriter writer;
        writer.Init(buf, sizeof(buf));
        TLVType outer;
        if (writer.StartContainer(AnonymousTag(), kTLVType_Structure, outer) != CHIP_NO_ERROR)
            return {};
        body(writer);
        if (writer.EndContainer(outer) != CHIP_NO_ERROR)
            return {};
        if (writer.Finalize() != CHIP_NO_ERROR)
            return {};
        return std::string(reinterpret_cast<const char *>(buf), writer.GetLengthWritten());
    };

    std::vector<std::string> out;
    out.push_back(build([](TLVWriter & w) {
        (void) w.Put(ContextTag(0), uint8_t{ 1 });
        (void) w.Put(ContextTag(1), uint16_t{ 0xCAFE });
        (void) w.Put(ContextTag(2), uint32_t{ 0xDEADBEEF });
        (void) w.Put(ContextTag(3), uint64_t{ 0x0123456789ABCDEFULL });
    }));
    out.push_back(build([](TLVWriter & w) {
        (void) w.PutString(ContextTag(0), "hello");
        (void) w.PutBytes(ContextTag(1), reinterpret_cast<const uint8_t *>("world"), 5);
        (void) w.PutBoolean(ContextTag(2), true);
    }));
    out.push_back(build([](TLVWriter & w) {
        TLVType arr;
        (void) w.StartContainer(ContextTag(0), kTLVType_Array, arr);
        for (int i = 0; i < 8; ++i)
            (void) w.Put(AnonymousTag(), static_cast<uint32_t>(i));
        (void) w.EndContainer(arr);
    }));
    out.push_back(build([](TLVWriter & w) {
        TLVType inner;
        (void) w.StartContainer(ContextTag(0), kTLVType_Structure, inner);
        (void) w.Put(ContextTag(0), int64_t{ -1234 });
        (void) w.PutString(ContextTag(1), "nested");
        (void) w.EndContainer(inner);
    }));
    out.push_back(build([](TLVWriter & w) {
        // List variant
        TLVType list;
        (void) w.StartContainer(ContextTag(0), kTLVType_List, list);
        (void) w.Put(AnonymousTag(), uint8_t{ 0xAA });
        (void) w.Put(ContextTag(1), uint64_t{ 0x1122334455667788ULL });
        (void) w.EndContainer(list);
    }));
    return out;
}

CHIP_ERROR NoopHandler(const TLVReader &, size_t, void *) { return CHIP_NO_ERROR; }

void TLVUtilitiesIterateFuzz(const std::string & blob)
{
    EnsureInitialized();
    TLVReader reader;
    reader.Init(reinterpret_cast<const uint8_t *>(blob.data()), blob.size());
    if (reader.Next() != CHIP_NO_ERROR)
        return;

    (void) Utilities::Iterate(reader, NoopHandler, nullptr);
    (void) Utilities::Iterate(reader, NoopHandler, nullptr, /*aRecurse=*/false);
}

FUZZ_TEST(TLVUtilitiesPW, TLVUtilitiesIterateFuzz)
    .WithDomains(Arbitrary<std::string>().WithSeeds(TlvSeeds()).WithMaxSize(4096));

void TLVUtilitiesCountFuzz(const std::string & blob)
{
    EnsureInitialized();
    TLVReader reader;
    reader.Init(reinterpret_cast<const uint8_t *>(blob.data()), blob.size());
    if (reader.Next() != CHIP_NO_ERROR)
        return;

    size_t count = 0;
    (void) Utilities::Count(reader, count);
    (void) Utilities::Count(reader, count, /*aRecurse=*/false);
}

FUZZ_TEST(TLVUtilitiesPW, TLVUtilitiesCountFuzz)
    .WithDomains(Arbitrary<std::string>().WithSeeds(TlvSeeds()).WithMaxSize(4096));

void TLVUtilitiesFindFuzz(const std::string & blob, uint8_t tagNum)
{
    EnsureInitialized();
    TLVReader reader;
    reader.Init(reinterpret_cast<const uint8_t *>(blob.data()), blob.size());
    if (reader.Next() != CHIP_NO_ERROR)
        return;

    TLVReader found;
    (void) Utilities::Find(reader, ContextTag(tagNum), found);
    (void) Utilities::Find(reader, AnonymousTag(), found);
    (void) Utilities::Find(reader, CommonTag(tagNum), found);
}

FUZZ_TEST(TLVUtilitiesPW, TLVUtilitiesFindFuzz)
    .WithDomains(Arbitrary<std::string>().WithSeeds(TlvSeeds()).WithMaxSize(4096), Arbitrary<uint8_t>());

} // namespace
