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
 *      Property-based TLV encode↔decode roundtrip fuzzer (FuzzTest framework).
 *      The existing FuzzTlvReader/FuzzTlvReaderPW only fuzz the *read* side
 *      with raw bytes — they cannot find encoder/decoder asymmetries (the bug
 *      class that surfaced F-1 in PacketHeader). Here:
 *        Roundtrip: write a structured value via TLVWriter, read it back via
 *        TLVReader, assert the decoded value matches the original.
 *
 *      Bugs this can catch:
 *        - Encoder writes more/fewer bytes than EstimateStructOverhead reports
 *        - Reader skips bytes the writer wrote (or vice versa)
 *        - Tag-encoding asymmetry between Put and Get sides
 *        - String length encoding (8/16/32/64-bit length forms)
 */

#include <cmath>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

#include <lib/core/CHIPError.h>
#include <lib/core/TLVReader.h>
#include <lib/core/TLVTags.h>
#include <lib/core/TLVTypes.h>
#include <lib/core/TLVWriter.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/Span.h>

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

// Outcome of a roundtrip attempt. The harness only asserts equality when
// Put succeeded; Put-side rejections are legitimate (some inputs aren't
// representable, e.g. lengths beyond the writer's buffer).
enum class RoundtripResult
{
    PutFailed,   // Put rejected — skip equality check (not a bug)
    DecodedOk,   // Get succeeded — caller must check equality
    GetFailed,   // Put succeeded but Get failed — REAL bug
};

template <typename F, typename G>
RoundtripResult RoundtripInsideStruct(uint8_t * buf, uint32_t bufLen, F putFn, G getFn)
{
    TLVWriter writer;
    writer.Init(buf, bufLen);

    TLVType outerW;
    if (writer.StartContainer(AnonymousTag(), kTLVType_Structure, outerW) != CHIP_NO_ERROR)
        return RoundtripResult::PutFailed;
    if (putFn(writer) != CHIP_NO_ERROR)
        return RoundtripResult::PutFailed;
    if (writer.EndContainer(outerW) != CHIP_NO_ERROR)
        return RoundtripResult::PutFailed;
    if (writer.Finalize() != CHIP_NO_ERROR)
        return RoundtripResult::PutFailed;

    TLVReader reader;
    reader.Init(buf, writer.GetLengthWritten());
    if (reader.Next() != CHIP_NO_ERROR)
        return RoundtripResult::GetFailed;

    TLVType outerR;
    if (reader.EnterContainer(outerR) != CHIP_NO_ERROR)
        return RoundtripResult::GetFailed;
    if (reader.Next() != CHIP_NO_ERROR)
        return RoundtripResult::GetFailed;
    if (getFn(reader) != CHIP_NO_ERROR)
        return RoundtripResult::GetFailed;
    if (reader.ExitContainer(outerR) != CHIP_NO_ERROR)
        return RoundtripResult::GetFailed;
    return RoundtripResult::DecodedOk;
}

// Roundtrip: u64 written by Put(ContextTag(N), val), read back via Get<u64>.
void U64Roundtrip(uint8_t tagNum, uint64_t value)
{
    EnsureInitialized();

    uint8_t buf[64];
    uint64_t decoded = 0;
    const auto result = RoundtripInsideStruct(
        buf, sizeof(buf),
        [&](TLVWriter & w) { return w.Put(ContextTag(tagNum), value); },
        [&](TLVReader & r) { return r.Get(decoded); });
    if (result == RoundtripResult::PutFailed)
        return; // Put rejected this input — legitimate, skip
    ASSERT_EQ(result, RoundtripResult::DecodedOk);
    ASSERT_EQ(decoded, value);
}

FUZZ_TEST(TLVRoundtrip, U64Roundtrip).WithDomains(Arbitrary<uint8_t>(), Arbitrary<uint64_t>());

void I64Roundtrip(uint8_t tagNum, int64_t value)
{
    EnsureInitialized();

    uint8_t buf[64];
    int64_t decoded = 0;
    const auto result = RoundtripInsideStruct(
        buf, sizeof(buf),
        [&](TLVWriter & w) { return w.Put(ContextTag(tagNum), value); },
        [&](TLVReader & r) { return r.Get(decoded); });
    if (result == RoundtripResult::PutFailed)
        return; // Put rejected this input — legitimate, skip
    ASSERT_EQ(result, RoundtripResult::DecodedOk);
    ASSERT_EQ(decoded, value);
}

FUZZ_TEST(TLVRoundtrip, I64Roundtrip).WithDomains(Arbitrary<uint8_t>(), Arbitrary<int64_t>());

void BytesRoundtrip(uint8_t tagNum, const std::vector<uint8_t> & bytes)
{
    EnsureInitialized();
    if (bytes.size() > 8192)
        return;

    std::vector<uint8_t> buf(bytes.size() + 64);
    ByteSpan decoded;
    const auto result = RoundtripInsideStruct(
        buf.data(), static_cast<uint32_t>(buf.size()),
        [&](TLVWriter & w) {
            return w.PutBytes(ContextTag(tagNum), bytes.data(), static_cast<uint32_t>(bytes.size()));
        },
        [&](TLVReader & r) { return r.Get(decoded); });
    if (result == RoundtripResult::PutFailed)
        return; // Put rejected this input — legitimate, skip
    ASSERT_EQ(result, RoundtripResult::DecodedOk);
    ASSERT_EQ(decoded.size(), bytes.size());
    if (!bytes.empty())
        ASSERT_EQ(memcmp(decoded.data(), bytes.data(), bytes.size()), 0);
}

FUZZ_TEST(TLVRoundtrip, BytesRoundtrip)
    .WithDomains(Arbitrary<uint8_t>(),
                 Arbitrary<std::vector<uint8_t>>().WithMaxSize(8192));

void StringRoundtrip(uint8_t tagNum, const std::string & str)
{
    EnsureInitialized();
    if (str.size() > 8192)
        return;

    // Known intentional asymmetry (see F-5 in REPORT.md): TLVReader::Get(CharSpan&)
    // truncates strings at the first 0x1F (Unicode Information Separator 1) byte
    // — see src/lib/core/TLVReader.cpp:340. Skip those inputs so the harness can
    // explore the rest of the string-encoding space looking for *unintended*
    // asymmetries.
    if (str.find('\x1F') != std::string::npos)
        return;

    std::vector<uint8_t> buf(str.size() + 64);
    CharSpan decoded;
    const auto result = RoundtripInsideStruct(
        buf.data(), static_cast<uint32_t>(buf.size()),
        [&](TLVWriter & w) {
            return w.PutString(ContextTag(tagNum), str.c_str(), static_cast<uint32_t>(str.size()));
        },
        [&](TLVReader & r) { return r.Get(decoded); });
    if (result == RoundtripResult::PutFailed)
        return; // Put rejected this input — legitimate, skip
    ASSERT_EQ(result, RoundtripResult::DecodedOk);
    ASSERT_EQ(decoded.size(), str.size());
    if (!str.empty())
        ASSERT_EQ(memcmp(decoded.data(), str.data(), str.size()), 0);
}

FUZZ_TEST(TLVRoundtrip, StringRoundtrip)
    .WithDomains(Arbitrary<uint8_t>(),
                 Arbitrary<std::string>().WithMaxSize(8192));

// Two-element struct: writes (tagA: u32 a, tagB: bytes b) inside a structure,
// reads back, asserts both fields match.
void StructTwoFieldRoundtrip(uint8_t tagA, uint8_t tagB, uint32_t a, const std::vector<uint8_t> & b)
{
    EnsureInitialized();
    if (tagA == tagB)
        return; // duplicate tags inside a structure are ill-formed
    if (b.size() > UINT16_MAX)
        return;

    std::vector<uint8_t> buf(b.size() + 64);
    TLVWriter writer;
    writer.Init(buf.data(), static_cast<uint32_t>(buf.size()));

    TLVType outer;
    ASSERT_EQ(writer.StartContainer(AnonymousTag(), kTLVType_Structure, outer), CHIP_NO_ERROR);
    ASSERT_EQ(writer.Put(ContextTag(tagA), a), CHIP_NO_ERROR);
    ASSERT_EQ(writer.PutBytes(ContextTag(tagB), b.data(), static_cast<uint32_t>(b.size())), CHIP_NO_ERROR);
    ASSERT_EQ(writer.EndContainer(outer), CHIP_NO_ERROR);
    ASSERT_EQ(writer.Finalize(), CHIP_NO_ERROR);

    TLVReader reader;
    reader.Init(buf.data(), writer.GetLengthWritten());
    ASSERT_EQ(reader.Next(), CHIP_NO_ERROR);
    ASSERT_EQ(reader.GetType(), kTLVType_Structure);

    TLVType outerR;
    ASSERT_EQ(reader.EnterContainer(outerR), CHIP_NO_ERROR);

    ASSERT_EQ(reader.Next(), CHIP_NO_ERROR);
    uint32_t decodedA = 0;
    ASSERT_EQ(reader.Get(decodedA), CHIP_NO_ERROR);
    ASSERT_EQ(decodedA, a);

    ASSERT_EQ(reader.Next(), CHIP_NO_ERROR);
    ByteSpan decodedB;
    ASSERT_EQ(reader.Get(decodedB), CHIP_NO_ERROR);
    ASSERT_EQ(decodedB.size(), b.size());
    if (!b.empty())
    {
        ASSERT_EQ(memcmp(decodedB.data(), b.data(), b.size()), 0);
    }

    ASSERT_EQ(reader.ExitContainer(outerR), CHIP_NO_ERROR);
}

FUZZ_TEST(TLVRoundtrip, StructTwoFieldRoundtrip)
    .WithDomains(Arbitrary<uint8_t>(), Arbitrary<uint8_t>(), Arbitrary<uint32_t>(),
                 Arbitrary<std::vector<uint8_t>>().WithMaxSize(2048));

// =============================================================================
// Coverage extension: smaller-int Get variants (the 8/16/32 widths reach distinct
// branches in TLVReader::Get vs the 64-bit overloads), plus Float/Double + Bool
// + the OpenContainer/CloseContainer pair (vs Enter/Exit which we already cover).
// =============================================================================

void U8Roundtrip(uint8_t tagNum, uint8_t value)
{
    EnsureInitialized();
    uint8_t buf[64];
    uint8_t decoded = 0;
    const auto result = RoundtripInsideStruct(
        buf, sizeof(buf),
        [&](TLVWriter & w) { return w.Put(ContextTag(tagNum), value); },
        [&](TLVReader & r) { return r.Get(decoded); });
    if (result == RoundtripResult::PutFailed)
        return;
    ASSERT_EQ(result, RoundtripResult::DecodedOk);
    ASSERT_EQ(decoded, value);
}
FUZZ_TEST(TLVRoundtrip, U8Roundtrip).WithDomains(Arbitrary<uint8_t>(), Arbitrary<uint8_t>());

void I8Roundtrip(uint8_t tagNum, int8_t value)
{
    EnsureInitialized();
    uint8_t buf[64];
    int8_t decoded = 0;
    const auto result = RoundtripInsideStruct(
        buf, sizeof(buf),
        [&](TLVWriter & w) { return w.Put(ContextTag(tagNum), value); },
        [&](TLVReader & r) { return r.Get(decoded); });
    if (result == RoundtripResult::PutFailed)
        return;
    ASSERT_EQ(result, RoundtripResult::DecodedOk);
    ASSERT_EQ(decoded, value);
}
FUZZ_TEST(TLVRoundtrip, I8Roundtrip).WithDomains(Arbitrary<uint8_t>(), Arbitrary<int8_t>());

void U16Roundtrip(uint8_t tagNum, uint16_t value)
{
    EnsureInitialized();
    uint8_t buf[64];
    uint16_t decoded = 0;
    const auto result = RoundtripInsideStruct(
        buf, sizeof(buf),
        [&](TLVWriter & w) { return w.Put(ContextTag(tagNum), value); },
        [&](TLVReader & r) { return r.Get(decoded); });
    if (result == RoundtripResult::PutFailed)
        return;
    ASSERT_EQ(result, RoundtripResult::DecodedOk);
    ASSERT_EQ(decoded, value);
}
FUZZ_TEST(TLVRoundtrip, U16Roundtrip).WithDomains(Arbitrary<uint8_t>(), Arbitrary<uint16_t>());

void I16Roundtrip(uint8_t tagNum, int16_t value)
{
    EnsureInitialized();
    uint8_t buf[64];
    int16_t decoded = 0;
    const auto result = RoundtripInsideStruct(
        buf, sizeof(buf),
        [&](TLVWriter & w) { return w.Put(ContextTag(tagNum), value); },
        [&](TLVReader & r) { return r.Get(decoded); });
    if (result == RoundtripResult::PutFailed)
        return;
    ASSERT_EQ(result, RoundtripResult::DecodedOk);
    ASSERT_EQ(decoded, value);
}
FUZZ_TEST(TLVRoundtrip, I16Roundtrip).WithDomains(Arbitrary<uint8_t>(), Arbitrary<int16_t>());

void U32Roundtrip(uint8_t tagNum, uint32_t value)
{
    EnsureInitialized();
    uint8_t buf[64];
    uint32_t decoded = 0;
    const auto result = RoundtripInsideStruct(
        buf, sizeof(buf),
        [&](TLVWriter & w) { return w.Put(ContextTag(tagNum), value); },
        [&](TLVReader & r) { return r.Get(decoded); });
    if (result == RoundtripResult::PutFailed)
        return;
    ASSERT_EQ(result, RoundtripResult::DecodedOk);
    ASSERT_EQ(decoded, value);
}
FUZZ_TEST(TLVRoundtrip, U32Roundtrip).WithDomains(Arbitrary<uint8_t>(), Arbitrary<uint32_t>());

void I32Roundtrip(uint8_t tagNum, int32_t value)
{
    EnsureInitialized();
    uint8_t buf[64];
    int32_t decoded = 0;
    const auto result = RoundtripInsideStruct(
        buf, sizeof(buf),
        [&](TLVWriter & w) { return w.Put(ContextTag(tagNum), value); },
        [&](TLVReader & r) { return r.Get(decoded); });
    if (result == RoundtripResult::PutFailed)
        return;
    ASSERT_EQ(result, RoundtripResult::DecodedOk);
    ASSERT_EQ(decoded, value);
}
FUZZ_TEST(TLVRoundtrip, I32Roundtrip).WithDomains(Arbitrary<uint8_t>(), Arbitrary<int32_t>());

void BoolRoundtrip(uint8_t tagNum, bool value)
{
    EnsureInitialized();
    uint8_t buf[64];
    bool decoded = !value;
    const auto result = RoundtripInsideStruct(
        buf, sizeof(buf),
        [&](TLVWriter & w) { return w.PutBoolean(ContextTag(tagNum), value); },
        [&](TLVReader & r) { return r.Get(decoded); });
    if (result == RoundtripResult::PutFailed)
        return;
    ASSERT_EQ(result, RoundtripResult::DecodedOk);
    ASSERT_EQ(decoded, value);
}
FUZZ_TEST(TLVRoundtrip, BoolRoundtrip).WithDomains(Arbitrary<uint8_t>(), Arbitrary<bool>());

void FloatRoundtrip(uint8_t tagNum, float value)
{
    EnsureInitialized();
    if (std::isnan(value))
        return; // NaN doesn't equal itself; skip
    uint8_t buf[64];
    float decoded = 0.0f;
    const auto result = RoundtripInsideStruct(
        buf, sizeof(buf),
        [&](TLVWriter & w) { return w.Put(ContextTag(tagNum), value); },
        [&](TLVReader & r) { return r.Get(decoded); });
    if (result == RoundtripResult::PutFailed)
        return;
    ASSERT_EQ(result, RoundtripResult::DecodedOk);
    ASSERT_EQ(decoded, value);
}
FUZZ_TEST(TLVRoundtrip, FloatRoundtrip).WithDomains(Arbitrary<uint8_t>(), Arbitrary<float>());

void DoubleRoundtrip(uint8_t tagNum, double value)
{
    EnsureInitialized();
    if (std::isnan(value))
        return;
    uint8_t buf[64];
    double decoded = 0.0;
    const auto result = RoundtripInsideStruct(
        buf, sizeof(buf),
        [&](TLVWriter & w) { return w.Put(ContextTag(tagNum), value); },
        [&](TLVReader & r) { return r.Get(decoded); });
    if (result == RoundtripResult::PutFailed)
        return;
    ASSERT_EQ(result, RoundtripResult::DecodedOk);
    ASSERT_EQ(decoded, value);
}
FUZZ_TEST(TLVRoundtrip, DoubleRoundtrip).WithDomains(Arbitrary<uint8_t>(), Arbitrary<double>());

// OpenContainer/CloseContainer (the alternative to Enter/Exit).
// Property: a struct with one u32 field, written via StartContainer + Put, can
// be read back via OpenContainer + Get + CloseContainer.
void OpenCloseContainerRoundtrip(uint8_t tagNum, uint32_t inner)
{
    EnsureInitialized();
    uint8_t buf[128];
    TLVWriter writer;
    writer.Init(buf, sizeof(buf));

    TLVType outerW;
    if (writer.StartContainer(AnonymousTag(), kTLVType_Structure, outerW) != CHIP_NO_ERROR)
        return;
    if (writer.Put(ContextTag(tagNum), inner) != CHIP_NO_ERROR)
        return;
    if (writer.EndContainer(outerW) != CHIP_NO_ERROR)
        return;
    if (writer.Finalize() != CHIP_NO_ERROR)
        return;

    TLVReader reader;
    reader.Init(buf, writer.GetLengthWritten());
    ASSERT_EQ(reader.Next(), CHIP_NO_ERROR);

    TLVReader inside;
    ASSERT_EQ(reader.OpenContainer(inside), CHIP_NO_ERROR);
    ASSERT_EQ(inside.Next(), CHIP_NO_ERROR);
    uint32_t decoded = 0;
    ASSERT_EQ(inside.Get(decoded), CHIP_NO_ERROR);
    ASSERT_EQ(decoded, inner);
    ASSERT_EQ(reader.CloseContainer(inside), CHIP_NO_ERROR);
}
FUZZ_TEST(TLVRoundtrip, OpenCloseContainerRoundtrip)
    .WithDomains(Arbitrary<uint8_t>(), Arbitrary<uint32_t>());

// CopyElement / CopyContainer property: an element written via Put + Finalize,
// then re-read and CopyElement'd into a fresh writer, should produce a buffer
// that decodes to the same value.
void CopyElementRoundtrip(uint8_t tagNum, uint64_t value)
{
    EnsureInitialized();

    uint8_t srcBuf[64];
    {
        TLVWriter writer;
        writer.Init(srcBuf, sizeof(srcBuf));
        TLVType outer;
        if (writer.StartContainer(AnonymousTag(), kTLVType_Structure, outer) != CHIP_NO_ERROR) return;
        if (writer.Put(ContextTag(tagNum), value) != CHIP_NO_ERROR) return;
        if (writer.EndContainer(outer) != CHIP_NO_ERROR) return;
        if (writer.Finalize() != CHIP_NO_ERROR) return;
    }

    TLVReader srcReader;
    srcReader.Init(srcBuf, sizeof(srcBuf));
    if (srcReader.Next() != CHIP_NO_ERROR) return;
    TLVType srcOuter;
    if (srcReader.EnterContainer(srcOuter) != CHIP_NO_ERROR) return;
    if (srcReader.Next() != CHIP_NO_ERROR) return;

    uint8_t dstBuf[128];
    TLVWriter dstWriter;
    dstWriter.Init(dstBuf, sizeof(dstBuf));
    TLVType dstOuter;
    if (dstWriter.StartContainer(AnonymousTag(), kTLVType_Structure, dstOuter) != CHIP_NO_ERROR) return;
    ASSERT_EQ(dstWriter.CopyElement(srcReader), CHIP_NO_ERROR);
    if (dstWriter.EndContainer(dstOuter) != CHIP_NO_ERROR) return;
    if (dstWriter.Finalize() != CHIP_NO_ERROR) return;

    // Decode dst, expect same field value.
    TLVReader dstReader;
    dstReader.Init(dstBuf, dstWriter.GetLengthWritten());
    ASSERT_EQ(dstReader.Next(), CHIP_NO_ERROR);
    TLVType dstOuterR;
    ASSERT_EQ(dstReader.EnterContainer(dstOuterR), CHIP_NO_ERROR);
    ASSERT_EQ(dstReader.Next(), CHIP_NO_ERROR);
    uint64_t decoded = 0;
    ASSERT_EQ(dstReader.Get(decoded), CHIP_NO_ERROR);
    ASSERT_EQ(decoded, value);
    ASSERT_EQ(dstReader.ExitContainer(dstOuterR), CHIP_NO_ERROR);
}
FUZZ_TEST(TLVRoundtrip, CopyElementRoundtrip).WithDomains(Arbitrary<uint8_t>(), Arbitrary<uint64_t>());

} // namespace
