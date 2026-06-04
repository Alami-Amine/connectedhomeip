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

// FuzzTest harness for the AccessControl cluster TLV DECODE paths (wire-reachable, attacker-
// controlled bytes decoded server-side via DecodableType::Decode). Beyond the generic per-type
// decoders (seeded with default-encoded ::Type skeletons), this harness adds populated-list and
// nested-TLV seeds for the security-critical shapes:
//   - AccessControlEntryStruct with non-empty subjects[] + targets[] (the ACL write payload).
//   - AccessControlExtensionStruct whose `data` octstr is itself a valid TLV list, mirroring the
//     server's CheckExtensionEntryDataFormat second-level parse (a two-level attacker-TLV surface).
//   - ReviewFabricRestrictions with a populated ARL list of nested restriction structs.
// These populated seeds exercise the list-iteration / nested-parse decode arms that default-encoded
// (empty-list) seeds leave uncovered.

#include <cstdint>
#include <utility>
#include <vector>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

#include <app/data-model/Encode.h>
#include <clusters/AccessControl/Commands.h>
#include <clusters/AccessControl/Structs.h>
#include <lib/core/TLV.h>
#include <lib/core/TLVWriter.h>

namespace chip {
namespace {

using namespace fuzztest;
using namespace chip::app;
using namespace chip::app::Clusters;
using namespace chip::app::Clusters::AccessControl;

volatile uint64_t gU64Sink = 0;
volatile uint8_t gU8Sink   = 0;

// Encodable Types come in several flavors: non-fabric Encode(writer,tag); fabric-scoped
// EncodeForWrite(writer,tag); fabric-scoped EncodeForWrite(FabricAwareTLVWriter,tag).
// Priority-tag dispatch picks whichever exists, with a graceful no-seed fallback.
namespace seed_detail {
struct P0
{
};
struct P1 : P0
{
};
struct P2 : P1
{
};
struct P3 : P2
{
};

template <typename T>
auto TryEnc(T & o, TLV::TLVWriter & w, P3) -> decltype(o.EncodeForWrite(w, TLV::AnonymousTag()))
{
    return o.EncodeForWrite(w, TLV::AnonymousTag());
}
template <typename T>
auto TryEnc(T & o, TLV::TLVWriter & w, P2)
    -> decltype(o.EncodeForWrite(std::declval<DataModel::FabricAwareTLVWriter &>(), TLV::AnonymousTag()))
{
    DataModel::FabricAwareTLVWriter fw(w, kUndefinedFabricIndex);
    return o.EncodeForWrite(fw, TLV::AnonymousTag());
}
template <typename T>
auto TryEnc(T & o, TLV::TLVWriter & w, P1) -> decltype(o.Encode(w, TLV::AnonymousTag()))
{
    return o.Encode(w, TLV::AnonymousTag());
}
template <typename T>
CHIP_ERROR TryEnc(T &, TLV::TLVWriter &, P0)
{
    return CHIP_ERROR_NOT_IMPLEMENTED;
}
} // namespace seed_detail

template <typename EncT>
std::vector<std::uint8_t> EncSeed()
{
    uint8_t buf[2048];
    TLV::TLVWriter writer;
    writer.Init(buf, sizeof(buf));
    EncT obj;
    if (seed_detail::TryEnc(obj, writer, seed_detail::P3{}) != CHIP_NO_ERROR || writer.Finalize() != CHIP_NO_ERROR)
    {
        return {};
    }
    return std::vector<std::uint8_t>(buf, buf + writer.GetLengthWritten());
}

template <typename T>
auto TryDecode(T & d, TLV::TLVReader & r, int) -> decltype(d.Decode(r, kUndefinedFabricIndex))
{
    return d.Decode(r, kUndefinedFabricIndex);
}
template <typename T>
CHIP_ERROR TryDecode(T & d, TLV::TLVReader & r, long)
{
    return d.Decode(r);
}
template <typename T>
void DriveDecode(const std::vector<std::uint8_t> & bytes)
{
    TLV::TLVReader reader;
    reader.Init(bytes.data(), bytes.size());
    if (reader.Next() != CHIP_NO_ERROR)
    {
        return;
    }
    T decoded;
    (void) TryDecode(decoded, reader, 0);
}

// ---- Generic broad coverage: every command / struct decoder, default-encoded seeds ----
void CommandDecode(const std::vector<std::uint8_t> & bytes)
{
    DriveDecode<Commands::ReviewFabricRestrictions::DecodableType>(bytes);
}
FUZZ_TEST(AccessControl, CommandDecode)
    .WithDomains(Arbitrary<std::vector<std::uint8_t>>().WithSeeds({
        EncSeed<Commands::ReviewFabricRestrictions::Type>(),
    }));

void StructDecode(const std::vector<std::uint8_t> & bytes)
{
    DriveDecode<Structs::AccessControlEntryStruct::DecodableType>(bytes);
    DriveDecode<Structs::AccessControlExtensionStruct::DecodableType>(bytes);
    DriveDecode<Structs::AccessControlTargetStruct::DecodableType>(bytes);
    DriveDecode<Structs::CommissioningAccessRestrictionEntryStruct::DecodableType>(bytes);
    DriveDecode<Structs::AccessRestrictionEntryStruct::DecodableType>(bytes);
    DriveDecode<Structs::AccessRestrictionStruct::DecodableType>(bytes);
}
FUZZ_TEST(AccessControl, StructDecode)
    .WithDomains(Arbitrary<std::vector<std::uint8_t>>().WithSeeds({
        EncSeed<Structs::AccessControlEntryStruct::Type>(),
        EncSeed<Structs::AccessControlExtensionStruct::Type>(),
        EncSeed<Structs::AccessControlTargetStruct::Type>(),
        EncSeed<Structs::CommissioningAccessRestrictionEntryStruct::Type>(),
        EncSeed<Structs::AccessRestrictionEntryStruct::Type>(),
        EncSeed<Structs::AccessRestrictionStruct::Type>(),
    }));

// ---- Populated-list seed: AccessControlEntryStruct with non-empty subjects + targets ----
std::vector<std::uint8_t> AclEntrySeed()
{
    uint8_t buf[512];
    TLV::TLVWriter writer;
    writer.Init(buf, sizeof(buf));

    Structs::AccessControlEntryStruct::Type entry;
    entry.privilege = AccessControlEntryPrivilegeEnum::kOperate;
    entry.authMode  = AccessControlEntryAuthModeEnum::kCase;

    static const uint64_t subjects[] = { 0x0001000000000001ULL, 0x0001000000000002ULL };
    entry.subjects.SetNonNull(DataModel::List<const uint64_t>(subjects));

    static Structs::AccessControlTargetStruct::Type targetItems[1];
    targetItems[0].cluster.SetNonNull(static_cast<chip::ClusterId>(0x0006));
    targetItems[0].endpoint.SetNonNull(static_cast<chip::EndpointId>(1));
    targetItems[0].deviceType.SetNull();
    entry.targets.SetNonNull(DataModel::List<const Structs::AccessControlTargetStruct::Type>(targetItems));
    entry.fabricIndex = 1;

    if (entry.EncodeForWrite(writer, TLV::AnonymousTag()) != CHIP_NO_ERROR || writer.Finalize() != CHIP_NO_ERROR)
    {
        return {};
    }
    return std::vector<std::uint8_t>(buf, buf + writer.GetLengthWritten());
}

void AclEntryDecode(const std::vector<std::uint8_t> & bytes)
{
    TLV::TLVReader reader;
    reader.Init(bytes.data(), bytes.size());
    if (reader.Next() != CHIP_NO_ERROR)
    {
        return;
    }
    Structs::AccessControlEntryStruct::DecodableType entry;
    if (entry.Decode(reader) != CHIP_NO_ERROR)
    {
        return;
    }
    if (!entry.subjects.IsNull())
    {
        auto it = entry.subjects.Value().begin();
        while (it.Next())
        {
            gU64Sink ^= it.GetValue();
        }
        (void) it.GetStatus();
    }
    if (!entry.targets.IsNull())
    {
        auto it = entry.targets.Value().begin();
        while (it.Next())
        {
            const auto & t = it.GetValue();
            if (!t.cluster.IsNull())
            {
                gU64Sink ^= static_cast<uint64_t>(t.cluster.Value());
            }
            if (!t.endpoint.IsNull())
            {
                gU64Sink ^= static_cast<uint64_t>(t.endpoint.Value());
            }
        }
        (void) it.GetStatus();
    }
}
FUZZ_TEST(AccessControl, AclEntryDecode)
    .WithDomains(Arbitrary<std::vector<std::uint8_t>>().WithSeeds({
        AclEntrySeed(),
    }));

// ---- Nested-TLV seed: AccessControlExtensionStruct whose `data` is itself a TLV list ----
std::vector<std::uint8_t> ExtensionSeed()
{
    uint8_t innerBuf[64];
    TLV::TLVWriter inner;
    inner.Init(innerBuf, sizeof(innerBuf));
    TLV::TLVType outerContainer;
    if (inner.StartContainer(TLV::AnonymousTag(), TLV::kTLVType_List, outerContainer) != CHIP_NO_ERROR)
    {
        return {};
    }
    if (inner.Put(TLV::ProfileTag(0x0001, 1), static_cast<uint8_t>(0x42)) != CHIP_NO_ERROR)
    {
        return {};
    }
    if (inner.EndContainer(outerContainer) != CHIP_NO_ERROR || inner.Finalize() != CHIP_NO_ERROR)
    {
        return {};
    }
    ByteSpan innerSpan(innerBuf, inner.GetLengthWritten());

    uint8_t outerBuf[256];
    TLV::TLVWriter writer;
    writer.Init(outerBuf, sizeof(outerBuf));
    Structs::AccessControlExtensionStruct::Type ext;
    ext.data        = innerSpan;
    ext.fabricIndex = 1;
    if (ext.EncodeForWrite(writer, TLV::AnonymousTag()) != CHIP_NO_ERROR || writer.Finalize() != CHIP_NO_ERROR)
    {
        return {};
    }
    return std::vector<std::uint8_t>(outerBuf, outerBuf + writer.GetLengthWritten());
}

void ExtensionDecode(const std::vector<std::uint8_t> & bytes)
{
    TLV::TLVReader reader;
    reader.Init(bytes.data(), bytes.size());
    if (reader.Next() != CHIP_NO_ERROR)
    {
        return;
    }
    Structs::AccessControlExtensionStruct::DecodableType ext;
    if (ext.Decode(reader) != CHIP_NO_ERROR)
    {
        return;
    }
    for (size_t i = 0; i < ext.data.size(); i++)
    {
        gU8Sink ^= ext.data.data()[i];
    }
    // Second-level parse, mirroring the server's CheckExtensionEntryDataFormat.
    if (ext.data.size() > 0)
    {
        TLV::TLVReader nested;
        nested.Init(ext.data);
        auto containerType = TLV::kTLVType_List;
        if (nested.Next(containerType, TLV::AnonymousTag()) != CHIP_NO_ERROR)
        {
            return;
        }
        if (nested.EnterContainer(containerType) != CHIP_NO_ERROR)
        {
            return;
        }
        while (nested.Next() == CHIP_NO_ERROR)
        {
            volatile auto tag = nested.GetTag();
            (void) tag;
        }
        (void) nested.ExitContainer(containerType);
    }
}
FUZZ_TEST(AccessControl, ExtensionDecode)
    .WithDomains(Arbitrary<std::vector<std::uint8_t>>().WithSeeds({
        ExtensionSeed(),
    }));

// ---- Populated-list seed: ReviewFabricRestrictions with a non-empty ARL list ----
std::vector<std::uint8_t> ReviewFabricRestrictionsSeed()
{
    uint8_t buf[512];
    TLV::TLVWriter writer;
    writer.Init(buf, sizeof(buf));

    Commands::ReviewFabricRestrictions::Type cmd;
    static Structs::AccessRestrictionStruct::Type restrictions[2];
    restrictions[0].type = AccessRestrictionTypeEnum::kAttributeAccessForbidden;
    restrictions[0].id.SetNonNull(static_cast<uint32_t>(0x0001));
    restrictions[1].type = AccessRestrictionTypeEnum::kCommandForbidden;
    restrictions[1].id.SetNull();

    static Structs::CommissioningAccessRestrictionEntryStruct::Type arlItems[1];
    arlItems[0].endpoint     = static_cast<chip::EndpointId>(1);
    arlItems[0].cluster      = static_cast<chip::ClusterId>(0x0006);
    arlItems[0].restrictions = DataModel::List<const Structs::AccessRestrictionStruct::Type>(restrictions);
    cmd.arl                  = DataModel::List<const Structs::CommissioningAccessRestrictionEntryStruct::Type>(arlItems);

    if (cmd.Encode(writer, TLV::AnonymousTag()) != CHIP_NO_ERROR || writer.Finalize() != CHIP_NO_ERROR)
    {
        return {};
    }
    return std::vector<std::uint8_t>(buf, buf + writer.GetLengthWritten());
}

void ReviewFabricRestrictionsDecode(const std::vector<std::uint8_t> & bytes)
{
    DriveDecode<Commands::ReviewFabricRestrictions::DecodableType>(bytes);
}
FUZZ_TEST(AccessControl, ReviewFabricRestrictionsDecode)
    .WithDomains(Arbitrary<std::vector<std::uint8_t>>().WithSeeds({
        ReviewFabricRestrictionsSeed(),
    }));

} // namespace
} // namespace chip
