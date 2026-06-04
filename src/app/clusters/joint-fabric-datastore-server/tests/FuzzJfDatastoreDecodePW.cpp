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

// FuzzTest harness for the JointFabricDatastore cluster TLV DECODE paths (wire-reachable, attacker-controlled
// bytes decoded server-side via DecodableType::Decode). Seeded with valid TLV from the matching
// encodable ::Type. Decode-only scope; handler post-decode logic covered by inspection in the writeup.

#include <cstdint>
#include <vector>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

#include <clusters/JointFabricDatastore/Commands.h>
#include <clusters/JointFabricDatastore/Structs.h>
#include <utility>

#include <app/data-model/Encode.h>
#include <lib/core/TLV.h>
#include <lib/core/TLVWriter.h>

namespace chip {
namespace {

using namespace fuzztest;
using namespace chip::app;
using namespace chip::app::Clusters;
using namespace chip::app::Clusters::JointFabricDatastore;

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

void CommandDecode(const std::vector<std::uint8_t> & bytes)
{
    DriveDecode<Commands::AddKeySet::DecodableType>(bytes);
    DriveDecode<Commands::UpdateKeySet::DecodableType>(bytes);
    DriveDecode<Commands::RemoveKeySet::DecodableType>(bytes);
    DriveDecode<Commands::AddGroup::DecodableType>(bytes);
    DriveDecode<Commands::UpdateGroup::DecodableType>(bytes);
    DriveDecode<Commands::RemoveGroup::DecodableType>(bytes);
    DriveDecode<Commands::AddAdmin::DecodableType>(bytes);
    DriveDecode<Commands::UpdateAdmin::DecodableType>(bytes);
    DriveDecode<Commands::RemoveAdmin::DecodableType>(bytes);
    DriveDecode<Commands::AddPendingNode::DecodableType>(bytes);
    DriveDecode<Commands::RefreshNode::DecodableType>(bytes);
    DriveDecode<Commands::UpdateNode::DecodableType>(bytes);
    DriveDecode<Commands::RemoveNode::DecodableType>(bytes);
    DriveDecode<Commands::UpdateEndpointForNode::DecodableType>(bytes);
    DriveDecode<Commands::AddGroupIDToEndpointForNode::DecodableType>(bytes);
    DriveDecode<Commands::RemoveGroupIDFromEndpointForNode::DecodableType>(bytes);
    DriveDecode<Commands::AddBindingToEndpointForNode::DecodableType>(bytes);
    DriveDecode<Commands::RemoveBindingFromEndpointForNode::DecodableType>(bytes);
    DriveDecode<Commands::AddACLToNode::DecodableType>(bytes);
    DriveDecode<Commands::RemoveACLFromNode::DecodableType>(bytes);
}
FUZZ_TEST(JointFabricDatastore, CommandDecode)
    .WithDomains(Arbitrary<std::vector<std::uint8_t>>().WithSeeds({
        EncSeed<Commands::AddKeySet::Type>(),
        EncSeed<Commands::UpdateKeySet::Type>(),
        EncSeed<Commands::RemoveKeySet::Type>(),
        EncSeed<Commands::AddGroup::Type>(),
        EncSeed<Commands::UpdateGroup::Type>(),
        EncSeed<Commands::RemoveGroup::Type>(),
        EncSeed<Commands::AddAdmin::Type>(),
        EncSeed<Commands::UpdateAdmin::Type>(),
        EncSeed<Commands::RemoveAdmin::Type>(),
        EncSeed<Commands::AddPendingNode::Type>(),
        EncSeed<Commands::RefreshNode::Type>(),
        EncSeed<Commands::UpdateNode::Type>(),
        EncSeed<Commands::RemoveNode::Type>(),
        EncSeed<Commands::UpdateEndpointForNode::Type>(),
        EncSeed<Commands::AddGroupIDToEndpointForNode::Type>(),
        EncSeed<Commands::RemoveGroupIDFromEndpointForNode::Type>(),
        EncSeed<Commands::AddBindingToEndpointForNode::Type>(),
        EncSeed<Commands::RemoveBindingFromEndpointForNode::Type>(),
        EncSeed<Commands::AddACLToNode::Type>(),
        EncSeed<Commands::RemoveACLFromNode::Type>(),
    }));

void StructDecode(const std::vector<std::uint8_t> & bytes)
{
    DriveDecode<Structs::DatastoreGroupKeySetStruct::DecodableType>(bytes);
    DriveDecode<Structs::DatastoreAccessControlEntryStruct::DecodableType>(bytes);
    DriveDecode<Structs::DatastoreBindingTargetStruct::DecodableType>(bytes);
    DriveDecode<Structs::DatastoreStatusEntryStruct::DecodableType>(bytes);
    DriveDecode<Structs::DatastoreAccessControlTargetStruct::DecodableType>(bytes);
    DriveDecode<Structs::DatastoreAdministratorInformationEntryStruct::DecodableType>(bytes);
    DriveDecode<Structs::DatastoreNodeInformationEntryStruct::DecodableType>(bytes);
    DriveDecode<Structs::DatastoreGroupInformationEntryStruct::DecodableType>(bytes);
    DriveDecode<Structs::DatastoreACLEntryStruct::DecodableType>(bytes);
    DriveDecode<Structs::DatastoreEndpointEntryStruct::DecodableType>(bytes);
    DriveDecode<Structs::DatastoreEndpointGroupIDEntryStruct::DecodableType>(bytes);
    DriveDecode<Structs::DatastoreEndpointBindingEntryStruct::DecodableType>(bytes);
    DriveDecode<Structs::DatastoreNodeKeySetEntryStruct::DecodableType>(bytes);
}
FUZZ_TEST(JointFabricDatastore, StructDecode)
    .WithDomains(Arbitrary<std::vector<std::uint8_t>>().WithSeeds({
        EncSeed<Structs::DatastoreGroupKeySetStruct::Type>(),
        EncSeed<Structs::DatastoreAccessControlEntryStruct::Type>(),
        EncSeed<Structs::DatastoreBindingTargetStruct::Type>(),
        EncSeed<Structs::DatastoreStatusEntryStruct::Type>(),
        EncSeed<Structs::DatastoreAccessControlTargetStruct::Type>(),
        EncSeed<Structs::DatastoreAdministratorInformationEntryStruct::Type>(),
        EncSeed<Structs::DatastoreNodeInformationEntryStruct::Type>(),
        EncSeed<Structs::DatastoreGroupInformationEntryStruct::Type>(),
        EncSeed<Structs::DatastoreACLEntryStruct::Type>(),
        EncSeed<Structs::DatastoreEndpointEntryStruct::Type>(),
        EncSeed<Structs::DatastoreEndpointGroupIDEntryStruct::Type>(),
        EncSeed<Structs::DatastoreEndpointBindingEntryStruct::Type>(),
        EncSeed<Structs::DatastoreNodeKeySetEntryStruct::Type>(),
    }));

} // namespace
} // namespace chip