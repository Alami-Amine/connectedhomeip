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

// FuzzTest harness for the OperationalCredentials cluster TLV DECODE paths (wire-reachable, attacker-controlled
// bytes decoded server-side via DecodableType::Decode). Seeded with valid TLV from the matching
// encodable ::Type so the mutator reaches deep decode arms. Decode-only scope; server-handler
// post-decode logic is covered by inspection in the audit writeup, not here.

#include <cstdint>
#include <vector>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

#include <clusters/OperationalCredentials/Commands.h>
#include <clusters/OperationalCredentials/Structs.h>
#include <utility>

#include <app/data-model/Encode.h>
#include <lib/core/TLV.h>
#include <lib/core/TLVWriter.h>

namespace chip {
namespace {

using namespace fuzztest;
using namespace chip::app;
using namespace chip::app::Clusters;
using namespace chip::app::Clusters::OperationalCredentials;

// Encodable Types come in several flavors depending on fabric-scoping:
//   - non-fabric:                 Encode(TLV::TLVWriter&, tag)
//   - fabric-scoped (common):     EncodeForWrite(TLV::TLVWriter&, tag)
//   - fabric-scoped (write-aware): EncodeForWrite(DataModel::FabricAwareTLVWriter&, tag)
// Priority-tag dispatch picks whichever exists (P3>P2>P1), with a graceful no-seed fallback (P0).
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

// Fabric-scoped DecodableTypes expose Decode(reader, fabricIndex); others expose Decode(reader).
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
    DriveDecode<Commands::AttestationRequest::DecodableType>(bytes);
    DriveDecode<Commands::CertificateChainRequest::DecodableType>(bytes);
    DriveDecode<Commands::CSRRequest::DecodableType>(bytes);
    DriveDecode<Commands::AddNOC::DecodableType>(bytes);
    DriveDecode<Commands::UpdateNOC::DecodableType>(bytes);
    DriveDecode<Commands::NOCResponse::DecodableType>(bytes);
    DriveDecode<Commands::UpdateFabricLabel::DecodableType>(bytes);
    DriveDecode<Commands::RemoveFabric::DecodableType>(bytes);
    DriveDecode<Commands::AddTrustedRootCertificate::DecodableType>(bytes);
    DriveDecode<Commands::SetVIDVerificationStatement::DecodableType>(bytes);
    DriveDecode<Commands::SignVIDVerificationRequest::DecodableType>(bytes);
}
FUZZ_TEST(OperationalCredentials, CommandDecode)
    .WithDomains(Arbitrary<std::vector<std::uint8_t>>().WithSeeds({
        EncSeed<Commands::AttestationRequest::Type>(),
        EncSeed<Commands::CertificateChainRequest::Type>(),
        EncSeed<Commands::CSRRequest::Type>(),
        EncSeed<Commands::AddNOC::Type>(),
        EncSeed<Commands::UpdateNOC::Type>(),
        EncSeed<Commands::NOCResponse::Type>(),
        EncSeed<Commands::UpdateFabricLabel::Type>(),
        EncSeed<Commands::RemoveFabric::Type>(),
        EncSeed<Commands::AddTrustedRootCertificate::Type>(),
        EncSeed<Commands::SetVIDVerificationStatement::Type>(),
        EncSeed<Commands::SignVIDVerificationRequest::Type>(),
    }));

void StructDecode(const std::vector<std::uint8_t> & bytes)
{
    DriveDecode<Structs::FabricDescriptorStruct::DecodableType>(bytes);
    DriveDecode<Structs::NOCStruct::DecodableType>(bytes);
}
FUZZ_TEST(OperationalCredentials, StructDecode)
    .WithDomains(Arbitrary<std::vector<std::uint8_t>>().WithSeeds({
        EncSeed<Structs::FabricDescriptorStruct::Type>(),
        EncSeed<Structs::NOCStruct::Type>(),
    }));

} // namespace
} // namespace chip
