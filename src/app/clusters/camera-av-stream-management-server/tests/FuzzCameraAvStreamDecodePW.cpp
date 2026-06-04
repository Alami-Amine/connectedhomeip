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

// FuzzTest harness for the Camera AV Stream Management cluster's TLV decoders.
// Each FUZZ_TEST is seeded with valid TLV produced by encoding the matching
// encodable `::Type` (default-constructed, or with populated lists for the
// list-bearing types). Seeding gives the mutator a structurally-valid skeleton
// to mutate -- without it, Arbitrary<vector<uint8_t>> rarely forms TLV that even
// passes the struct-enter, so the deep decode/value arms stay uncovered.

#include <cstdint>
#include <vector>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

#include <clusters/CameraAvStreamManagement/Commands.h>
#include <clusters/CameraAvStreamManagement/Structs.h>
#include <lib/core/TLV.h>
#include <lib/core/TLVWriter.h>

namespace chip {
namespace {

using namespace fuzztest;
using namespace chip::app;           // DataModel::
using namespace chip::app::Clusters; // Globals::
using namespace chip::app::Clusters::CameraAvStreamManagement;

// Encode a default-constructed encodable Type into a valid TLV element (seed).
template <typename EncT>
std::vector<std::uint8_t> EncDefault()
{
    uint8_t buf[1024];
    TLV::TLVWriter writer;
    writer.Init(buf, sizeof(buf));
    EncT obj;
    if (obj.Encode(writer, TLV::AnonymousTag()) != CHIP_NO_ERROR)
    {
        return {};
    }
    if (writer.Finalize() != CHIP_NO_ERROR)
    {
        return {};
    }
    return std::vector<std::uint8_t>(buf, buf + writer.GetLengthWritten());
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
    (void) decoded.Decode(reader);
}

void CommandDecode(const std::vector<std::uint8_t> & bytes)
{
    DriveDecode<Commands::AudioStreamAllocate::DecodableType>(bytes);
    DriveDecode<Commands::VideoStreamAllocate::DecodableType>(bytes);
    DriveDecode<Commands::VideoStreamModify::DecodableType>(bytes);
    DriveDecode<Commands::SnapshotStreamAllocate::DecodableType>(bytes);
    DriveDecode<Commands::SnapshotStreamModify::DecodableType>(bytes);
    DriveDecode<Commands::CaptureSnapshot::DecodableType>(bytes);
}
FUZZ_TEST(CameraAvStream, CommandDecode)
    .WithDomains(Arbitrary<std::vector<std::uint8_t>>().WithSeeds({
        EncDefault<Commands::AudioStreamAllocate::Type>(),
        EncDefault<Commands::VideoStreamAllocate::Type>(),
        EncDefault<Commands::VideoStreamModify::Type>(),
        EncDefault<Commands::SnapshotStreamAllocate::Type>(),
        EncDefault<Commands::SnapshotStreamModify::Type>(),
        EncDefault<Commands::CaptureSnapshot::Type>(),
    }));

void StructDecode(const std::vector<std::uint8_t> & bytes)
{
    DriveDecode<Structs::VideoResolutionStruct::DecodableType>(bytes);
    DriveDecode<Structs::VideoStreamStruct::DecodableType>(bytes);
    DriveDecode<Structs::SnapshotStreamStruct::DecodableType>(bytes);
    DriveDecode<Structs::AudioStreamStruct::DecodableType>(bytes);
    DriveDecode<Structs::VideoSensorParamsStruct::DecodableType>(bytes);
    DriveDecode<Structs::RateDistortionTradeOffPointsStruct::DecodableType>(bytes);
}
FUZZ_TEST(CameraAvStream, StructDecode)
    .WithDomains(Arbitrary<std::vector<std::uint8_t>>().WithSeeds({
        EncDefault<Structs::VideoResolutionStruct::Type>(),
        EncDefault<Structs::VideoStreamStruct::Type>(),
        EncDefault<Structs::SnapshotStreamStruct::Type>(),
        EncDefault<Structs::AudioStreamStruct::Type>(),
        EncDefault<Structs::VideoSensorParamsStruct::Type>(),
        EncDefault<Structs::RateDistortionTradeOffPointsStruct::Type>(),
    }));

// Seed SetStreamPriorities with a populated streamPriorities list so the
// element-iteration arm is exercised from the start.
std::vector<std::uint8_t> SetStreamPrioritiesSeed()
{
    uint8_t buf[256];
    TLV::TLVWriter writer;
    writer.Init(buf, sizeof(buf));
    Commands::SetStreamPriorities::Type cmd;
    const Globals::StreamUsageEnum prios[] = { Globals::StreamUsageEnum::kInternal, Globals::StreamUsageEnum::kRecording,
                                               Globals::StreamUsageEnum::kAnalysis };
    cmd.streamPriorities                   = DataModel::List<const Globals::StreamUsageEnum>(prios);
    if (cmd.Encode(writer, TLV::AnonymousTag()) != CHIP_NO_ERROR || writer.Finalize() != CHIP_NO_ERROR)
    {
        return {};
    }
    return std::vector<std::uint8_t>(buf, buf + writer.GetLengthWritten());
}

void SetStreamPrioritiesDecode(const std::vector<std::uint8_t> & bytes)
{
    TLV::TLVReader reader;
    reader.Init(bytes.data(), bytes.size());
    if (reader.Next() != CHIP_NO_ERROR)
    {
        return;
    }
    Commands::SetStreamPriorities::DecodableType cmd;
    if (cmd.Decode(reader) != CHIP_NO_ERROR)
    {
        return;
    }
    auto iter = cmd.streamPriorities.begin();
    while (iter.Next())
    {
        volatile auto v = iter.GetValue();
        (void) v;
    }
    (void) iter.GetStatus();
}
FUZZ_TEST(CameraAvStream, SetStreamPrioritiesDecode)
    .WithDomains(Arbitrary<std::vector<std::uint8_t>>().WithSeeds({ SetStreamPrioritiesSeed() }));

// Seed AudioCapabilitiesStruct with populated lists.
std::vector<std::uint8_t> AudioCapabilitiesSeed()
{
    uint8_t buf[256];
    TLV::TLVWriter writer;
    writer.Init(buf, sizeof(buf));
    Structs::AudioCapabilitiesStruct::Type s;
    s.maxNumberOfChannels         = 2;
    const AudioCodecEnum codecs[] = { AudioCodecEnum::kOpus, AudioCodecEnum::kAacLc };
    const uint32_t rates[]        = { 8000, 16000, 48000 };
    const uint8_t depths[]        = { 16, 24 };
    s.supportedCodecs             = DataModel::List<const AudioCodecEnum>(codecs);
    s.supportedSampleRates        = DataModel::List<const uint32_t>(rates);
    s.supportedBitDepths          = DataModel::List<const uint8_t>(depths);
    if (s.Encode(writer, TLV::AnonymousTag()) != CHIP_NO_ERROR || writer.Finalize() != CHIP_NO_ERROR)
    {
        return {};
    }
    return std::vector<std::uint8_t>(buf, buf + writer.GetLengthWritten());
}

void AudioCapabilitiesDecode(const std::vector<std::uint8_t> & bytes)
{
    TLV::TLVReader reader;
    reader.Init(bytes.data(), bytes.size());
    if (reader.Next() != CHIP_NO_ERROR)
    {
        return;
    }
    Structs::AudioCapabilitiesStruct::DecodableType s;
    if (s.Decode(reader) != CHIP_NO_ERROR)
    {
        return;
    }
    {
        auto it = s.supportedCodecs.begin();
        while (it.Next())
        {
            volatile auto v = it.GetValue();
            (void) v;
        }
        (void) it.GetStatus();
    }
    {
        auto it = s.supportedSampleRates.begin();
        while (it.Next())
        {
            volatile auto v = it.GetValue();
            (void) v;
        }
        (void) it.GetStatus();
    }
    {
        auto it = s.supportedBitDepths.begin();
        while (it.Next())
        {
            volatile auto v = it.GetValue();
            (void) v;
        }
        (void) it.GetStatus();
    }
}
FUZZ_TEST(CameraAvStream, AudioCapabilitiesDecode)
    .WithDomains(Arbitrary<std::vector<std::uint8_t>>().WithSeeds({ AudioCapabilitiesSeed() }));

} // namespace
} // namespace chip
