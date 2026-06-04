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

// FuzzTest harnesses for the Thermostat cluster, in one binary:
//
//   * ThermostatPresets.PresetOwnedMemberLifetime — drives the PRODUCTION-reachable lifetime
//     operations of PresetStructWithOwnedMembers (decode a PresetStruct from wire TLV, converting-
//     assign into owned storage, copy-assign, self-assign, read back owned spans). These deep-copy
//     and re-point spans into the object's own buffers, so it is expected-clean. The class's IMPLICIT
//     copy *constructor* (declares operator= but no copy ctor) leaves a copy's spans aliasing the
//     source's buffers -- a latent heap-UAF -- intentionally NOT exercised here (production cannot
//     copy-construct it; `-Werror -Wdeprecated-copy-with-user-provided-copy` rejects it at compile
//     time). See the audit writeup; recommended fix is `= delete` (or define) the copy ctor.
//
//   * Thermostat.CommandDecode / Thermostat.StructDecode — wire-reachable TLV decode of the schedule
//     / atomic / suggestion commands + the ScheduleStruct family (the part of Thermostat Structs.ipp
//     not covered by the preset path). Seeded with valid TLV from the matching encodable ::Type.

#include <cstdint>
#include <type_traits>
#include <utility>
#include <vector>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

#include <app/clusters/thermostat-server/PresetStructWithOwnedMembers.h>
#include <app/data-model/Encode.h>
#include <clusters/Thermostat/Commands.h>
#include <clusters/Thermostat/Structs.h>
#include <clusters/shared/Structs.h>
#include <lib/core/Optional.h>
#include <lib/core/TLV.h>
#include <lib/core/TLVWriter.h>
#include <lib/support/Span.h>

namespace chip {
namespace {

using namespace fuzztest;
using namespace chip::app;
using namespace chip::app::Clusters;
using namespace chip::app::Clusters::Thermostat;

// ===========================================================================
// PresetStructWithOwnedMembers owned-member lifetime harness
// ===========================================================================

// Rule-of-5 guard: this type owns fixed buffers and re-points its inherited spans into them, so a
// copy MUST NOT be constructible via the implicit memberwise copy ctor (that would leave a copy's
// spans aliasing the *source's* buffers -> heap-UAF once the source dies). The user-declared
// operator= re-points correctly; the copy constructor must be `= delete`d (or defined). See audit
// finding 02. This assert is RED before the fix (the implicit copy ctor makes the type
// copy-constructible) and GREEN after.
static_assert(!std::is_copy_constructible<PresetStructWithOwnedMembers>::value,
              "PresetStructWithOwnedMembers must not be copy-constructible (rule-of-5: owned spans "
              "would alias the source's buffers -> heap-UAF). = delete the copy ctor; see audit 02.");

volatile uint8_t gByteSink = 0;
volatile char gCharSink    = 0;

void TouchOwnedMembers(const PresetStructWithOwnedMembers & p)
{
    auto handle = p.GetPresetHandle();
    if (!handle.IsNull())
    {
        const ByteSpan & span = handle.Value();
        for (size_t i = 0; i < span.size(); i++)
        {
            gByteSink = static_cast<uint8_t>(gByteSink ^ span.data()[i]);
        }
    }
    auto name = p.GetName();
    if (name.HasValue() && !name.Value().IsNull())
    {
        const CharSpan & span = name.Value().Value();
        for (size_t i = 0; i < span.size(); i++)
        {
            gCharSink = static_cast<char>(gCharSink ^ span.data()[i]);
        }
    }
}

// A fully-populated PresetStruct seed: non-null presetHandle, a name, both setpoints, builtIn.
std::vector<std::uint8_t> PresetSeed()
{
    uint8_t buf[256];
    TLV::TLVWriter writer;
    writer.Init(buf, sizeof(buf));

    Structs::PresetStruct::Type p;
    static const uint8_t handle[] = { 0x11, 0x22, 0x33, 0x44 };
    p.presetHandle.SetNonNull(ByteSpan(handle));
    p.presetScenario       = static_cast<PresetScenarioEnum>(1);
    static const char nm[] = "wake";
    p.name.SetValue(DataModel::Nullable<CharSpan>(CharSpan(nm, sizeof(nm) - 1)));
    p.coolingSetpoint.SetValue(static_cast<int16_t>(2500));
    p.heatingSetpoint.SetValue(static_cast<int16_t>(2000));
    p.builtIn.SetNonNull(true);

    if (p.Encode(writer, TLV::AnonymousTag()) != CHIP_NO_ERROR || writer.Finalize() != CHIP_NO_ERROR)
    {
        return {};
    }
    return std::vector<std::uint8_t>(buf, buf + writer.GetLengthWritten());
}

void PresetOwnedMemberLifetime(const std::vector<std::uint8_t> & bytes)
{
    TLV::TLVReader reader;
    reader.Init(bytes.data(), bytes.size());
    if (reader.Next() != CHIP_NO_ERROR)
    {
        return;
    }
    Structs::PresetStruct::Type decoded;
    if (decoded.Decode(reader) != CHIP_NO_ERROR)
    {
        return;
    }

    // Converting-assign into owned storage (deep copy + re-point spans).
    PresetStructWithOwnedMembers owned;
    owned = decoded;
    TouchOwnedMembers(owned);

    // Copy-assignment between owned structs (deep copy).
    PresetStructWithOwnedMembers copyAssigned;
    copyAssigned = owned;
    TouchOwnedMembers(copyAssigned);

    // Self-assignment via pointer indirection (exercise the this==&other guard).
    PresetStructWithOwnedMembers * selfPtr = &copyAssigned;
    copyAssigned                           = *selfPtr;
    TouchOwnedMembers(copyAssigned);
}
FUZZ_TEST(ThermostatPresets, PresetOwnedMemberLifetime)
    .WithDomains(Arbitrary<std::vector<std::uint8_t>>().WithSeeds({ PresetSeed() }));

// ===========================================================================
// Thermostat schedule / atomic / suggestion decode harness
// ===========================================================================

// Encodable Types come in several flavors (non-fabric Encode; fabric-scoped EncodeForWrite on a
// plain or fabric-aware writer). Priority-tag dispatch picks whichever exists, with a graceful
// no-seed fallback.
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
    DriveDecode<Commands::SetWeeklySchedule::DecodableType>(bytes);
    DriveDecode<Commands::GetWeeklySchedule::DecodableType>(bytes);
    DriveDecode<Commands::ClearWeeklySchedule::DecodableType>(bytes);
    DriveDecode<Commands::SetActiveScheduleRequest::DecodableType>(bytes);
    DriveDecode<Commands::SetActivePresetRequest::DecodableType>(bytes);
    DriveDecode<Commands::AtomicRequest::DecodableType>(bytes);
    DriveDecode<Commands::AddThermostatSuggestion::DecodableType>(bytes);
    DriveDecode<Commands::RemoveThermostatSuggestion::DecodableType>(bytes);
}
FUZZ_TEST(Thermostat, CommandDecode)
    .WithDomains(Arbitrary<std::vector<std::uint8_t>>().WithSeeds({
        EncSeed<Commands::SetWeeklySchedule::Type>(),
        EncSeed<Commands::GetWeeklySchedule::Type>(),
        EncSeed<Commands::ClearWeeklySchedule::Type>(),
        EncSeed<Commands::SetActiveScheduleRequest::Type>(),
        EncSeed<Commands::SetActivePresetRequest::Type>(),
        EncSeed<Commands::AtomicRequest::Type>(),
        EncSeed<Commands::AddThermostatSuggestion::Type>(),
        EncSeed<Commands::RemoveThermostatSuggestion::Type>(),
    }));

void StructDecode(const std::vector<std::uint8_t> & bytes)
{
    DriveDecode<Structs::ScheduleStruct::DecodableType>(bytes);
    DriveDecode<Structs::ScheduleTransitionStruct::DecodableType>(bytes);
    DriveDecode<Structs::WeeklyScheduleTransitionStruct::DecodableType>(bytes);
    DriveDecode<Globals::Structs::AtomicAttributeStatusStruct::DecodableType>(bytes);
}
FUZZ_TEST(Thermostat, StructDecode)
    .WithDomains(Arbitrary<std::vector<std::uint8_t>>().WithSeeds({
        EncSeed<Structs::ScheduleStruct::Type>(),
        EncSeed<Structs::ScheduleTransitionStruct::Type>(),
        EncSeed<Structs::WeeklyScheduleTransitionStruct::Type>(),
        EncSeed<Globals::Structs::AtomicAttributeStatusStruct::Type>(),
    }));

} // namespace
} // namespace chip
