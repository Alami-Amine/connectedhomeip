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
 *      Fuzzes chip::TLV::Utilities::Iterate / Find / Count — the recursive
 *      TLV walkers used by many higher-level decoders. The TLV reader itself
 *      is fuzzed by FuzzTlvReader; this drills into the Utilities helpers
 *      that recurse through containers via callbacks.
 */

#include <cstddef>
#include <cstdint>

#include <lib/core/TLVCommon.h>
#include <lib/core/TLVReader.h>
#include <lib/core/TLVTags.h>
#include <lib/core/TLVUtilities.h>

namespace {

CHIP_ERROR NoopHandler(const chip::TLV::TLVReader &, size_t, void *)
{
    return CHIP_NO_ERROR;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t len)
{
    chip::TLV::TLVReader reader;
    reader.Init(data, len);

    if (reader.Next() != CHIP_NO_ERROR)
    {
        return 0;
    }

    (void) chip::TLV::Utilities::Iterate(reader, NoopHandler, nullptr);
    (void) chip::TLV::Utilities::Iterate(reader, NoopHandler, nullptr, /* aRecurse= */ false);

    {
        size_t count = 0;
        (void) chip::TLV::Utilities::Count(reader, count);
    }

    {
        size_t count = 0;
        (void) chip::TLV::Utilities::Count(reader, count, /* aRecurse= */ false);
    }

    {
        chip::TLV::TLVReader found;
        (void) chip::TLV::Utilities::Find(reader, chip::TLV::AnonymousTag(), found);
    }

    return 0;
}
