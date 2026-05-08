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
 *      Fuzzes the IM "building-block" Parsers below the message level:
 *      AttributePathIB, CommandPathIB, EventPathIB, ClusterPathIB,
 *      AttributeDataIB, EventDataIB, CommandDataIB, AttributeStatusIB,
 *      CommandStatusIB. These are reached from every IM message; subtle
 *      bounds bugs here propagate to every IM exchange post-CASE.
 */

#include <cstddef>
#include <cstdint>

#include <app/MessageDef/AttributeDataIB.h>
#include <app/MessageDef/AttributePathIB.h>
#include <app/MessageDef/AttributeStatusIB.h>
#include <app/MessageDef/ClusterPathIB.h>
#include <app/MessageDef/CommandDataIB.h>
#include <app/MessageDef/CommandPathIB.h>
#include <app/MessageDef/CommandStatusIB.h>
#include <app/MessageDef/EventDataIB.h>
#include <app/MessageDef/EventPathIB.h>
#include <app/MessageDef/StatusIB.h>
#include <lib/core/TLVReader.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>

namespace {

bool EnsureInitialized()
{
    static const bool sInitialized = [] {
        VerifyOrDie(chip::Platform::MemoryInit() == CHIP_NO_ERROR);
        return true;
    }();
    return sInitialized;
}

template <typename Parser>
void DriveParser(const uint8_t * data, size_t len)
{
    chip::TLV::TLVReader reader;
    reader.Init(data, len);

    if (reader.Next() != CHIP_NO_ERROR)
    {
        return;
    }

    Parser parser;
    if (parser.Init(reader) != CHIP_NO_ERROR)
    {
        return;
    }
#if CHIP_CONFIG_IM_PRETTY_PRINT
    (void) parser.PrettyPrint();
#endif
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t len)
{
    using namespace chip::app;

    (void) EnsureInitialized();

    if (len == 0)
    {
        return 0;
    }

    const uint8_t selector = data[0] % 9;
    const uint8_t * body   = data + 1;
    const size_t bodyLen   = len - 1;

    switch (selector)
    {
    case 0:
        DriveParser<AttributePathIB::Parser>(body, bodyLen);
        break;
    case 1:
        DriveParser<CommandPathIB::Parser>(body, bodyLen);
        break;
    case 2:
        DriveParser<EventPathIB::Parser>(body, bodyLen);
        break;
    case 3:
        DriveParser<ClusterPathIB::Parser>(body, bodyLen);
        break;
    case 4:
        DriveParser<AttributeDataIB::Parser>(body, bodyLen);
        break;
    case 5:
        DriveParser<EventDataIB::Parser>(body, bodyLen);
        break;
    case 6:
        DriveParser<CommandDataIB::Parser>(body, bodyLen);
        break;
    case 7:
        DriveParser<AttributeStatusIB::Parser>(body, bodyLen);
        break;
    case 8:
        DriveParser<CommandStatusIB::Parser>(body, bodyLen);
        break;
    }

    return 0;
}
