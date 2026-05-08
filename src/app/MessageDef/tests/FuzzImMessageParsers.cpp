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
 *      Fuzzes the typed Interaction Model message Parsers used to decode
 *      every IM exchange after CASE: InvokeRequest, ReadRequest,
 *      SubscribeRequest, WriteRequest, ReportData, StatusResponse,
 *      InvokeResponse. Each parser walks an attacker-controlled TLV stream;
 *      bugs here are reachable post-CASE from any peer fabric node.
 *
 *      The first input byte selects which parser to drive. The remainder is
 *      handed to a TLV reader and to PrettyPrint(), which exercises the full
 *      schema-validation walk over the parsed structure.
 */

#include <cstddef>
#include <cstdint>

#include <app/MessageDef/InvokeRequestMessage.h>
#include <app/MessageDef/InvokeResponseMessage.h>
#include <app/MessageDef/ReadRequestMessage.h>
#include <app/MessageDef/ReportDataMessage.h>
#include <app/MessageDef/StatusResponseMessage.h>
#include <app/MessageDef/SubscribeRequestMessage.h>
#include <app/MessageDef/WriteRequestMessage.h>
#include <lib/core/CHIPError.h>
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
    (void) parser.ExitContainer();
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

    const uint8_t selector = data[0] % 7;
    const uint8_t * body   = data + 1;
    const size_t bodyLen   = len - 1;

    switch (selector)
    {
    case 0:
        DriveParser<InvokeRequestMessage::Parser>(body, bodyLen);
        break;
    case 1:
        DriveParser<InvokeResponseMessage::Parser>(body, bodyLen);
        break;
    case 2:
        DriveParser<ReadRequestMessage::Parser>(body, bodyLen);
        break;
    case 3:
        DriveParser<SubscribeRequestMessage::Parser>(body, bodyLen);
        break;
    case 4:
        DriveParser<WriteRequestMessage::Parser>(body, bodyLen);
        break;
    case 5:
        DriveParser<ReportDataMessage::Parser>(body, bodyLen);
        break;
    case 6:
        DriveParser<StatusResponseMessage::Parser>(body, bodyLen);
        break;
    }

    return 0;
}
