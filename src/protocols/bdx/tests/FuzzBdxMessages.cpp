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
 *      Fuzzes the typed BDX message Parse() implementations: TransferInit,
 *      SendAccept, ReceiveAccept, CounterMessage, DataBlock, BlockQueryWithSkip.
 *      The first input byte selects which Parse() to drive; the remainder is
 *      copied into a PacketBuffer.
 */

#include <cstddef>
#include <cstdint>

#include <lib/support/CHIPMem.h>
#include <protocols/bdx/BdxMessages.h>
#include <system/SystemPacketBuffer.h>

namespace {

bool EnsureInitialized()
{
    static const bool sInitialized = [] {
        VerifyOrDie(chip::Platform::MemoryInit() == CHIP_NO_ERROR);
        return true;
    }();
    return sInitialized;
}

template <typename Msg>
void FuzzOne(const uint8_t * data, size_t len)
{
    auto buf = chip::System::PacketBufferHandle::NewWithData(data, len);
    if (buf.IsNull())
    {
        return;
    }
    Msg msg;
    (void) msg.Parse(std::move(buf));
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t len)
{
    using namespace chip::bdx;

    (void) EnsureInitialized();

    if (len == 0)
    {
        return 0;
    }

    const uint8_t selector = data[0] % 6;
    const uint8_t * body   = data + 1;
    const size_t bodyLen   = len - 1;

    switch (selector)
    {
    case 0:
        FuzzOne<TransferInit>(body, bodyLen);
        break;
    case 1:
        FuzzOne<SendAccept>(body, bodyLen);
        break;
    case 2:
        FuzzOne<ReceiveAccept>(body, bodyLen);
        break;
    case 3:
        FuzzOne<CounterMessage>(body, bodyLen);
        break;
    case 4:
        FuzzOne<DataBlock>(body, bodyLen);
        break;
    case 5:
        FuzzOne<BlockQueryWithSkip>(body, bodyLen);
        break;
    }

    return 0;
}
