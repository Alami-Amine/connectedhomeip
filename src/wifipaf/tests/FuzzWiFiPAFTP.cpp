/*
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

#include <cstddef>
#include <cstdint>
#include <utility>

#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <system/SystemPacketBuffer.h>
#include <wifipaf/WiFiPAFTP.h>

namespace {

using chip::System::PacketBufferHandle;
using chip::WiFiPAF::SequenceNumber_t;
using chip::WiFiPAF::WiFiPAFTP;

bool EnsureInitialized()
{
    static const bool sInitialized = [] {
        VerifyOrDie(chip::Platform::MemoryInit() == CHIP_NO_ERROR);
        return true;
    }();
    return sInitialized;
}

} // namespace

// Fuzzer input is framed as a sequence of PAFTP fragments:
//   <2-byte BE length><length bytes of fragment payload>...
// Each fragment is fed to WiFiPAFTP::HandleCharacteristicReceived, driving
// the reassembly state machine (header flag parsing, ack/seq handling,
// fragment stitching) across many packets in a single input.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)
{
    (void) EnsureInitialized();

    WiFiPAFTP engine;
    if (engine.Init(nullptr, /* expect_first_ack = */ false) != CHIP_NO_ERROR)
    {
        return 0;
    }

    size_t cursor = 0;
    while (cursor + 2 <= size)
    {
        uint16_t fragLen = static_cast<uint16_t>((data[cursor] << 8) | data[cursor + 1]);
        cursor += 2;

        const size_t available = size - cursor;
        if (fragLen > available)
        {
            fragLen = static_cast<uint16_t>(available);
        }

        auto buf = PacketBufferHandle::NewWithData(data + cursor, fragLen);
        cursor += fragLen;
        if (buf.IsNull())
        {
            break;
        }

        SequenceNumber_t receivedAck = 0;
        bool didReceiveAck           = false;
        (void) engine.HandleCharacteristicReceived(std::move(buf), receivedAck, didReceiveAck);

        if (engine.RxState() == WiFiPAFTP::kState_Complete)
        {
            (void) engine.TakeRxPacket();
        }
        if (engine.RxState() == WiFiPAFTP::kState_Error)
        {
            break;
        }
    }

    return 0;
}
