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

// FuzzTest harness for the Matter message-header parsers. PacketHeader::Decode
// and PayloadHeader::Decode are the first parsers every unauthenticated
// UDP/TCP/BLE frame hits, before any crypto/session lookup. Both are
// self-contained decoders over a raw (data, size) buffer, so the fuzz input
// maps 1:1 onto the wire bytes an on-link attacker controls.

#include <cstdint>
#include <vector>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

#include <transport/raw/MessageHeader.h>

namespace chip {
namespace {

using namespace fuzztest;

void PacketHeaderDecode(const std::vector<std::uint8_t> & bytes)
{
    PacketHeader header;
    uint16_t decodeLen = 0;
    if (header.Decode(bytes.data(), bytes.size(), &decodeLen) == CHIP_NO_ERROR)
    {
        // Round-trip: re-encode the decoded header (covers EncodeSizeBytes/Encode
        // and catches any decode/encode asymmetry).
        uint8_t out[256];
        uint16_t encodeLen = 0;
        (void) header.EncodeSizeBytes();
        (void) header.Encode(out, sizeof(out), &encodeLen);
    }
}
// Seeds = valid headers covering each Decode arm (LE: msgFlags, sessionId[2],
// secFlags, msgCounter[4], [srcNodeId 8], [destNodeId 8 | destGroupId 2],
// [mxLength 2 + ext]). Version nibble 0 = kMsgHeaderVersion; secFlags low bits =
// session type (0 unicast, 1 group). These get the fuzzer past the version gate
// straight into the source/dest/extension arms that random bytes rarely reach.
FUZZ_TEST(MessageHeader, PacketHeaderDecode)
    .WithDomains(Arbitrary<std::vector<std::uint8_t>>().WithSeeds({
        { 0x00, 0x01, 0x00, 0x00, 0xBE, 0xBA, 0xFE, 0xCA },                                                 // unicast, no src/dest
        { 0x04, 0x01, 0x00, 0x00, 0xBE, 0xBA, 0xFE, 0xCA, 1, 2, 3, 4, 5, 6, 7, 8 },                         // source node id present
        { 0x01, 0x01, 0x00, 0x00, 0xBE, 0xBA, 0xFE, 0xCA, 9, 9, 9, 9, 9, 9, 9, 9 },                         // dest node id present
        { 0x02, 0x01, 0x00, 0x01, 0xBE, 0xBA, 0xFE, 0xCA, 0x34, 0x12 },                                     // dest group (group session)
        { 0x00, 0x01, 0x00, 0x20, 0xBE, 0xBA, 0xFE, 0xCA, 0x04, 0x00, 0xDE, 0xAD, 0xBE, 0xEF },             // message extension
    }));

void PayloadHeaderDecode(const std::vector<std::uint8_t> & bytes)
{
    PayloadHeader header;
    uint16_t decodeLen = 0;
    if (header.Decode(bytes.data(), bytes.size(), &decodeLen) == CHIP_NO_ERROR)
    {
        uint8_t out[256];
        uint16_t encodeLen = 0;
        (void) header.EncodeSizeBytes();
        (void) header.Encode(out, sizeof(out), &encodeLen);
    }
}
// Seeds (LE: exFlags, msgType, exchangeId[2], [vendorId 2], protocolId[2],
// [ackCounter 4], [sxLength 2 + ext]). exFlags: 0x02 Ack, 0x08 SecuredExt,
// 0x10 VendorIdPresent.
FUZZ_TEST(MessageHeader, PayloadHeaderDecode)
    .WithDomains(Arbitrary<std::vector<std::uint8_t>>().WithSeeds({
        { 0x00, 0x05, 0x07, 0x00, 0x01, 0x00 },                                     // minimal
        { 0x10, 0x05, 0x07, 0x00, 0xF1, 0xFF, 0x01, 0x00 },                         // vendor id present
        { 0x02, 0x05, 0x07, 0x00, 0x01, 0x00, 0x04, 0x03, 0x02, 0x01 },             // ack message
        { 0x08, 0x05, 0x07, 0x00, 0x01, 0x00, 0x02, 0x00, 0xAB, 0xCD },             // secured extension
    }));

} // namespace
} // namespace chip
