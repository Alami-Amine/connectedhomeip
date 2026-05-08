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
 *      Seeded FuzzTest harness for the over-the-wire packet headers.
 *      The libFuzzer variant needs many execs to discover the version-bits /
 *      flag-combination structure on its own. Here we feed it real encoded
 *      headers built from `Map`'d domain inputs and let FuzzTest mutate from
 *      a structurally-valid baseline.
 *
 *      Property under test: Decode → Encode round-trip equality. Already
 *      surfaced F-1 (reserved msg-flags bit 3 asymmetry) under libFuzzer; the
 *      seeded version should reach it in <1 second.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include <lib/core/DataModelTypes.h>
#include <lib/support/CHIPMem.h>
#include <transport/raw/MessageHeader.h>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

namespace {

using namespace chip;
using namespace fuzztest;

// Forward declarations — definitions follow PacketHeaderSeeds().
std::vector<uint8_t> EncodeWithSecurityFlags(uint8_t msgFlags, uint16_t sessionId, uint8_t secFlags,
                                              uint32_t messageCounter);
std::vector<uint8_t> EncodeWithExtensionBlock(uint8_t msgFlags, uint16_t sessionId, uint8_t secFlags,
                                              uint32_t messageCounter, uint16_t mxLength,
                                              const uint8_t * mxData);

std::vector<uint8_t> EncodeValidPacketHeader(uint16_t sessionId, uint32_t messageCounter, uint8_t destSelector,
                                             uint64_t sourceNodeId, uint64_t destNodeId, uint16_t destGroupId)
{
    PacketHeader hdr;
    hdr.SetSessionId(sessionId);
    hdr.SetMessageCounter(messageCounter);

    if (sourceNodeId != 0)
    {
        hdr.SetSourceNodeId(sourceNodeId);
    }

    switch (destSelector % 3)
    {
    case 1:
        hdr.SetDestinationNodeId(destNodeId);
        break;
    case 2:
        hdr.SetSessionType(Header::SessionType::kGroupSession);
        hdr.SetDestinationGroupId(destGroupId);
        break;
    default:
        break;
    }

    uint8_t buf[64];
    uint16_t encoded = 0;
    if (hdr.Encode(buf, sizeof(buf), &encoded) != CHIP_NO_ERROR)
    {
        return {};
    }
    return std::vector<uint8_t>(buf, buf + encoded);
}

std::vector<std::vector<uint8_t>> PacketHeaderSeeds()
{
    Platform::MemoryInit();
    std::vector<std::vector<uint8_t>> seeds;

    auto add = [&](std::vector<uint8_t> v) {
        if (!v.empty())
            seeds.push_back(std::move(v));
    };

    // ==== All flag combinations across destination types ====
    // Plain unicast, no node ids (most common shape)
    add(EncodeValidPacketHeader(0x0000, 0x00000000, /*dest*/ 0, 0, 0, 0));
    add(EncodeValidPacketHeader(0x1234, 0x55667788, /*dest*/ 0, 0, 0, 0));
    add(EncodeValidPacketHeader(0xFFFF, 0xFFFFFFFF, /*dest*/ 0, 0, 0, 0));

    // ==== Source NodeID variants ====
    add(EncodeValidPacketHeader(0xABCD, 0xDEADBEEF, /*dest*/ 0, 0x0123456789ABCDEFULL, 0, 0));
    add(EncodeValidPacketHeader(0x0001, 0x00000001, /*dest*/ 0, 1, 0, 0));
    add(EncodeValidPacketHeader(0xFFFE, 0xFFFFFFFE, /*dest*/ 0, 0xFFFFFFFFFFFFFFFFULL, 0, 0));

    // ==== Destination NodeID variants ====
    add(EncodeValidPacketHeader(0x0001, 0x00000001, /*dest*/ 1, 0, 0xFEDCBA9876543210ULL, 0));
    add(EncodeValidPacketHeader(0x0010, 0x00000010, /*dest*/ 1, 0, 0x0000000000000001ULL, 0));

    // ==== Group session forms ====
    add(EncodeValidPacketHeader(0x0002, 0x00000002, /*dest*/ 2, 0, 0, 0x0001));
    add(EncodeValidPacketHeader(0x0002, 0x00000002, /*dest*/ 2, 0, 0, 0xCAFE));
    add(EncodeValidPacketHeader(0xFFFF, 0xFFFFFFFE, /*dest*/ 2, 0, 0, 0xFFFE));

    // ==== Source + destination NodeID ====
    add(EncodeValidPacketHeader(0x9999, 0x12345678, /*dest*/ 1, 0x0A0B0C0D0E0F1011ULL, 0xAABBCCDDEEFF0011ULL, 0));

    // Hand-crafted security-flag forms whose roundtrip *does* hold (privacy /
    // control-msg / session-type don't impact encoder output length).
    // NOTE: kMsgExtensionFlag (0x20) seeds are intentionally excluded from
    // the roundtrip seed pool — decoder consumes the extension block and the
    // encoder doesn't emit it, so they always violate the roundtrip property
    // (this is documented as finding F-7). They live in DecodeOnlySeeds()
    // below where the harness only decodes (no encode-then-equal check).
    add(EncodeWithSecurityFlags(/*msgFlags*/ 0x00, /*sid*/ 0x1234, /*secFlags*/ 0x80, /*ctr*/ 0xDEADBEEF));
    add(EncodeWithSecurityFlags(0x00, 0x1234, 0x40, 0x12345678));
    add(EncodeWithSecurityFlags(0x00, 0x1234, 0x01, 0x12345678));
    add(EncodeWithSecurityFlags(0x00, 0x1234, 0x02, 0x12345678));
    add(EncodeWithSecurityFlags(0x00, 0x9999, 0xC1, 0x00000001));

    Platform::MemoryShutdown();
    return seeds;
}

// Seeds that exercise paths Roundtrip can't (because they trigger F-7),
// for use with the decode-only FUZZ_TEST.
std::vector<std::vector<uint8_t>> PacketHeaderDecodeOnlySeeds()
{
    Platform::MemoryInit();
    auto seeds = PacketHeaderSeeds(); // start from the roundtrippable ones
    auto add = [&](std::vector<uint8_t> v) {
        if (!v.empty())
            seeds.push_back(std::move(v));
    };

    // Message-extension block (kMsgExtensionFlag set) — empty, small, big
    add(EncodeWithExtensionBlock(0x00, 0x1234, 0x00, 0x12345678, 0, nullptr));
    {
        const uint8_t mxData[] = { 0xAA, 0xBB, 0xCC, 0xDD };
        add(EncodeWithExtensionBlock(0x00, 0x1234, 0x00, 0x12345678, sizeof(mxData), mxData));
    }
    {
        std::vector<uint8_t> big(64, 0x42);
        add(EncodeWithExtensionBlock(0x00, 0x1234, 0x00, 0x12345678, static_cast<uint16_t>(big.size()), big.data()));
    }

    Platform::MemoryShutdown();
    return seeds;
}

void PacketHeaderDecodeOnlyFuzz(const std::vector<uint8_t> & bytes)
{
    Platform::MemoryInit();

    PacketHeader hdr;
    uint16_t consumed = 0;
    (void) hdr.Decode(bytes.data(), bytes.size(), &consumed);

    Platform::MemoryShutdown();
}

FUZZ_TEST(MessageHeader, PacketHeaderDecodeOnlyFuzz)
    .WithDomains(Arbitrary<std::vector<uint8_t>>().WithSeeds(PacketHeaderDecodeOnlySeeds()));

// Build a Source+Group form too (uncommon but legal post-MCSP).
std::vector<uint8_t> EncodeMcspLikeHeader(uint16_t sessionId, uint32_t messageCounter, uint64_t sourceNodeId,
                                          uint16_t destGroupId)
{
    PacketHeader hdr;
    hdr.SetSessionId(sessionId);
    hdr.SetMessageCounter(messageCounter);
    hdr.SetSourceNodeId(sourceNodeId);
    hdr.SetSessionType(Header::SessionType::kGroupSession);
    hdr.SetDestinationGroupId(destGroupId);

    uint8_t buf[64];
    uint16_t encoded = 0;
    if (hdr.Encode(buf, sizeof(buf), &encoded) != CHIP_NO_ERROR)
    {
        return {};
    }
    return std::vector<uint8_t>(buf, buf + encoded);
}

// Hand-built raw bytes that set the security flags we care about.
// The encoder doesn't expose a clean SetPrivacyFlag(true) for outbound; the
// mProcessing path is exercised when *parsing* a header that has the flags
// set, so we hand-assemble byte streams that the *decoder* will accept.
std::vector<uint8_t> EncodeWithSecurityFlags(uint8_t msgFlags, uint16_t sessionId, uint8_t secFlags,
                                              uint32_t messageCounter)
{
    std::vector<uint8_t> out;
    out.push_back(msgFlags);
    out.push_back(static_cast<uint8_t>(sessionId & 0xFF));
    out.push_back(static_cast<uint8_t>(sessionId >> 8));
    out.push_back(secFlags);
    out.push_back(static_cast<uint8_t>(messageCounter & 0xFF));
    out.push_back(static_cast<uint8_t>((messageCounter >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((messageCounter >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((messageCounter >> 24) & 0xFF));
    return out;
}

// Adds an mxLength=0 message-extension block right after the fixed portion.
// Forces the parser through the kMsgExtensionFlag path.
std::vector<uint8_t> EncodeWithExtensionBlock(uint8_t msgFlags, uint16_t sessionId, uint8_t secFlags,
                                              uint32_t messageCounter, uint16_t mxLength,
                                              const uint8_t * mxData)
{
    auto out = EncodeWithSecurityFlags(msgFlags, sessionId,
                                       static_cast<uint8_t>(secFlags | 0x20 /* kMsgExtensionFlag */),
                                       messageCounter);
    out.push_back(static_cast<uint8_t>(mxLength & 0xFF));
    out.push_back(static_cast<uint8_t>(mxLength >> 8));
    for (uint16_t i = 0; i < mxLength; ++i)
    {
        out.push_back(mxData ? mxData[i] : 0);
    }
    return out;
}

void PacketHeaderRoundtripFuzz(const std::vector<uint8_t> & bytes)
{
    Platform::MemoryInit();

    PacketHeader hdr;
    uint16_t consumed = 0;
    if (hdr.Decode(bytes.data(), bytes.size(), &consumed) == CHIP_NO_ERROR)
    {
        uint8_t encoded[128];
        uint16_t encodedLen      = 0;
        const uint16_t expectedLen = hdr.EncodeSizeBytes();
        if (expectedLen <= sizeof(encoded) &&
            hdr.Encode(encoded, sizeof(encoded), &encodedLen) == CHIP_NO_ERROR)
        {
            ASSERT_EQ(encodedLen, consumed);
            ASSERT_EQ(encodedLen, expectedLen);
            ASSERT_EQ(memcmp(encoded, bytes.data(), encodedLen), 0);
        }
    }

    Platform::MemoryShutdown();
}

FUZZ_TEST(MessageHeader, PacketHeaderRoundtripFuzz)
    .WithDomains(Arbitrary<std::vector<uint8_t>>().WithSeeds(PacketHeaderSeeds()));

void PayloadHeaderDecodeFuzz(const std::vector<uint8_t> & bytes)
{
    Platform::MemoryInit();
    PayloadHeader hdr;
    uint16_t consumed = 0;
    (void) hdr.Decode(bytes.data(), bytes.size(), &consumed);
    Platform::MemoryShutdown();
}

// Construct PayloadHeader seeds across all common protocol IDs.
std::vector<std::vector<uint8_t>> PayloadHeaderSeeds()
{
    Platform::MemoryInit();
    std::vector<std::vector<uint8_t>> seeds;

    auto add = [&](Protocols::Id proto, uint8_t messageType, uint16_t exchangeId, bool ack, uint32_t ackCounter,
                   bool initiator = false) {
        PayloadHeader p;
        p.SetMessageType(proto, messageType);
        p.SetExchangeID(exchangeId);
        p.SetInitiator(initiator);
        if (ack)
        {
            p.SetAckMessageCounter(ackCounter);
        }
        uint8_t buf[64];
        uint16_t n = 0;
        if (p.Encode(buf, sizeof(buf), &n) == CHIP_NO_ERROR)
        {
            seeds.emplace_back(buf, buf + n);
        }
    };

    add(Protocols::SecureChannel::Id, /*PASE Pake1*/ 32, 0x0001, false, 0, true);
    add(Protocols::SecureChannel::Id, /*Sigma1*/ 0x30, 0x0002, true, 0xCAFEBABE, true);
    add(Protocols::InteractionModel::Id, /*InvokeReq*/ 8, 0x0003, false, 0, true);
    add(Protocols::InteractionModel::Id, /*ReadReq*/ 2, 0x0004, true, 0x12345678, true);
    add(Protocols::BDX::Id, /*SendInit*/ 1, 0x0005, false, 0, false);
    add(Protocols::UserDirectedCommissioning::Id, 0, 0x0006, false, 0, false);

    // Hand-built forms exercising the kExchangeFlag_SecuredExtension path the
    // encoder doesn't expose (the spec reserves Secured Extensions for future
    // use — but the *decoder* must handle peer-provided ones cleanly).
    auto addSecExt = [&](uint8_t exFlags, uint8_t messageType, uint16_t exchangeId, uint16_t protocolId,
                          uint16_t sxLength, const uint8_t * sxData) {
        std::vector<uint8_t> v;
        v.push_back(exFlags | 0x08); // kExchangeFlag_SecuredExtension
        v.push_back(messageType);
        v.push_back(static_cast<uint8_t>(exchangeId & 0xFF));
        v.push_back(static_cast<uint8_t>(exchangeId >> 8));
        v.push_back(static_cast<uint8_t>(protocolId & 0xFF));
        v.push_back(static_cast<uint8_t>(protocolId >> 8));
        v.push_back(static_cast<uint8_t>(sxLength & 0xFF));
        v.push_back(static_cast<uint8_t>(sxLength >> 8));
        for (uint16_t i = 0; i < sxLength; ++i)
        {
            v.push_back(sxData ? sxData[i] : 0);
        }
        seeds.push_back(std::move(v));
    };
    addSecExt(0x00, 0x10, 0x0007, 0x0001, 0, nullptr);
    addSecExt(0x01, 0x20, 0x0008, 0x0001, 4, (const uint8_t *) "abcd");

    // Vendor-ID-present form
    auto addVid = [&](uint16_t vendorId, uint8_t messageType, uint16_t exchangeId, uint16_t protocolId,
                      uint8_t exFlags) {
        std::vector<uint8_t> v;
        v.push_back(exFlags | 0x10); // kExchangeFlag_VendorIdPresent
        v.push_back(messageType);
        v.push_back(static_cast<uint8_t>(exchangeId & 0xFF));
        v.push_back(static_cast<uint8_t>(exchangeId >> 8));
        v.push_back(static_cast<uint8_t>(vendorId & 0xFF));
        v.push_back(static_cast<uint8_t>(vendorId >> 8));
        v.push_back(static_cast<uint8_t>(protocolId & 0xFF));
        v.push_back(static_cast<uint8_t>(protocolId >> 8));
        seeds.push_back(std::move(v));
    };
    addVid(0xFFF1, 0x05, 0x0009, 0x0010, 0x00);
    addVid(0xFFFF, 0xFF, 0xFFFF, 0xFFFF, 0x07); // VID + AckMsg + NeedsAck + Initiator

    Platform::MemoryShutdown();
    return seeds;
}

FUZZ_TEST(MessageHeader, PayloadHeaderDecodeFuzz)
    .WithDomains(Arbitrary<std::vector<uint8_t>>().WithSeeds(PayloadHeaderSeeds()));

} // namespace
