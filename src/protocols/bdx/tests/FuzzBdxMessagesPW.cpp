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
 *      Seeded FuzzTest harness for the typed BDX message Parsers. Each seed
 *      is a real BDX message produced by the matching `MessageSize` +
 *      `WriteToBuffer` round, so the mutator starts from valid wire format
 *      and explores the typed-fields branches.
 */

#include <utility>
#include <vector>

#include <lib/support/BufferWriter.h>
#include <lib/support/CHIPMem.h>
#include <protocols/bdx/BdxMessages.h>
#include <system/SystemPacketBuffer.h>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

namespace {

using namespace chip;
using namespace chip::bdx;
using namespace fuzztest;

template <typename Msg>
std::vector<uint8_t> EncodeBdx(const Msg & msg)
{
    const size_t needed = msg.MessageSize();
    std::vector<uint8_t> buf(needed);
    Encoding::LittleEndian::BufferWriter writer(buf.data(), buf.size());
    msg.WriteToBuffer(writer);
    if (!writer.Fit())
        return {};
    buf.resize(writer.Needed());
    return buf;
}

std::vector<uint8_t> SeedTransferInit()
{
    TransferInit msg;
    msg.TransferCtlOptions.SetRaw(0x00);
    msg.Version       = 1;
    msg.MaxBlockSize  = 1024;
    msg.StartOffset   = 0;
    msg.MaxLength     = 0;
    static const uint8_t fileDesignator[] = { 'm','a','t','t','e','r','-','o','t','a' };
    msg.FileDesignator = fileDesignator;
    msg.FileDesLength  = sizeof(fileDesignator);
    msg.Metadata       = nullptr;
    msg.MetadataLength = 0;
    return EncodeBdx(msg);
}

std::vector<uint8_t> SeedReceiveAccept()
{
    ReceiveAccept msg;
    msg.TransferCtlFlags.SetRaw(0x00);
    msg.Version       = 1;
    msg.MaxBlockSize  = 1024;
    msg.StartOffset   = 0;
    msg.Length        = 4096;
    msg.Metadata      = nullptr;
    msg.MetadataLength = 0;
    return EncodeBdx(msg);
}

std::vector<uint8_t> SeedDataBlock()
{
    DataBlock msg;
    msg.BlockCounter = 7;
    static const uint8_t payload[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
    msg.Data       = payload;
    msg.DataLength = sizeof(payload);
    return EncodeBdx(msg);
}

std::vector<uint8_t> SeedSendAccept()
{
    SendAccept msg;
    msg.TransferCtlFlags.SetRaw(0x00);
    msg.Version       = 1;
    msg.MaxBlockSize  = 1024;
    msg.Metadata      = nullptr;
    msg.MetadataLength = 0;
    return EncodeBdx(msg);
}

std::vector<uint8_t> SeedCounterMessage()
{
    CounterMessage msg;
    msg.BlockCounter = 0xDEADBEEF;
    return EncodeBdx(msg);
}

std::vector<uint8_t> SeedBlockQueryWithSkip()
{
    BlockQueryWithSkip msg;
    msg.BlockCounter = 0x1000;
    msg.BytesToSkip  = 0x800;
    return EncodeBdx(msg);
}

template <typename Msg>
void ParseFuzz(const std::vector<uint8_t> & bytes)
{
    Platform::MemoryInit();
    auto buf = System::PacketBufferHandle::NewWithData(bytes.data(), bytes.size());
    if (!buf.IsNull())
    {
        Msg parsed;
        RETURN_SAFELY_IGNORED parsed.Parse(std::move(buf));
    }
    Platform::MemoryShutdown();
}

template <typename Msg>
auto SeededDomain(std::vector<uint8_t> seed)
{
    std::vector<std::vector<uint8_t>> seeds;
    if (!seed.empty())
        seeds.push_back(std::move(seed));
    return Arbitrary<std::vector<uint8_t>>().WithSeeds(seeds);
}

void TransferInitFuzz(const std::vector<uint8_t> & bytes)  { ParseFuzz<TransferInit>(bytes); }
void ReceiveAcceptFuzz(const std::vector<uint8_t> & bytes) { ParseFuzz<ReceiveAccept>(bytes); }
void DataBlockFuzz(const std::vector<uint8_t> & bytes)     { ParseFuzz<DataBlock>(bytes); }
void SendAcceptFuzz(const std::vector<uint8_t> & bytes)    { ParseFuzz<SendAccept>(bytes); }
void CounterMessageFuzz(const std::vector<uint8_t> & bytes){ ParseFuzz<CounterMessage>(bytes); }
void BlockQueryWithSkipFuzz(const std::vector<uint8_t> & bytes) { ParseFuzz<BlockQueryWithSkip>(bytes); }

FUZZ_TEST(BdxMessages, TransferInitFuzz).WithDomains(SeededDomain<TransferInit>([] {
    Platform::MemoryInit();
    auto v = SeedTransferInit();
    Platform::MemoryShutdown();
    return v;
}()));

FUZZ_TEST(BdxMessages, ReceiveAcceptFuzz).WithDomains(SeededDomain<ReceiveAccept>([] {
    Platform::MemoryInit();
    auto v = SeedReceiveAccept();
    Platform::MemoryShutdown();
    return v;
}()));

FUZZ_TEST(BdxMessages, DataBlockFuzz).WithDomains(SeededDomain<DataBlock>([] {
    Platform::MemoryInit();
    auto v = SeedDataBlock();
    Platform::MemoryShutdown();
    return v;
}()));

FUZZ_TEST(BdxMessages, SendAcceptFuzz).WithDomains(SeededDomain<SendAccept>([] {
    Platform::MemoryInit();
    auto v = SeedSendAccept();
    Platform::MemoryShutdown();
    return v;
}()));

FUZZ_TEST(BdxMessages, CounterMessageFuzz).WithDomains(SeededDomain<CounterMessage>([] {
    Platform::MemoryInit();
    auto v = SeedCounterMessage();
    Platform::MemoryShutdown();
    return v;
}()));

FUZZ_TEST(BdxMessages, BlockQueryWithSkipFuzz).WithDomains(SeededDomain<BlockQueryWithSkip>([] {
    Platform::MemoryInit();
    auto v = SeedBlockQueryWithSkip();
    Platform::MemoryShutdown();
    return v;
}()));

} // namespace
