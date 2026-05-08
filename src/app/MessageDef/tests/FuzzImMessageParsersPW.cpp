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
 *      Seeded FuzzTest harness for the IM message Parsers. The libFuzzer
 *      variant gets ft≈1600 because random bytes rarely satisfy IM's nested
 *      TLV schema. Here we seed with valid Builder-emitted messages so the
 *      mutator starts from real structure and stresses every path that
 *      `PrettyPrint` walks (which traverses the full schema).
 */

#include <vector>

#include <app/MessageDef/AttributePathIBs.h>
#include <app/MessageDef/InvokeRequestMessage.h>
#include <app/MessageDef/ReadRequestMessage.h>
#include <app/MessageDef/ReportDataMessage.h>
#include <app/MessageDef/InvokeResponseMessage.h>
#include <app/MessageDef/InvokeResponseIBs.h>
#include <app/MessageDef/StatusResponseMessage.h>
#include <app/MessageDef/SubscribeRequestMessage.h>
#include <app/MessageDef/WriteRequestMessage.h>
#include <lib/core/TLVReader.h>
#include <lib/core/TLVWriter.h>
#include <lib/support/CHIPMem.h>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

namespace {

using namespace chip;
using namespace chip::app;
using namespace fuzztest;

// Build a minimal-but-valid InvokeRequestMessage TLV blob.
std::vector<uint8_t> BuildInvokeRequestSeed()
{
    uint8_t buf[256];
    TLV::TLVWriter writer;
    writer.Init(buf);

    InvokeRequestMessage::Builder builder;
    if (builder.Init(&writer) != CHIP_NO_ERROR)
        return {};
    builder.SuppressResponse(false);
    builder.TimedRequest(false);
    auto & invokeRequests = builder.CreateInvokeRequests();
    invokeRequests.EndOfInvokeRequests();
    builder.EndOfInvokeRequestMessage();
    if (writer.Finalize() != CHIP_NO_ERROR)
        return {};

    return std::vector<uint8_t>(buf, buf + writer.GetLengthWritten());
}

std::vector<uint8_t> BuildReadRequestSeed()
{
    uint8_t buf[256];
    TLV::TLVWriter writer;
    writer.Init(buf);

    ReadRequestMessage::Builder builder;
    if (builder.Init(&writer) != CHIP_NO_ERROR)
        return {};
    builder.CreateAttributeRequests().EndOfAttributePathIBs();
    builder.IsFabricFiltered(true);
    builder.EndOfReadRequestMessage();
    if (writer.Finalize() != CHIP_NO_ERROR)
        return {};

    return std::vector<uint8_t>(buf, buf + writer.GetLengthWritten());
}

std::vector<uint8_t> BuildSubscribeRequestSeed()
{
    uint8_t buf[256];
    TLV::TLVWriter writer;
    writer.Init(buf);

    SubscribeRequestMessage::Builder builder;
    if (builder.Init(&writer) != CHIP_NO_ERROR)
        return {};
    builder.KeepSubscriptions(false);
    builder.MinIntervalFloorSeconds(0);
    builder.MaxIntervalCeilingSeconds(60);
    builder.CreateAttributeRequests().EndOfAttributePathIBs();
    builder.IsFabricFiltered(true);
    builder.EndOfSubscribeRequestMessage();
    if (writer.Finalize() != CHIP_NO_ERROR)
        return {};

    return std::vector<uint8_t>(buf, buf + writer.GetLengthWritten());
}

std::vector<uint8_t> BuildStatusResponseSeed()
{
    uint8_t buf[64];
    TLV::TLVWriter writer;
    writer.Init(buf);

    StatusResponseMessage::Builder builder;
    if (builder.Init(&writer) != CHIP_NO_ERROR)
        return {};
    builder.Status(Protocols::InteractionModel::Status::Success);
    if (writer.Finalize() != CHIP_NO_ERROR)
        return {};

    return std::vector<uint8_t>(buf, buf + writer.GetLengthWritten());
}

std::vector<uint8_t> BuildWriteRequestSeed()
{
    uint8_t buf[256];
    TLV::TLVWriter writer;
    writer.Init(buf);

    WriteRequestMessage::Builder builder;
    if (builder.Init(&writer) != CHIP_NO_ERROR)
        return {};
    builder.SuppressResponse(false);
    builder.TimedRequest(false);
    builder.CreateWriteRequests().EndOfAttributeDataIBs();
    builder.MoreChunkedMessages(false);
    builder.EndOfWriteRequestMessage();
    if (writer.Finalize() != CHIP_NO_ERROR)
        return {};

    return std::vector<uint8_t>(buf, buf + writer.GetLengthWritten());
}

std::vector<uint8_t> BuildReportDataSeed()
{
    uint8_t buf[256];
    TLV::TLVWriter writer;
    writer.Init(buf);

    ReportDataMessage::Builder builder;
    if (builder.Init(&writer) != CHIP_NO_ERROR)
        return {};
    builder.SuppressResponse(false);
    builder.SubscriptionId(0x12345678);
    builder.CreateAttributeReportIBs().EndOfAttributeReportIBs();
    builder.CreateEventReports().EndOfEventReports();
    builder.MoreChunkedMessages(false);
    builder.EndOfReportDataMessage();
    if (writer.Finalize() != CHIP_NO_ERROR)
        return {};

    return std::vector<uint8_t>(buf, buf + writer.GetLengthWritten());
}

std::vector<uint8_t> BuildInvokeResponseSeed()
{
    uint8_t buf[256];
    TLV::TLVWriter writer;
    writer.Init(buf);

    InvokeResponseMessage::Builder builder;
    if (builder.Init(&writer) != CHIP_NO_ERROR)
        return {};
    builder.SuppressResponse(false);
    builder.CreateInvokeResponses().EndOfInvokeResponses();
    builder.MoreChunkedMessages(false);
    builder.EndOfInvokeResponseMessage();
    if (writer.Finalize() != CHIP_NO_ERROR)
        return {};

    return std::vector<uint8_t>(buf, buf + writer.GetLengthWritten());
}

template <typename Parser>
void DriveParser(const std::vector<uint8_t> & bytes)
{
    TLV::TLVReader reader;
    reader.Init(bytes.data(), bytes.size());
    if (reader.Next() != CHIP_NO_ERROR)
        return;

    Parser parser;
    if (parser.Init(reader) != CHIP_NO_ERROR)
        return;

#if CHIP_CONFIG_IM_PRETTY_PRINT
    (void) parser.PrettyPrint();
#endif
    (void) parser.ExitContainer();
}

void InvokeRequestFuzz(const std::vector<uint8_t> & bytes)
{
    Platform::MemoryInit();
    DriveParser<InvokeRequestMessage::Parser>(bytes);
    Platform::MemoryShutdown();
}

void ReadRequestFuzz(const std::vector<uint8_t> & bytes)
{
    Platform::MemoryInit();
    DriveParser<ReadRequestMessage::Parser>(bytes);
    Platform::MemoryShutdown();
}

void SubscribeRequestFuzz(const std::vector<uint8_t> & bytes)
{
    Platform::MemoryInit();
    DriveParser<SubscribeRequestMessage::Parser>(bytes);
    Platform::MemoryShutdown();
}

void StatusResponseFuzz(const std::vector<uint8_t> & bytes)
{
    Platform::MemoryInit();
    DriveParser<StatusResponseMessage::Parser>(bytes);
    Platform::MemoryShutdown();
}

auto SeededInvoke()
{
    Platform::MemoryInit();
    auto v = BuildInvokeRequestSeed();
    Platform::MemoryShutdown();
    std::vector<std::vector<uint8_t>> seeds;
    if (!v.empty())
        seeds.push_back(std::move(v));
    return Arbitrary<std::vector<uint8_t>>().WithSeeds(seeds);
}

auto SeededRead()
{
    Platform::MemoryInit();
    auto v = BuildReadRequestSeed();
    Platform::MemoryShutdown();
    std::vector<std::vector<uint8_t>> seeds;
    if (!v.empty())
        seeds.push_back(std::move(v));
    return Arbitrary<std::vector<uint8_t>>().WithSeeds(seeds);
}

auto SeededSubscribe()
{
    Platform::MemoryInit();
    auto v = BuildSubscribeRequestSeed();
    Platform::MemoryShutdown();
    std::vector<std::vector<uint8_t>> seeds;
    if (!v.empty())
        seeds.push_back(std::move(v));
    return Arbitrary<std::vector<uint8_t>>().WithSeeds(seeds);
}

auto SeededStatus()
{
    Platform::MemoryInit();
    auto v = BuildStatusResponseSeed();
    Platform::MemoryShutdown();
    std::vector<std::vector<uint8_t>> seeds;
    if (!v.empty())
        seeds.push_back(std::move(v));
    return Arbitrary<std::vector<uint8_t>>().WithSeeds(seeds);
}

FUZZ_TEST(ImMessageParsers, InvokeRequestFuzz).WithDomains(SeededInvoke());
FUZZ_TEST(ImMessageParsers, ReadRequestFuzz).WithDomains(SeededRead());
FUZZ_TEST(ImMessageParsers, SubscribeRequestFuzz).WithDomains(SeededSubscribe());
FUZZ_TEST(ImMessageParsers, StatusResponseFuzz).WithDomains(SeededStatus());

void WriteRequestFuzz(const std::vector<uint8_t> & bytes)
{
    Platform::MemoryInit();
    DriveParser<WriteRequestMessage::Parser>(bytes);
    Platform::MemoryShutdown();
}

void ReportDataFuzz(const std::vector<uint8_t> & bytes)
{
    Platform::MemoryInit();
    DriveParser<ReportDataMessage::Parser>(bytes);
    Platform::MemoryShutdown();
}

void InvokeResponseFuzz(const std::vector<uint8_t> & bytes)
{
    Platform::MemoryInit();
    DriveParser<InvokeResponseMessage::Parser>(bytes);
    Platform::MemoryShutdown();
}

auto SeededWrite()
{
    Platform::MemoryInit();
    auto v = BuildWriteRequestSeed();
    Platform::MemoryShutdown();
    std::vector<std::vector<uint8_t>> seeds;
    if (!v.empty())
        seeds.push_back(std::move(v));
    return Arbitrary<std::vector<uint8_t>>().WithSeeds(seeds);
}

auto SeededReport()
{
    Platform::MemoryInit();
    auto v = BuildReportDataSeed();
    Platform::MemoryShutdown();
    std::vector<std::vector<uint8_t>> seeds;
    if (!v.empty())
        seeds.push_back(std::move(v));
    return Arbitrary<std::vector<uint8_t>>().WithSeeds(seeds);
}

auto SeededInvokeResponse()
{
    Platform::MemoryInit();
    auto v = BuildInvokeResponseSeed();
    Platform::MemoryShutdown();
    std::vector<std::vector<uint8_t>> seeds;
    if (!v.empty())
        seeds.push_back(std::move(v));
    return Arbitrary<std::vector<uint8_t>>().WithSeeds(seeds);
}

FUZZ_TEST(ImMessageParsers, WriteRequestFuzz).WithDomains(SeededWrite());
FUZZ_TEST(ImMessageParsers, ReportDataFuzz).WithDomains(SeededReport());
FUZZ_TEST(ImMessageParsers, InvokeResponseFuzz).WithDomains(SeededInvokeResponse());

} // namespace
