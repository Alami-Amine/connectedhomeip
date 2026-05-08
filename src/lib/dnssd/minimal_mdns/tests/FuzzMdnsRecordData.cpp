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
 *      Fuzzes the mDNS record-data parsers: ParseTxtRecord, ParseSrvRecord,
 *      ParsePtrRecord, ParseARecord, ParseAAAARecord. Reachable from any
 *      mDNS reply on the local network during commissioning/operational
 *      discovery.
 */

#include <cstddef>
#include <cstdint>

#include <inet/IPAddress.h>
#include <lib/core/CHIPError.h>
#include <lib/dnssd/minimal_mdns/RecordData.h>
#include <lib/dnssd/minimal_mdns/core/BytesRange.h>

namespace {

class NoopTxt : public mdns::Minimal::TxtRecordDelegate
{
public:
    void OnRecord(const mdns::Minimal::BytesRange &, const mdns::Minimal::BytesRange &) override {}
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t len)
{
    using namespace mdns::Minimal;

    BytesRange range(data, data + len);

    {
        NoopTxt sink;
        (void) ParseTxtRecord(range, &sink);
    }

    {
        SrvRecord srv;
        (void) srv.Parse(range, range);
    }

    {
        // ParsePtrRecord requires the validity range to bound the name pointer.
        SerializedQNameIterator name;
        (void) ParsePtrRecord(range, range, &name);
    }

    {
        chip::Inet::IPAddress addr;
        (void) ParseARecord(range, &addr);
    }

    {
        chip::Inet::IPAddress addr;
        (void) ParseAAAARecord(range, &addr);
    }

    return 0;
}
