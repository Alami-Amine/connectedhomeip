// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0
//
// Raw-byte libFuzzer harness for connectedhomeip's minimal mDNS wire parsers.
// One input file == one mDNS packet on the wire. Reachable from any mDNS
// responder on the local link during commissioning / operational discovery,
// so every byte here is attacker-controlled.
//
// This is the pipeline-native (raw bytes in, ASAN abort out) sibling of the
// FuzzTest harnesses on AA/NewFuzzersV2 (FuzzPacketParsingPW /
// FuzzMdnsRecordDataPW / FuzzMdnsQNamePW). It drives the same parse entry
// points but without the typed-domain corpus encoding, so a crafted packet on
// disk is fed verbatim to ParsePacket. The FuzzTest invariant oracles
// (ASSERT_*) are intentionally dropped: this harness hunts memory-safety
// crashes (the ASAN floor), not logic-invariant violations.
//
// Surfaces fanned out from the single input buffer:
//   1. ParsePacket            — full packet parse (header/query/resource walk),
//                               which itself dispatches SRV/A/AAAA/PTR records.
//   2. SerializedQNameIterator — DNS name decode swept from every start offset
//                               (compression-pointer loops / OOB reads).
//   3. ParseTxtRecord         — TXT record body parse (not exercised by the
//                               ParsePacket delegate below).

#include <cstddef>
#include <cstdint>

#include <inet/IPAddress.h>
#include <lib/dnssd/minimal_mdns/Parser.h>
#include <lib/dnssd/minimal_mdns/RecordData.h>
#include <lib/dnssd/minimal_mdns/core/BytesRange.h>
#include <lib/dnssd/minimal_mdns/core/QName.h>

namespace {

using namespace chip;
using namespace mdns::Minimal;

// Mirrors the upstream FuzzPacketParsing delegate: on each resource record,
// re-parse the typed record so the record-specific parsers (and the embedded
// name walk) run against the live packet bounds.
class FuzzDelegate : public ParserDelegate
{
public:
    explicit FuzzDelegate(const BytesRange & packet) : mPacketRange(packet) {}
    ~FuzzDelegate() override {}

    void OnHeader(ConstHeaderRef & header) override {}
    void OnQuery(const QueryData & data) override {}
    void OnResource(ResourceType type, const ResourceData & data) override
    {
        switch (data.GetType())
        {
        case QType::SRV: {
            SrvRecord srv;
            (void) srv.Parse(data.GetData(), mPacketRange);
            break;
        }
        case QType::A: {
            Inet::IPAddress addr;
            (void) ParseARecord(data.GetData(), &addr);
            break;
        }
        case QType::AAAA: {
            Inet::IPAddress addr;
            (void) ParseAAAARecord(data.GetData(), &addr);
            break;
        }
        case QType::PTR: {
            SerializedQNameIterator name;
            (void) ParsePtrRecord(data.GetData(), mPacketRange, &name);
            break;
        }
        case QType::TXT: {
            // ParsePacket's own dispatch does not crack TXT bodies; do it here
            // so the TXT key/value walk is exercised against the packet bounds.
            ParseTxtRecord(data.GetData(), &mNoopTxt);
            break;
        }
        default:
            break;
        }
    }

private:
    // Touches every reported (name,value) range so the sanitizer validates the
    // pointers stay inside the supplied buffer.
    class NoopTxt : public TxtRecordDelegate
    {
    public:
        void OnRecord(const BytesRange & name, const BytesRange & value) override
        {
            for (const uint8_t * p = name.Start(); p < name.End(); ++p)
            {
                mAcc = static_cast<uint8_t>(mAcc + *p);
            }
            for (const uint8_t * p = value.Start(); p < value.End(); ++p)
            {
                mAcc = static_cast<uint8_t>(mAcc + *p);
            }
        }

    private:
        volatile uint8_t mAcc = 0;
    };

    BytesRange mPacketRange;
    NoopTxt mNoopTxt;
};

// Walk a name iterator to completion with a hard step budget so a malformed /
// looping name cannot hang the run.
void DrainName(SerializedQNameIterator name)
{
    size_t safety = 0;
    while (name.Next())
    {
        (void) name.Value();
        if (++safety > 256)
        {
            break;
        }
    }
    (void) name.IsValid();
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t len)
{
    if (len == 0)
    {
        return 0;
    }

    BytesRange packet(data, data + len);

    // 1. Full packet parse (dispatches SRV/A/AAAA/PTR/TXT via the delegate).
    {
        FuzzDelegate delegate(packet);
        ParsePacket(packet, &delegate);
    }

    // 2. QName decode swept from every start offset, exercising the
    //    look-behind / compression-pointer-target validation from each
    //    position in the buffer (mirrors the FuzzMdnsQName offset sweep).
    {
        const size_t step = (len > 8) ? (len / 8) : 1;
        for (size_t off = 0; off < len; off += step)
        {
            DrainName(SerializedQNameIterator(packet, data + off));
        }
    }

    return 0;
}
