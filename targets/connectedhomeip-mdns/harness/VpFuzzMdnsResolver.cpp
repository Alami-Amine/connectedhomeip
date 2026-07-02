// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0
//
// Raw-byte libFuzzer harness for the DNS-SD IncrementalResolver orchestration
// layer — the code that drives an mDNS discovery record set (SRV -> TXT ->
// A/AAAA) into the fixed-size NodeData buffers during Matter discovery. Every
// byte is attacker-controlled: any mDNS responder on the local link can send
// these records.
//
// Pipeline-native sibling of the FuzzTest harness FuzzMdnsResolverPW. That
// harness takes eight typed domains (flavor, instance, host, port, ttl,
// txt-entry vector, addIp, ip bytes); here a single flat input is split into
// those arguments by a tiny deterministic byte consumer, so a crafted file
// maps to one lifecycle run. The record-building scaffolding (WireRecord /
// QNameHolder) is ported verbatim from the FuzzTest harness; the gtest
// invariant oracles are intentionally dropped — this hunts ASAN crashes.
//
// Construction mirrors TestIncrementalResolve.cpp: build typed ResourceRecords
// (Srv/Txt/IP) with a chosen QName, serialize them to wire bytes, re-parse
// into a ResourceData, and feed that to the real resolver — the same wire
// decode the network path uses, so a crash here is reachable from a packet.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <inet/IPAddress.h>
#include <inet/InetInterface.h>
#include <lib/core/CHIPEncoding.h>
#include <lib/dnssd/IncrementalResolve.h>
#include <lib/dnssd/Resolver.h>
#include <lib/dnssd/Types.h>
#include <lib/dnssd/minimal_mdns/Parser.h>
#include <lib/dnssd/minimal_mdns/RecordData.h>
#include <lib/dnssd/minimal_mdns/core/DnsHeader.h>
#include <lib/dnssd/minimal_mdns/core/QName.h>
#include <lib/dnssd/minimal_mdns/core/RecordWriter.h>
#include <lib/dnssd/minimal_mdns/records/IP.h>
#include <lib/dnssd/minimal_mdns/records/ResourceRecord.h>
#include <lib/dnssd/minimal_mdns/records/Srv.h>
#include <lib/dnssd/minimal_mdns/records/Txt.h>
#include <lib/support/BufferWriter.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>

namespace {

using namespace chip;
using namespace chip::Dnssd;
using namespace mdns::Minimal;

void EnsureInitialized()
{
    static const bool sInitialized = [] {
        VerifyOrDie(Platform::MemoryInit() == CHIP_NO_ERROR);
        return true;
    }();
    (void) sInitialized;
}

// Minimal deterministic byte consumer — the self-contained stand-in for
// FuzzedDataProvider. Reads big-endian integers and length-prefixed strings
// off the front of the buffer, saturating to zero / empty when exhausted.
class Consumer
{
public:
    Consumer(const uint8_t * data, size_t len) : mPtr(data), mRemaining(len) {}

    uint8_t Byte()
    {
        if (mRemaining == 0)
        {
            return 0;
        }
        --mRemaining;
        return *mPtr++;
    }

    uint16_t U16() { return static_cast<uint16_t>((static_cast<uint16_t>(Byte()) << 8) | Byte()); }

    uint64_t U64()
    {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i)
        {
            v = (v << 8) | Byte();
        }
        return v;
    }

    bool Bool() { return (Byte() & 1u) != 0; }

    // 1-byte length prefix (clamped to maxLen and to what remains), then bytes.
    std::string Str(size_t maxLen)
    {
        size_t want = Byte();
        if (want > maxLen)
        {
            want = maxLen;
        }
        if (want > mRemaining)
        {
            want = mRemaining;
        }
        std::string s(reinterpret_cast<const char *>(mPtr), want);
        mPtr += want;
        mRemaining -= want;
        return s;
    }

    void Fill(uint8_t * out, size_t count)
    {
        for (size_t i = 0; i < count; ++i)
        {
            out[i] = Byte();
        }
    }

    size_t Remaining() const { return mRemaining; }

private:
    const uint8_t * mPtr;
    size_t mRemaining;
};

// ---- Record-building scaffolding (ported from FuzzMdnsResolverPW) ----

enum class ServiceFlavor : uint8_t
{
    kOperational,
    kCommissionable,
    kCommissioner,
};

struct QNameHolder
{
    std::vector<std::string> storage;
    std::vector<QNamePart> parts;

    FullQName Full()
    {
        parts.clear();
        parts.reserve(storage.size());
        for (auto & s : storage)
        {
            parts.push_back(s.c_str());
        }
        FullQName q;
        q.names     = parts.data();
        q.nameCount = parts.size();
        return q;
    }
};

QNameHolder MakeServiceName(ServiceFlavor flavor, const std::string & instance)
{
    QNameHolder holder;
    holder.storage.push_back(instance);
    switch (flavor)
    {
    case ServiceFlavor::kOperational:
        holder.storage.push_back("_matter");
        holder.storage.push_back("_tcp");
        break;
    case ServiceFlavor::kCommissionable:
        holder.storage.push_back("_matterc");
        holder.storage.push_back("_udp");
        break;
    case ServiceFlavor::kCommissioner:
        holder.storage.push_back("_matterd");
        holder.storage.push_back("_udp");
        break;
    }
    holder.storage.push_back("local");
    return holder;
}

QNameHolder MakeHostName(const std::string & host)
{
    QNameHolder holder;
    holder.storage.push_back(host);
    holder.storage.push_back("local");
    return holder;
}

class WireRecord
{
public:
    bool Build(const ResourceRecord & record)
    {
        uint8_t headerBuffer[HeaderRef::kSizeBytes] = {};
        HeaderRef dummyHeader(headerBuffer);

        chip::Encoding::BigEndian::BufferWriter output(mBuffer.data(), mBuffer.size());
        RecordWriter writer(&output);

        if (!record.Append(dummyHeader, ResourceType::kAnswer, writer) || !writer.Fit())
        {
            return false;
        }

        const uint8_t * ptr = mBuffer.data();
        BytesRange packet(mBuffer.data(), mBuffer.data() + mBuffer.size());
        return mResource.Parse(packet, &ptr);
    }

    const ResourceData & Resource() const { return mResource; }
    BytesRange Packet() const { return BytesRange(mBuffer.data(), mBuffer.data() + mBuffer.size()); }

private:
    std::array<uint8_t, 1024> mBuffer = {};
    ResourceData mResource;
};

void RunLifecycle(uint8_t flavorSel, const std::string & instance, const std::string & host, uint16_t port, uint64_t ttl,
                  const std::vector<std::string> & txtEntries, bool addIp, const std::array<uint8_t, 16> & ipBytes)
{
    const ServiceFlavor flavor = static_cast<ServiceFlavor>(flavorSel % 3);

    QNameHolder serviceName = MakeServiceName(flavor, instance);
    QNameHolder hostName    = MakeHostName(host);

    SrvResourceRecord srvBuilder(serviceName.Full(), hostName.Full(), port);
    WireRecord srvWire;
    if (!srvWire.Build(srvBuilder))
    {
        return;
    }

    SrvRecord srv;
    if (!srv.Parse(srvWire.Resource().GetData(), srvWire.Packet()))
    {
        return;
    }

    IncrementalResolver resolver;
    CHIP_ERROR err = resolver.InitializeParsing(srvWire.Resource().GetName(), ttl, srv);
    if (err != CHIP_NO_ERROR || !resolver.IsActive())
    {
        return;
    }

    const Inet::InterfaceId interface = Inet::InterfaceId::Null();

    {
        std::vector<const char *> entryPtrs;
        entryPtrs.reserve(txtEntries.size());
        bool tooLong = false;
        for (const auto & e : txtEntries)
        {
            if (e.size() > 63)
            {
                tooLong = true;
                break;
            }
            entryPtrs.push_back(e.c_str());
        }

        if (!tooLong && !entryPtrs.empty())
        {
            TxtResourceRecord txtBuilder(serviceName.Full(), entryPtrs.data(), entryPtrs.size());
            WireRecord txtWire;
            if (txtWire.Build(txtBuilder))
            {
                (void) resolver.OnRecord(interface, txtWire.Resource(), txtWire.Packet());
            }
        }
    }

    if (addIp)
    {
        Inet::IPAddress addr;
        memcpy(addr.Addr, ipBytes.data(), sizeof(addr.Addr));

        IPResourceRecord ipBuilder(hostName.Full(), addr);
        WireRecord ipWire;
        if (ipWire.Build(ipBuilder))
        {
            (void) resolver.OnRecord(interface, ipWire.Resource(), ipWire.Packet());
        }
    }

    if (resolver.IsActiveOperationalParse())
    {
        ResolvedNodeData nodeData;
        (void) resolver.Take(nodeData);
    }
    else if (resolver.IsActiveCommissionParse())
    {
        DiscoveredNodeData nodeData;
        (void) resolver.Take(nodeData);
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t len)
{
    if (len == 0)
    {
        return 0;
    }

    EnsureInitialized();

    Consumer fdp(data, len);

    const uint8_t flavorSel = fdp.Byte();
    const std::string instance = fdp.Str(80);
    const std::string host     = fdp.Str(80);
    const uint16_t port        = fdp.U16();
    const uint64_t ttl         = fdp.U64();

    std::vector<std::string> txtEntries;
    uint8_t txtCount = fdp.Byte() & 0x0f; // up to 15 entries
    for (uint8_t i = 0; i < txtCount && fdp.Remaining() > 0; ++i)
    {
        txtEntries.push_back(fdp.Str(255));
    }

    const bool addIp = fdp.Bool();
    std::array<uint8_t, 16> ipBytes{};
    fdp.Fill(ipBytes.data(), ipBytes.size());

    RunLifecycle(flavorSel, instance, host, port, ttl, txtEntries, addIp, ipBytes);

    return 0;
}
