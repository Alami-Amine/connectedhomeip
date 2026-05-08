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
 *      Seeded FuzzTest harness for Inet::IPAddress::FromString. The
 *      libFuzzer variant explores random bytes; here the seeds are valid
 *      IPv4, IPv6, IPv4-mapped-IPv6, link-local, multicast, and "tricky"
 *      address forms (zero-compression boundaries, embedded-IPv4 inside
 *      IPv6, scope-id suffixes). The mutator starts from those seeds and
 *      perturbs them, exercising the parser's whitespace / digit / colon
 *      / dot state machine.
 *
 *      Property: parse → format → re-parse must round-trip when the
 *      original was valid. (Format-side asymmetry is the bug class that
 *      surfaced F-1 in PacketHeader.)
 */

#include <string>
#include <vector>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

#include <inet/IPAddress.h>
#include <inet/InetInterface.h>
#include <lib/support/CHIPMem.h>

namespace {

using namespace chip;
using namespace chip::Inet;
using namespace fuzztest;

void EnsureInitialized()
{
    static const bool sInitialized = [] {
        VerifyOrDie(Platform::MemoryInit() == CHIP_NO_ERROR);
        return true;
    }();
    (void) sInitialized;
}

std::vector<std::string> IpAddressSeeds()
{
    return {
        // ==== Valid IPv4 ====
        "0.0.0.0",
        "127.0.0.1",
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "8.8.8.8",
        "169.254.1.1",          // link-local IPv4
        "224.0.0.1",            // multicast IPv4
        "239.255.255.250",      // SSDP multicast
        "255.255.255.255",      // broadcast
        // ==== Valid IPv6 ====
        "::",                   // all-zero
        "::1",                  // loopback
        "fe80::1",              // link-local
        "fec0::1",              // site-local (deprecated)
        "ff02::1",              // all-nodes multicast
        "ff02::2",              // all-routers
        "ff02::fb",             // mDNS
        "ff02::1:ff00:0",       // solicited-node prefix
        "ff05::1:3",            // site-local DHCP
        "2001:db8::1",          // documentation
        "2001:0db8:0000:0000:0000:0000:0000:0001", // fully expanded
        "2001:db8:0:0:0:0:0:1",                    // partial compression
        "2001:db8:1:2:3:4:5:6",                    // no compression possible
        "fc00::1",                                  // unique local
        "fd00::1",                                  // unique local
        // ==== IPv4-mapped IPv6 ====
        "::ffff:127.0.0.1",
        "::ffff:0:0",
        "::ffff:8.8.8.8",
        "::ffff:255.255.255.255",
        // ==== IPv4-compatible IPv6 (deprecated, but parser may still accept) ====
        "::127.0.0.1",
        "::8.8.8.8",
        // ==== With scope-id suffix ====
        "fe80::1%eth0",
        "fe80::1%lo",
        "fe80::1%1",
        "ff02::1%eth0",
        // ==== Bracketed forms (RFC 3986 URL-style) ====
        "[::1]",
        "[2001:db8::1]",
        // ==== Compression edge cases ====
        "::ffff",
        "0:0:0:0:0:0:0:0",
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",  // all-1s
        "1::",                                       // trailing compression
        "::1:2",                                     // leading compression with two groups
        "1:2::3:4",                                  // middle compression
        // ==== Invalid inputs (parser should reject cleanly) ====
        ":::",                                       // too many colons
        "1::1::1",                                   // two ::
        "::g",                                       // invalid hex digit
        "::-",                                       // invalid char
        "256.256.256.256",                           // octet > 255
        "1.2.3",                                     // truncated IPv4
        "1.2.3.4.5",                                 // extra dot
        "1.2.3.0xff",                                // hex IPv4
        "01.02.03.04",                               // leading zeros
        "1.2.3.4 ",                                  // trailing whitespace
        " 1.2.3.4",                                  // leading whitespace
        "1.2.3.4 abc",                               // garbage suffix
        "0.0.0.0/24",                                // CIDR-style
        "2001:db8::1/64",                            // IPv6 CIDR
        // ==== Empty / boundary ====
        "",
        " ",
        "0",
        ":",
        ".",
        std::string(64, ':'),                        // overflow attempt
        std::string(64, '0'),                        // overflow attempt
    };
}

// Pure-parse fuzzer (length-bounded form). FuzzTest mutates the seeds.
void FromStringLenBoundedFuzz(const std::string & s)
{
    EnsureInitialized();
    IPAddress addr;
    (void) IPAddress::FromString(s.c_str(), s.size(), addr);
}

FUZZ_TEST(IpAddressPW, FromStringLenBoundedFuzz)
    .WithDomains(Arbitrary<std::string>().WithSeeds(IpAddressSeeds()).WithMaxSize(256));

void FromStringNulTerminatedFuzz(const std::string & s)
{
    EnsureInitialized();
    IPAddress addr;
    (void) IPAddress::FromString(s.c_str(), addr);
}

FUZZ_TEST(IpAddressPW, FromStringNulTerminatedFuzz)
    .WithDomains(Arbitrary<std::string>().WithSeeds(IpAddressSeeds()).WithMaxSize(256));

void FromStringWithInterfaceFuzz(const std::string & s)
{
    EnsureInitialized();
    IPAddress addr;
    InterfaceId iface;
    (void) IPAddress::FromString(s.c_str(), addr, iface);
}

FUZZ_TEST(IpAddressPW, FromStringWithInterfaceFuzz)
    .WithDomains(Arbitrary<std::string>().WithSeeds(IpAddressSeeds()).WithMaxSize(256));

// Property-based round-trip: parse → ToString → parse again, assert equal.
void FromStringRoundtripFuzz(const std::string & s)
{
    EnsureInitialized();

    IPAddress first;
    if (!IPAddress::FromString(s.c_str(), s.size(), first))
        return; // not a valid address — skip

    char buf[INET6_ADDRSTRLEN];
    first.ToString(buf, sizeof(buf));

    IPAddress second;
    ASSERT_TRUE(IPAddress::FromString(buf, second));
    ASSERT_TRUE(first == second);
}

FUZZ_TEST(IpAddressPW, FromStringRoundtripFuzz)
    .WithDomains(Arbitrary<std::string>().WithSeeds(IpAddressSeeds()).WithMaxSize(256));

// Property: every valid parse should classify consistently across all the
// IPAddress query methods (Type, IsIPv4/IsIPv6/IsMulticast/IsLinkLocal etc.)
// and ToString/ToIPv6 should not crash on any successfully-parsed address.
void IpAddressClassifyFuzz(const std::string & s)
{
    EnsureInitialized();

    IPAddress addr;
    if (!IPAddress::FromString(s.c_str(), s.size(), addr))
        return;

    // Touch every observable accessor.
    (void) addr.Type();
    (void) addr.IsIPv4();
    (void) addr.IsIPv4Multicast();
    (void) addr.IsIPv4Broadcast();
    (void) addr.IsIPv6();
    (void) addr.IsIPv6Multicast();
    (void) addr.IsIPv6LinkLocal();
    (void) addr.IsIPv6ULA();
    (void) addr.IsIPv6GlobalUnicast();
    (void) addr.IsMulticast();

    char buf[INET6_ADDRSTRLEN];
    addr.ToString(buf, sizeof(buf));

    // ToIPv4/ToIPv6 should be safe to call even if the type doesn't match —
    // they return zero-IP for the wrong type rather than crash.
    (void) addr.ToIPv4();
    (void) addr.ToIPv6();
}

FUZZ_TEST(IpAddressPW, IpAddressClassifyFuzz)
    .WithDomains(Arbitrary<std::string>().WithSeeds(IpAddressSeeds()).WithMaxSize(256));

// Idempotent ToString: format the parsed address twice into different
// buffers, assert the textual output is identical.
void IpAddressToStringStableFuzz(const std::string & s)
{
    EnsureInitialized();

    IPAddress addr;
    if (!IPAddress::FromString(s.c_str(), s.size(), addr))
        return;

    char buf1[INET6_ADDRSTRLEN] = {};
    char buf2[INET6_ADDRSTRLEN] = {};
    addr.ToString(buf1, sizeof(buf1));
    addr.ToString(buf2, sizeof(buf2));
    ASSERT_EQ(std::string(buf1), std::string(buf2));
}

FUZZ_TEST(IpAddressPW, IpAddressToStringStableFuzz)
    .WithDomains(Arbitrary<std::string>().WithSeeds(IpAddressSeeds()).WithMaxSize(256));

} // namespace
