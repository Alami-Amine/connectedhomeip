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
 *      Fuzzes Inet::IPAddress::FromString — the string-to-IPAddress parser.
 *      Reachable from cluster commands (e.g. NetworkCommissioning, OTA
 *      provider URLs), config files, mDNS-resolved targets, and command-line
 *      tools that take user-typed addresses.
 */

#include <cstddef>
#include <cstdint>
#include <string>

#include <inet/IPAddress.h>
#include <inet/InetInterface.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t len)
{
    using namespace chip::Inet;

    // Length-bounded form (no NUL required).
    {
        IPAddress out;
        (void) IPAddress::FromString(reinterpret_cast<const char *>(data), len, out);
    }

    // C-string form: pass through std::string to ensure NUL termination.
    {
        std::string s(reinterpret_cast<const char *>(data), len);
        IPAddress out;
        (void) IPAddress::FromString(s.c_str(), out);
    }

    // Length-bounded with InterfaceId: explicit overload not present, but the
    // (str, addr, ifaceOutput) form requires NUL-terminated input.
    {
        std::string s(reinterpret_cast<const char *>(data), len);
        IPAddress out;
        InterfaceId iface;
        (void) IPAddress::FromString(s.c_str(), out, iface);
    }

    return 0;
}
