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
 *      Seeded FuzzTest harness for UDC payload parsers. Seeds are real
 *      payloads produced by the matching WritePayload(); the mutator
 *      explores the typed-fields branches (instance name, vid/pid,
 *      pairing instructions, target app infos) instead of bouncing off
 *      WritePayload's TLV-tag check.
 */

#include <cstdint>
#include <string>
#include <vector>

#include <lib/support/CHIPMem.h>
#include <protocols/user_directed_commissioning/UserDirectedCommissioning.h>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

namespace {

using namespace chip;
using namespace chip::Protocols::UserDirectedCommissioning;
using namespace fuzztest;

std::string BuildIdentificationDeclarationSeed(uint16_t vid = 0xFFF1, uint16_t pid = 0x8001,
                                               const char * deviceName = "Matter Fuzz Device",
                                               uint8_t pairingHint = 1, bool withRotatingId = true,
                                               bool withTargetApps = false)
{
    Platform::MemoryInit();

    IdentificationDeclaration id;
    id.SetInstanceName("FUZZ-INSTANCE-12345678");
    id.SetVendorId(vid);
    id.SetProductId(pid);
    id.SetDeviceName(deviceName);
    if (withRotatingId)
    {
        static const uint8_t rotatingId[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A };
        id.SetRotatingId(rotatingId, sizeof(rotatingId));
    }
    id.SetCdPort(0x1234);
    id.SetPairingInst("Press the button");
    id.SetPairingHint(pairingHint);
    if (withTargetApps)
    {
        TargetAppInfo info;
        info.vendorId  = 0xFFF2;
        info.productId = 0x8002;
        id.AddTargetAppInfo(info);
    }

    uint8_t buf[1024];
    uint32_t written = id.WritePayload(buf, sizeof(buf));
    Platform::MemoryShutdown();
    if (written == 0)
        return {};
    return std::string(reinterpret_cast<const char *>(buf), written);
}

std::string BuildCommissionerDeclarationSeed(CommissionerDeclaration::CdError err = CommissionerDeclaration::CdError::kNoError,
                                             bool needsPasscode = false, bool noAppsFound = false,
                                             bool qrDisplayed = true, uint8_t passcodeLen = 8,
                                             bool cancelPasscode = false, bool passcodeDialogDisplayed = false)
{
    Platform::MemoryInit();

    CommissionerDeclaration cd;
    cd.SetErrorCode(err);
    cd.SetCommissionerPasscode(true);
    cd.SetNeedsPasscode(needsPasscode);
    cd.SetNoAppsFound(noAppsFound);
    cd.SetQRCodeDisplayed(qrDisplayed);
    cd.SetPasscodeLength(passcodeLen);
    cd.SetCancelPasscode(cancelPasscode);
    cd.SetPasscodeDialogDisplayed(passcodeDialogDisplayed);

    uint8_t buf[1024];
    uint32_t written = cd.WritePayload(buf, sizeof(buf));
    Platform::MemoryShutdown();
    if (written == 0)
        return {};
    return std::string(reinterpret_cast<const char *>(buf), written);
}

void IdentificationDeclarationFuzz(const std::string & bytes)
{
    Platform::MemoryInit();
    std::vector<uint8_t> mutableCopy(bytes.begin(), bytes.end());
    IdentificationDeclaration id;
    RETURN_SAFELY_IGNORED id.ReadPayload(mutableCopy.data(), mutableCopy.size());
    Platform::MemoryShutdown();
}

void CommissionerDeclarationFuzz(const std::string & bytes)
{
    Platform::MemoryInit();
    std::vector<uint8_t> mutableCopy(bytes.begin(), bytes.end());
    CommissionerDeclaration cd;
    RETURN_SAFELY_IGNORED cd.ReadPayload(mutableCopy.data(), mutableCopy.size());
    Platform::MemoryShutdown();
}

auto SeededId()
{
    std::vector<std::string> seeds;
    auto add = [&](std::string s) { if (!s.empty()) seeds.push_back(std::move(s)); };
    add(BuildIdentificationDeclarationSeed(0xFFF1, 0x8001, "Matter Fuzz Device", 1, true, false));
    add(BuildIdentificationDeclarationSeed(0x0001, 0x0001, "Short Name", 0, false, false));
    add(BuildIdentificationDeclarationSeed(0xFFFF, 0xFFFF, "Long Device Name " "With Many Characters Spread Across The Buffer", 16, true, true));
    add(BuildIdentificationDeclarationSeed(0x0FFF, 0x1234, "", 0, false, false));
    add(BuildIdentificationDeclarationSeed(0xFFF1, 0x8001, "App Targets", 5, false, true));
    return Arbitrary<std::string>().WithSeeds(seeds);
}

auto SeededCd()
{
    std::vector<std::string> seeds;
    auto add = [&](std::string s) { if (!s.empty()) seeds.push_back(std::move(s)); };
    using Err = CommissionerDeclaration::CdError;
    add(BuildCommissionerDeclarationSeed(Err::kNoError, false, false, true, 8, false, false));
    add(BuildCommissionerDeclarationSeed(Err::kPaseConnectionFailed, true, false, true, 6, false, false));
    add(BuildCommissionerDeclarationSeed(Err::kCommissionerPasscodeNotSupported, false, true, false, 0, false, true));
    add(BuildCommissionerDeclarationSeed(Err::kAppInstallConsentPending, true, false, false, 0, true, true));
    add(BuildCommissionerDeclarationSeed(Err::kInvalidIdentificationDeclarationParams, false, false, true, 11, false, false));
    return Arbitrary<std::string>().WithSeeds(seeds);
}

FUZZ_TEST(UdcMessages, IdentificationDeclarationFuzz).WithDomains(SeededId());
FUZZ_TEST(UdcMessages, CommissionerDeclarationFuzz).WithDomains(SeededCd());

} // namespace
