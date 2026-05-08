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
 *      Seeded FuzzTest harness for BLEEndPoint::Receive — the BTP analogue
 *      of FuzzWiFiPAFEndPointPW. Drives the capabilities handshake with
 *      `ElementOf`-bounded windowSize / MTU values that target the field-
 *      validation logic, plus seeded PAFTP-style fragment slots for the
 *      post-Connected reorder queue.
 *
 *      WindowSize values cover: 0, 1, MIN-1, MIN, MIN+1, MAX, MAX+1, 0xFF.
 *      MTU values cover: spec floor (23), the underflow boundary (mtu - 3
 *      arithmetic), MTU = 0, MTU = 1, larger BLE 4.2 / 5.x sizes.
 */

#include <cstdint>
#include <utility>
#include <vector>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

#include <ble/Ble.h>
#include <ble/BLEEndPoint.h>
#include <ble/BleLayer.h>
#include <ble/BleLayerDelegate.h>
#include <ble/BleConfig.h>
#include <lib/core/CHIPError.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <platform/CHIPDeviceLayer.h>
#include <system/SystemLayer.h>
#include <system/SystemPacketBuffer.h>

namespace chip {
namespace Ble {

class FuzzBleLayerDelegate : public BleLayerDelegate
{
public:
    void OnBleConnectionComplete(BLEEndPoint *) override {}
    void OnBleConnectionError(CHIP_ERROR) override {}
    void OnEndPointConnectComplete(BLEEndPoint *, CHIP_ERROR) override {}
    void OnEndPointMessageReceived(BLEEndPoint *, System::PacketBufferHandle &&) override {}
    void OnEndPointConnectionClosed(BLEEndPoint *, CHIP_ERROR) override {}
    CHIP_ERROR SetEndPoint(BLEEndPoint *) override { return CHIP_NO_ERROR; }
};

class FuzzBlePlatformDelegate : public BlePlatformDelegate
{
public:
    CHIP_ERROR SubscribeCharacteristic(BLE_CONNECTION_OBJECT, const ChipBleUUID *, const ChipBleUUID *) override
    {
        return CHIP_NO_ERROR;
    }
    CHIP_ERROR UnsubscribeCharacteristic(BLE_CONNECTION_OBJECT, const ChipBleUUID *, const ChipBleUUID *) override
    {
        return CHIP_NO_ERROR;
    }
    CHIP_ERROR CloseConnection(BLE_CONNECTION_OBJECT) override { return CHIP_NO_ERROR; }
    uint16_t GetMTU(BLE_CONNECTION_OBJECT) const override { return 23; }
    CHIP_ERROR SendIndication(BLE_CONNECTION_OBJECT, const ChipBleUUID *, const ChipBleUUID *,
                              System::PacketBufferHandle) override
    {
        return CHIP_NO_ERROR;
    }
    CHIP_ERROR SendWriteRequest(BLE_CONNECTION_OBJECT, const ChipBleUUID *, const ChipBleUUID *,
                                System::PacketBufferHandle) override
    {
        return CHIP_NO_ERROR;
    }
};

class FuzzBleApplicationDelegate : public BleApplicationDelegate
{
public:
    void NotifyChipConnectionClosed(BLE_CONNECTION_OBJECT) override {}
};

} // namespace Ble
} // namespace chip

namespace {

using chip::Ble::BLEEndPoint;
using chip::Ble::BleLayer;
using chip::Ble::FuzzBleApplicationDelegate;
using chip::Ble::FuzzBleLayerDelegate;
using chip::Ble::FuzzBlePlatformDelegate;
using chip::Ble::kBleRole_Central;
using chip::Ble::kBleRole_Peripheral;
using chip::Ble::BleRole;
using chip::System::PacketBufferHandle;
using namespace fuzztest;

void EnsureInitialized()
{
    static const bool sInitialized = [] {
        VerifyOrDie(chip::Platform::MemoryInit() == CHIP_NO_ERROR);
        VerifyOrDie(chip::DeviceLayer::SystemLayer().Init() == CHIP_NO_ERROR);
        std::atexit([] { chip::DeviceLayer::SystemLayer().Shutdown(); });
        return true;
    }();
    (void) sInitialized;
}

PacketBufferHandle BuildCapabilitiesRequest(uint8_t windowSize, uint16_t mtu)
{
    constexpr size_t kReqLen = 9;
    auto buf = PacketBufferHandle::New(kReqLen);
    if (buf.IsNull())
        return buf;
    uint8_t * p = buf->Start();
    p[0] = 0x65; // CHECK_BYTE_1
    p[1] = 0x6C; // CHECK_BYTE_2
    p[2] = 0x04; // version
    p[3] = 0x00;
    p[4] = 0x00;
    p[5] = static_cast<uint8_t>(mtu);
    p[6] = static_cast<uint8_t>(mtu >> 8);
    p[7] = windowSize;
    p[8] = 0x00;
    buf->SetDataLength(kReqLen);
    return buf;
}

PacketBufferHandle BuildCapabilitiesResponse(uint8_t windowSize, uint16_t fragmentSize)
{
    constexpr size_t kRespLen = 6;
    auto buf = PacketBufferHandle::New(kRespLen);
    if (buf.IsNull())
        return buf;
    uint8_t * p = buf->Start();
    p[0] = 0x65;
    p[1] = 0x6C;
    p[2] = 0x04;
    p[3] = static_cast<uint8_t>(fragmentSize);
    p[4] = static_cast<uint8_t>(fragmentSize >> 8);
    p[5] = windowSize;
    buf->SetDataLength(kRespLen);
    return buf;
}

auto AnyRole()
{
    return ElementOf<BleRole>({ kBleRole_Central, kBleRole_Peripheral });
}

// Boundary values for the window-size field — the bug class fixed by
// PR #43031 lives at 0..effective-min and around MAX. Per BleConfig.h the
// effective minimum for stability is 3 (BLE_MAX_RECEIVE_WINDOW_SIZE must
// be > 2), so the danger zone is 0/1/2 plus the boundary around MAX.
auto AnyWindowSize()
{
    return ElementOf<uint8_t>({
        static_cast<uint8_t>(0),
        static_cast<uint8_t>(1),
        static_cast<uint8_t>(2),
        static_cast<uint8_t>(3),
        static_cast<uint8_t>(BLE_MAX_RECEIVE_WINDOW_SIZE - 1),
        static_cast<uint8_t>(BLE_MAX_RECEIVE_WINDOW_SIZE),
        static_cast<uint8_t>(BLE_MAX_RECEIVE_WINDOW_SIZE + 1),
        static_cast<uint8_t>(0xFE),
        static_cast<uint8_t>(0xFF),
    });
}

// MTU values that target the `mtu - 3` underflow path in the BTP fragment-
// length calculation.
auto AnyMtu()
{
    return ElementOf<uint16_t>({
        0,
        1,
        2,
        3,
        4,
        20,
        23,    // BLE 4.0 ATT_MTU floor
        100,
        185,   // BLE 4.2 default
        247,   // BLE 5.x extended
        512,
        1024,
        0xFFFE,
        0xFFFF,
    });
}

// Real BTP data-phase fragment shapes.
std::vector<std::vector<uint8_t>> BtpDataFragmentSeeds()
{
    return {
        { 0x05, 0x01, 0x01, 0x00, 0x00 }, // start+end, seq 1, ack
        { 0x05, 0x01, 0x03, 0x00, 0x00 }, // out-of-order seq 3
        { 0x01, 0x00, 0x01, 0x00, 0x00 }, // start only, no ack
        { 0x04, 0x01, 0x02, 0x00 },       // end only, seq 2
        { 0x08 },                         // pure ack
    };
}

void BleEndpointReceiveDoesNotCrash(BleRole role, bool sendResponse, uint8_t windowSize, uint16_t lengthField,
                                    const std::vector<uint8_t> & frag0, const std::vector<uint8_t> & frag1,
                                    const std::vector<uint8_t> & frag2)
{
    EnsureInitialized();

    BleLayer layer;
    FuzzBlePlatformDelegate platformDelegate;
    FuzzBleApplicationDelegate appDelegate;
    FuzzBleLayerDelegate layerDelegate;

    if (layer.Init(&platformDelegate, &appDelegate, &chip::DeviceLayer::SystemLayer()) != CHIP_NO_ERROR)
    {
        return;
    }
    layer.mBleTransport = &layerDelegate;

    BLEEndPoint * ep = nullptr;
    if (layer.NewBleEndPoint(&ep, /* connObj */ nullptr, role, /* autoClose */ false) != CHIP_NO_ERROR || ep == nullptr)
    {
        layer.Shutdown();
        return;
    }

    PacketBufferHandle handshake =
        sendResponse ? BuildCapabilitiesResponse(windowSize, lengthField) : BuildCapabilitiesRequest(windowSize, lengthField);
    if (!handshake.IsNull())
    {
        RETURN_SAFELY_IGNORED ep->Receive(std::move(handshake));
    }

    for (const auto * frag : { &frag0, &frag1, &frag2 })
    {
        auto buf = PacketBufferHandle::NewWithData(frag->data(), frag->size());
        if (buf.IsNull())
            continue;
        RETURN_SAFELY_IGNORED ep->Receive(std::move(buf));
    }

    ep->Close();
    layer.Shutdown();
}

FUZZ_TEST(FuzzBleEndPointPW, BleEndpointReceiveDoesNotCrash)
    .WithDomains(
        AnyRole(),
        Arbitrary<bool>(),
        AnyWindowSize(),
        AnyMtu(),
        Arbitrary<std::vector<uint8_t>>().WithSeeds(BtpDataFragmentSeeds()),
        Arbitrary<std::vector<uint8_t>>().WithSeeds(BtpDataFragmentSeeds()),
        Arbitrary<std::vector<uint8_t>>().WithSeeds(BtpDataFragmentSeeds()));

} // namespace
