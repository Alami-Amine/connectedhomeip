/*
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

// Fuzz harness for BLEEndPoint, mirroring
// src/wifipaf/tests/FuzzWiFiPAFEndPoint.cpp.
//
// Targets the BTP capabilities handshake and the Receive() path. Crafted
// inputs exercise:
//   - peer-supplied req.mWindowSize / resp.mWindowSize at boundaries:
//     0, 1, 2, BLE_MIN_RECEIVE_WINDOW_SIZE - 1, > BLE_MAX_RECEIVE_WINDOW_SIZE.
//     This is the bug class fixed by PR #43031 (WiFiPAF) and its BTP twin.
//   - peer-supplied req.mMtu near the underflow boundary (`mtu - 3`).
//   - reorder-queue / reassembly fragments fed after the handshake.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <utility>

#include <ble/Ble.h>
#include <ble/BLEEndPoint.h>
#include <ble/BleLayer.h>
#include <ble/BleLayerDelegate.h>
#include <lib/core/CHIPError.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <platform/CHIPDeviceLayer.h>
#include <system/SystemLayer.h>
#include <system/SystemPacketBuffer.h>

namespace chip {
namespace Ble {

// Sink delegates: swallow everything, never re-enter the layer.
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
using chip::System::PacketBufferHandle;

bool EnsureInitialized()
{
    static const bool sInitialized = [] {
        VerifyOrDie(chip::Platform::MemoryInit() == CHIP_NO_ERROR);
        VerifyOrDie(chip::DeviceLayer::SystemLayer().Init() == CHIP_NO_ERROR);
        std::atexit([] { chip::DeviceLayer::SystemLayer().Shutdown(); });
        return true;
    }();
    return sInitialized;
}

// 9-byte BTP capabilities-request payload.
PacketBufferHandle BuildCapabilitiesRequest(uint8_t windowSize, uint16_t mtu)
{
    constexpr size_t kReqLen = 9;
    auto buf                 = PacketBufferHandle::New(kReqLen);
    if (buf.IsNull())
    {
        return buf;
    }
    uint8_t * p = buf->Start();
    p[0]        = 0x65;                              // CAPABILITIES_MSG_CHECK_BYTE_1
    p[1]        = 0x6C;                              // CAPABILITIES_MSG_CHECK_BYTE_2
    p[2]        = 0x04;
    p[3]        = 0x00;
    p[4]        = 0x00;
    p[5]        = static_cast<uint8_t>(mtu);         // mMtu LE low
    p[6]        = static_cast<uint8_t>(mtu >> 8);    // mMtu LE high
    p[7]        = windowSize;                        // *** target field ***
    p[8]        = 0x00;
    buf->SetDataLength(kReqLen);
    return buf;
}

// 6-byte BTP capabilities-response payload.
PacketBufferHandle BuildCapabilitiesResponse(uint8_t windowSize, uint16_t fragmentSize)
{
    constexpr size_t kRespLen = 6;
    auto buf                  = PacketBufferHandle::New(kRespLen);
    if (buf.IsNull())
    {
        return buf;
    }
    uint8_t * p = buf->Start();
    p[0]        = 0x65;
    p[1]        = 0x6C;
    p[2]        = 0x04;                                       // selected version
    p[3]        = static_cast<uint8_t>(fragmentSize);         // mFragmentSize LE low
    p[4]        = static_cast<uint8_t>(fragmentSize >> 8);    // mFragmentSize LE high
    p[5]        = windowSize;                                 // *** target field ***
    buf->SetDataLength(kRespLen);
    return buf;
}

} // namespace

// Fuzzer input layout:
//   byte 0 : config
//              bit 0 -> role (1 = Central, 0 = Peripheral)
//              bit 1 -> handshake message (1 = response, 0 = request)
//   byte 1 : windowSize (the field we're attacking)
//   bytes 2..3 (LE) : mMtu (request) or mFragmentSize (response)
//   rest   : <2-byte BE length><payload> fragments fed to Receive after the
//            handshake, exercising reorder-queue / reassembly state.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)
{
    (void) EnsureInitialized();

    if (size < 4)
    {
        return 0;
    }

    const uint8_t config       = data[0];
    const auto role            = (config & 0x01) ? kBleRole_Central : kBleRole_Peripheral;
    const bool sendResponse    = (config & 0x02) != 0;
    const uint8_t windowSize   = data[1];
    const uint16_t lengthField = static_cast<uint16_t>(data[2] | (data[3] << 8));

    BleLayer layer;
    FuzzBlePlatformDelegate platformDelegate;
    FuzzBleApplicationDelegate appDelegate;
    FuzzBleLayerDelegate layerDelegate;

    if (layer.Init(&platformDelegate, &appDelegate, &chip::DeviceLayer::SystemLayer()) != CHIP_NO_ERROR)
    {
        return 0;
    }
    layer.mBleTransport = &layerDelegate;

    BLEEndPoint * ep = nullptr;
    if (layer.NewBleEndPoint(&ep, /* connObj */ nullptr, role, /* autoClose */ false) != CHIP_NO_ERROR || ep == nullptr)
    {
        layer.Shutdown();
        return 0;
    }

    PacketBufferHandle handshake = sendResponse ? BuildCapabilitiesResponse(windowSize, lengthField)
                                                : BuildCapabilitiesRequest(windowSize, lengthField);
    if (!handshake.IsNull())
    {
        (void) ep->Receive(std::move(handshake));
    }

    // Post-handshake fragments: <2-byte BE length><payload>
    size_t cursor = 4;
    while (cursor + 2 <= size)
    {
        uint16_t fragLen = static_cast<uint16_t>((data[cursor] << 8) | data[cursor + 1]);
        cursor += 2;

        const size_t available = size - cursor;
        if (fragLen > available)
        {
            fragLen = static_cast<uint16_t>(available);
        }

        auto buf = PacketBufferHandle::NewWithData(data + cursor, fragLen);
        cursor += fragLen;
        if (buf.IsNull())
        {
            break;
        }

        (void) ep->Receive(std::move(buf));
    }

    ep->Close();
    layer.Shutdown();
    return 0;
}
