# PoC variant: AllocatePushTransport with triggerType=kMotion, a non-null motionZones list whose
# single entry has zone=NULL ("all zones", which bypasses ValidateZoneId so no defined zone is needed)
# and NO per-zone sensitivity, plus motionSensitivity present-but-NULL.
#
# On a !kPerZoneSensitivity device this drives the camera delegate's else branch
# (push-av-stream-manager.cpp:165) -> motionSensitivity.Value().Value() on a null Nullable ->
# std::bad_optional_access -> terminate -> node crash.
#
# Purpose: determine whether line 165 is REACHABLE or whether ValidateMotionZoneListSize gates it.
# Local-only reproduction harness (NOT for commit). Modeled on TC_PAVST_MotionZonesNull_PoC.
#
# === BEGIN CI TEST ARGUMENTS ===
# test-runner-runs:
#   run1:
#     app: ${CAMERA_APP}
#     app-args: --discriminator 1234 --KVS kvs1 --trace-to json:${TRACE_APP}.json
#     script-args: >
#       --storage-path admin_storage.json
#       --string-arg th_server_app_path:${PUSH_AV_SERVER}
#       --string-arg host_ip:localhost
#       --commissioning-method on-network
#       --discriminator 1234
#       --passcode 20202021
#       --PICS src/app/tests/suites/certification/ci-pics-values
#       --endpoint 1
#     factory-reset: true
#     quiet: false
# === END CI TEST ARGUMENTS ===

import logging

from mobly import asserts
from TC_PAVSTI_Utils import PAVSTIUtils, PushAvServerProcess, SupportedIngestInterface
from TC_PAVSTTestBase import PAVSTTestBase

import matter.clusters as Clusters
from matter.clusters.Types import NullValue
from matter.interaction_model import InteractionModelError, Status
from matter.testing.decorators import async_test_body
from matter.testing.matter_testing import MatterBaseTest
from matter.testing.runner import TestStep, default_matter_test_main

log = logging.getLogger(__name__)


class TC_PAVST_MotionSensitivityNull_PoC(MatterBaseTest, PAVSTTestBase, PAVSTIUtils):
    def desc_TC_PAVST_MotionSensitivityNull_PoC(self) -> str:
        return "[PoC] AllocatePushTransport kMotion + zone=NULL + motionSensitivity=NULL (manager.cpp:165)"

    def pics_TC_PAVST_MotionSensitivityNull_PoC(self):
        return ["PAVST.S"]

    @async_test_body
    async def setup_class(self):
        th_server_app = self.user_params.get("th_server_app_path", None)
        self.server = PushAvServerProcess(server_path=th_server_app)
        self.server.start(expected_output="Running on https://0.0.0.0:1234", timeout=30)
        super().setup_class()

    def teardown_class(self):
        if getattr(self, "server", None) is not None:
            self.server.terminate()
        super().teardown_class()

    def steps_TC_PAVST_MotionSensitivityNull_PoC(self) -> list[TestStep]:
        return [
            TestStep("precondition", "Commission + provision TLS endpoint + allocate streams", is_commissioning=True),
            TestStep(1, "Send AllocatePushTransport(kMotion, motionZones=[{zone:NULL}], motionSensitivity=NULL).",
                     "DUT must NOT crash: expect Success or a graceful Constraint/InvalidCommand — NOT a process abort."),
            TestStep(2, "Liveness check: read FeatureMap. A response proves the DUT survived (no crash)."),
        ]

    @async_test_body
    async def test_TC_PAVST_MotionSensitivityNull_PoC(self):
        endpoint = self.get_endpoint()
        self.endpoint = endpoint
        pvcluster = Clusters.PushAvStreamTransport

        self.step("precondition")
        host_ip = self.user_params.get("host_ip", None)
        self.tlsEndpointId, host_ip = await self.precondition_provision_tls_endpoint(server=self.server, host_ip=host_ip)
        uploadStreamId = self.server.create_stream(SupportedIngestInterface.cmaf)
        await self.allocate_one_video_stream()
        await self.allocate_one_audio_stream()

        self.step(1)
        # zone=NULL ("all zones") => ValidateZoneId is skipped, so no defined ZoneManagement zone is needed.
        # No per-zone sensitivity (required for !kPerZoneSensitivity). motionSensitivity present-but-NULL passes
        # validation (HasValue required, range-check gated on !IsNull) but is unwrapped at manager.cpp:165.
        triggerOptions = {
            "triggerType": pvcluster.Enums.TransportTriggerTypeEnum.kMotion,
            "maxPreRollLen": 4000,
            "motionZones": [{"zone": NullValue}],
            "motionSensitivity": NullValue,
            "motionTimeControl": {"initialDuration": 1, "augmentationDuration": 1, "maxDuration": 20, "blindDuration": 1},
        }

        log.info("PoC: sending AllocatePushTransport(kMotion, zone=NULL, motionSensitivity=NULL)")
        crashed = False
        try:
            status = await self.allocate_one_pushav_transport(
                endpoint, trigger_Options=triggerOptions, tlsEndPoint=self.tlsEndpointId,
                url=f"https://{host_ip}:1234/streams/{uploadStreamId}/")
            log.info(f"PoC: DUT returned status={status} (handled gracefully, no crash)")
        except InteractionModelError as e:
            log.info(f"PoC: InteractionModelError status={e.status} (graceful rejection, not a crash)")
        except Exception as e:  # ChipStackError / timeout / connection loss == device aborted
            crashed = True
            log.error(f"PoC: exception '{type(e).__name__}: {e}' — DUT likely CRASHED at manager.cpp:165. Check app stderr.")

        self.step(2)
        if not crashed:
            try:
                await self.read_single_attribute_check_success(
                    endpoint=endpoint, cluster=Clusters.CameraAvStreamManagement,
                    attribute=Clusters.CameraAvStreamManagement.Attributes.FeatureMap)
                log.info("PoC: liveness read succeeded — DUT is alive.")
            except Exception as e:
                crashed = True
                log.error(f"PoC: liveness read failed ('{type(e).__name__}') — DUT did not survive.")

        asserts.assert_false(crashed, "DUT crashed handling AllocatePushTransport(kMotion, zone=NULL, motionSensitivity=NULL) — manager.cpp:165")


if __name__ == "__main__":
    default_matter_test_main()
