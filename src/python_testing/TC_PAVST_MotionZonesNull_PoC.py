# PoC: AllocatePushTransport with triggerType=kMotion and motionZones present-but-NULL
# triggers VerifyOrDie in TransportTriggerOptionsStorage::operator= (storage.h:160) ->
# motionZones.Value().SetNull() on an empty Optional -> node crash.
#
# Local-only reproduction harness (NOT for commit). Modeled on TC_PAVST_2_7.
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


class TC_PAVST_MotionZonesNull_PoC(MatterBaseTest, PAVSTTestBase, PAVSTIUtils):
    def desc_TC_PAVST_MotionZonesNull_PoC(self) -> str:
        return "[PoC] AllocatePushTransport kMotion + motionZones=NULL crashes DUT (storage.h:160)"

    def pics_TC_PAVST_MotionZonesNull_PoC(self):
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

    def steps_TC_PAVST_MotionZonesNull_PoC(self) -> list[TestStep]:
        return [
            TestStep("precondition", "Commission + provision TLS endpoint + allocate streams", is_commissioning=True),
            TestStep(1, "Send AllocatePushTransport(kMotion, motionZones=NULL). DUT must NOT crash (red before fix).",
                     "Expect ConstraintError/InvalidCommand or Success — NOT a process abort / connection loss."),
        ]

    @async_test_body
    async def test_TC_PAVST_MotionZonesNull_PoC(self):
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
        # triggerType=kMotion with motionZones present-but-NULL.
        # Validation requires motionZones.HasValue() (satisfied: present) but never rejects the
        # null case; the storage operator= then derefs the empty member.
        triggerOptions = {
            "triggerType": pvcluster.Enums.TransportTriggerTypeEnum.kMotion,
            "maxPreRollLen": 4000,
            "motionZones": NullValue,
            "motionTimeControl": {"initialDuration": 1, "augmentationDuration": 1, "maxDuration": 20, "blindDuration": 1},
        }

        log.info("PoC: sending AllocatePushTransport(kMotion, motionZones=NULL) — expecting DUT crash if bug present")
        crashed = False
        try:
            status = await self.allocate_one_pushav_transport(
                endpoint, trigger_Options=triggerOptions, tlsEndPoint=self.tlsEndpointId,
                url=f"https://{host_ip}:1234/streams/{uploadStreamId}/")
            log.info(f"PoC: DUT returned status={status} (NO crash → bug absent/fixed)")
        except InteractionModelError as e:
            log.info(f"PoC: InteractionModelError status={e.status} (graceful → not a crash)")
        except Exception as e:  # ChipStackError / timeout / connection loss == device aborted
            crashed = True
            log.error(f"PoC: exception '{type(e).__name__}: {e}' — DUT likely CRASHED (VerifyOrDie). Check app stderr for abort.")

        # The bug manifests as a process abort: the command never returns and the session drops.
        # Assert the device survived (this assertion is RED before the fix, GREEN after).
        asserts.assert_false(crashed, "DUT crashed handling AllocatePushTransport(kMotion, motionZones=NULL) — storage.h:160 VerifyOrDie")


if __name__ == "__main__":
    default_matter_test_main()
