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
 *      Stateful FuzzTest harness for the Matter group-multicast peer-counter table.
 *
 *      An attacker driving a stream of decryptable group datagrams
 *      with many distinct attacker-controlled sourceNodeIds accumulates state in the
 *      file-static gGroupPeerTable and hits an out-of-bounds index or a corrupt count in
 *      the LRU maintenance code (src/transport/GroupPeerMessageCounter.cpp):
 *        - ShiftAndInsert                 (lines 39-46)
 *        - FindOrAddPeerFabricFound       (lines 58-98: insertPos, peerCount++, list[maxLimit-1])
 *        - GroupPeerTable::FindOrAddPeer  (lines 110-129: empty-fabric first-add)
 *
 *      FindOrAddPeer is called at SessionManager.cpp:1289 AFTER AES-CCM MIC verification
 *      succeeds. Raw byte mutation cannot forge a valid MIC, so this harness ENCRYPTS each
 *      datagram with the real group key (the device legitimately holds this shared symmetric
 *      key) using an attacker-chosen sourceNodeId/counter, then feeds the ciphertext through
 *      the real entry point SessionManager::OnMessageReceived. The corruption, if any, is a
 *      function of accumulated table state across many datagrams, so the input is decoded as
 *      a SEQUENCE of records and replayed within one fuzz input.
 *
 *      Uses the real SessionManager / FabricTable / GroupDataProviderImpl / CryptoContext /
 *      file-static gGroupPeerTable / real libcrypto. Nothing on the attacker path is stubbed.
 *      The datagram encoder is NOT a stub -- it is the legitimate group-message encryptor
 *      (production PrepareMessage hard-codes sourceNodeId = fabric->GetNodeId() at
 *      SessionManager.cpp:224, so it cannot vary the node ID; the encoder replicates the
 *      real encrypt sequence at SessionManager.cpp:219-313 with a chosen node ID).
 */

#include <array>
#include <cstdint>
#include <cstdlib>
#include <mutex>
#include <utility>
#include <vector>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

#include <credentials/GroupDataProviderImpl.h>
#include <credentials/PersistentStorageOpCertStore.h>
#include <credentials/tests/CHIPCert_unit_test_vectors.h>
#include <crypto/CHIPCryptoPAL.h>
#include <crypto/DefaultSessionKeystore.h>
#include <crypto/PersistentStorageOperationalKeystore.h>
#include <lib/core/CHIPCore.h>
#include <lib/support/AutoRelease.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/TestPersistentStorageDelegate.h>
#include <protocols/interaction_model/Constants.h>
#include <protocols/secure_channel/MessageCounterManager.h>
#include <transport/CryptoContext.h>
#include <transport/GroupSession.h>
#include <transport/SecureMessageCodec.h>
#include <transport/SessionManager.h>
#include <transport/TransportMgr.h>
#include <transport/raw/MessageHeader.h>
#include <transport/tests/LoopbackTransportManager.h>

namespace {

using namespace chip;
using namespace chip::Transport;
using namespace chip::Credentials;
using namespace fuzztest;

using chip::System::PacketBufferHandle;

using GroupInfo = GroupDataProvider::GroupInfo;
using GroupKey  = GroupDataProvider::GroupKey;
using KeySet    = GroupDataProvider::KeySet;

// The single group id every fabric registers a key for. The attacker (a group-key holder)
// controls the datagram's sourceNodeId/counter; the epoch key is legitimately configured.
constexpr GroupId kGroupId       = 2;
constexpr uint16_t kTestKeysetId = 0x0123;

// Number of fabrics the harness attempts to install. The FabricTable / cert vectors cap how
// many actually succeed; the real count is recorded in Fixture::fabricCount and used for the
// fabricSel % fabricCount routing. >=2 exercises the fabric-search loop and a second
// mGroupFabrics first-add slot; a single fabric still fully drives the 15-cap LRU.
constexpr size_t kMaxFabrics = 4;

// Distinct epoch key per fabric so each yields a distinct derived group key.
const uint8_t kEpochKeys[kMaxFabrics][16] = {
    { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf },
    { 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf },
    { 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf },
    { 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef },
};

// No-op sink: SessionMessageDelegate is the out-of-scope (ExchangeManager) boundary at
// SessionManager.cpp:1354. It performs no trust-boundary check on the attacker path.
class NoopDelegate : public SessionMessageDelegate
{
public:
    void OnMessageReceived(const PacketHeader &, const PayloadHeader &, const SessionHandle &, DuplicateMessage,
                           System::PacketBufferHandle &&) override
    {
    }
};

// Persistent one-time harness state, created once and reused across every fuzz input.
// gGroupPeerTable is file-static and persistent regardless; the per-input reset (below)
// clears the table so each input is self-contained and reproducible.
struct Fixture
{
    Testing::LoopbackTransportManager ctx;
    FabricTable fabricTable;
    TestPersistentStorageDelegate fabricStorage;
    PersistentStorageOperationalKeystore opKeyStore;
    PersistentStorageOpCertStore opCertStore;

    TestPersistentStorageDelegate providerStorage;
    Crypto::DefaultSessionKeystore providerKeystore;
    GroupDataProviderImpl provider{ /*maxGroupsPerFabric*/ 5, /*maxGroupKeysPerFabric*/ 8 };

    TestPersistentStorageDelegate deviceStorage;
    Crypto::DefaultSessionKeystore sessionKeystore;
    secure_channel::MessageCounterManager messageCounterManager;

    SessionManager sessionManager;
    NoopDelegate delegate;

    std::array<FabricIndex, kMaxFabrics> fabricIndices{};
    size_t fabricCount = 0;

    PeerAddress peer;
};

Fixture * gFixture = nullptr;

// Install one fabric (via a distinct NOC asset) plus its group key with a distinct epoch key.
// Returns true on success. AddNewFabricForTestIgnoringCollisions yields a distinct fabric_index
// per successful add.
bool InstallFabric(Fixture & fx, size_t slot, const TestCerts::UnitTestCertAsset & root,
                   const TestCerts::UnitTestCertAsset & icac, const TestCerts::UnitTestCertAsset & noc)
{
    FabricIndex fabricIndex = kUndefinedFabricIndex;
    if (fx.fabricTable.AddNewFabricForTestIgnoringCollisions(root.mCert, icac.mCert, noc.mCert, noc.mKey, &fabricIndex) !=
        CHIP_NO_ERROR)
    {
        return false;
    }

    uint8_t compressedFabricBuf[sizeof(uint64_t)];
    MutableByteSpan compressedFabricSpan(compressedFabricBuf);
    const FabricInfo * info = fx.fabricTable.FindFabricWithIndex(fabricIndex);
    if (info == nullptr || info->GetCompressedFabricIdBytes(compressedFabricSpan) != CHIP_NO_ERROR)
    {
        return false;
    }

    KeySet keySet(kTestKeysetId, GroupDataProvider::SecurityPolicy::kTrustFirst, 1);
    memcpy(keySet.epoch_keys[0].key, kEpochKeys[slot], 16);
    keySet.epoch_keys[0].start_time = 0;
    GroupKey groupKey(kGroupId, kTestKeysetId);
    GroupInfo groupInfo(kGroupId, "Group");

    VerifyOrReturnValue(fx.provider.SetKeySet(fabricIndex, compressedFabricSpan, keySet) == CHIP_NO_ERROR, false);
    VerifyOrReturnValue(fx.provider.SetGroupKeyAt(fabricIndex, 0, groupKey) == CHIP_NO_ERROR, false);
    VerifyOrReturnValue(fx.provider.SetGroupInfoAt(fabricIndex, 0, groupInfo) == CHIP_NO_ERROR, false);

    fx.fabricIndices[fx.fabricCount++] = fabricIndex;
    return true;
}

// Encode a valid, privacy-protected group datagram carrying an ATTACKER-CHOSEN sourceNodeId /
// counter / control-flag, using fabric `slot`'s real key. This mirrors the production encrypt
// sequence at SessionManager.cpp:219-313 exactly; the ONLY difference from PrepareMessage is
// that the node id, counter and control flag are chosen (production hard-codes them). Returns a
// CHIP_ERROR; on success `out` holds the wire bytes. Not a stub -- no trust-boundary check is
// added or removed.
CHIP_ERROR EncodeGroupDatagram(Fixture & fx, size_t slot, NodeId nodeId, uint32_t counter, bool isControl,
                               std::vector<uint8_t> & out)
{
    const FabricIndex fabricIndex = fx.fabricIndices[slot];

    PayloadHeader payloadHeader;
    payloadHeader.SetMessageType(chip::Protocols::InteractionModel::MsgType::InvokeCommandRequest);
    // No reliability/ack flag: payloadHeader.NeedsAck() must be false, else dispatch returns
    // at SessionManager.cpp:1278 before FindOrAddPeer.

    const uint8_t payload[] = { 'h', '4' };
    System::PacketBufferHandle msg =
        MessagePacketBuffer::NewWithData(payload, sizeof(payload));
    VerifyOrReturnError(!msg.IsNull(), CHIP_ERROR_NO_MEMORY);

    PacketHeader packetHeader;
    packetHeader.SetDestinationGroupId(kGroupId);
    packetHeader.SetMessageCounter(counter);
    packetHeader.SetSessionType(Header::SessionType::kGroupSession);
    packetHeader.SetFlags(Header::SecFlagValues::kPrivacyFlag);
    packetHeader.SetSourceNodeId(nodeId);
    // Flips the secFlags C-bit read at SessionManager.cpp:1289 to route control vs data.
    packetHeader.SetSecureSessionControlMsg(isControl);

    auto * groups = Credentials::GetGroupDataProvider();
    VerifyOrReturnError(groups != nullptr, CHIP_ERROR_INTERNAL);
    Crypto::SymmetricKeyContext * keyContext = groups->GetKeyContext(fabricIndex, kGroupId);
    VerifyOrReturnError(keyContext != nullptr, CHIP_ERROR_INTERNAL);
    AutoRelease<Crypto::SymmetricKeyContext> keyContextOwner(keyContext);

    packetHeader.SetSessionId(keyContext->GetKeyHash());
    CryptoContext cryptoContext(keyContext);

    CryptoContext::NonceStorage nonce;
    ReturnErrorOnFailure(
        CryptoContext::BuildNonce(nonce, packetHeader.GetSecurityFlags(), packetHeader.GetMessageCounter(), nodeId));
    ReturnErrorOnFailure(SecureMessageCodec::Encrypt(cryptoContext, nonce, payloadHeader, packetHeader, msg));

    ReturnErrorOnFailure(packetHeader.EncodeBeforeData(msg));

    // Privacy-encrypt the header fields (mirror SessionManager.cpp:267-313).
    VerifyOrReturnError(msg->TotalLength() == msg->DataLength(), CHIP_ERROR_INVALID_MESSAGE_LENGTH);
    uint8_t * data     = msg->Start();
    size_t len         = msg->TotalLength();
    uint16_t footerLen = packetHeader.MICTagLength();
    VerifyOrReturnError(footerLen <= len, CHIP_ERROR_INTERNAL);

    uint16_t taglen = 0;
    MessageAuthenticationCode mac;
    ReturnErrorOnFailure(mac.Decode(packetHeader, &data[len - footerLen], footerLen, &taglen));
    VerifyOrReturnError(taglen == footerLen, CHIP_ERROR_INTERNAL);

    uint8_t * privacyHeader = packetHeader.PrivacyHeader(msg->Start());
    size_t privacyLength    = packetHeader.PrivacyHeaderLength();
    ReturnErrorOnFailure(cryptoContext.PrivacyEncrypt(privacyHeader, privacyLength, privacyHeader, packetHeader, mac));

    out.assign(msg->Start(), msg->Start() + msg->DataLength());
    return CHIP_NO_ERROR;
}

Fixture & GetFixture()
{
    static std::once_flag once;
    std::call_once(once, [] {
        VerifyOrDie(chip::Platform::MemoryInit() == CHIP_NO_ERROR);

        auto * fx = new Fixture();

        VerifyOrDie(fx->ctx.Init() == CHIP_NO_ERROR);
        VerifyOrDie(fx->opKeyStore.Init(&fx->fabricStorage) == CHIP_NO_ERROR);
        VerifyOrDie(fx->opCertStore.Init(&fx->fabricStorage) == CHIP_NO_ERROR);

        fx->provider.SetStorageDelegate(&fx->providerStorage);
        fx->provider.SetSessionKeystore(&fx->providerKeystore);
        VerifyOrDie(fx->provider.Init() == CHIP_NO_ERROR);
        Credentials::SetGroupDataProvider(&fx->provider);

        FabricTable::InitParams initParams;
        initParams.storage             = &fx->fabricStorage;
        initParams.operationalKeystore = &fx->opKeyStore;
        initParams.opCertStore         = &fx->opCertStore;
        VerifyOrDie(fx->fabricTable.Init(initParams) == CHIP_NO_ERROR);

        VerifyOrDie(fx->sessionManager.Init(&fx->ctx.GetSystemLayer(), &fx->ctx.GetTransportMgr(),
                                            &fx->messageCounterManager, &fx->deviceStorage, &fx->fabricTable,
                                            fx->sessionKeystore) == CHIP_NO_ERROR);
        fx->sessionManager.SetMessageDelegate(&fx->delegate);

        using namespace chip::TestCerts;
        // Distinct roots (A, B) give distinct compressed fabric ids; NodeA2 adds a third fabric
        // under root A (distinct index via IgnoringCollisions). Each add that succeeds is one
        // routable fabric slot. A single fabric is a valid fallback.
        InstallFabric(*fx, 0, GetRootACertAsset(), GetIAA1CertAsset(), GetNodeA1CertAsset());
        InstallFabric(*fx, 1, GetRootBCertAsset(), GetIAB1CertAsset(), GetNodeB1CertAsset());
        InstallFabric(*fx, 2, GetRootACertAsset(), GetIAA1CertAsset(), GetNodeA2CertAsset());
        VerifyOrDie(fx->fabricCount >= 1);

        Inet::IPAddress addr;
        VerifyOrDie(Inet::IPAddress::FromString("::1", addr));
        fx->peer = PeerAddress::UDP(addr, CHIP_PORT);

        gFixture = fx;

        // The IOContext backing `ctx` uses file-static Inet EndPointManagers whose destructors
        // VerifyOrDie unless the layers were shut down. The fixture is intentionally leaked
        // (init once, reuse across inputs), so register a process-exit hook to shut the layers
        // down cleanly; otherwise the run ends in a spurious SIGABRT that reads as a crash.
        std::atexit([] {
            if (gFixture != nullptr)
            {
                gFixture->sessionManager.Shutdown();
                gFixture->ctx.Shutdown();
            }
        });
    });
    return *gFixture;
}

// One fuzzer record: routes a datagram to a fabric slot and picks the attacker-chosen fields.
struct Record
{
    uint8_t fabricSel; // % fabricCount -> which fabric key encrypts the datagram
    uint8_t nodeSel;   // -> nodeId = kNodeBase + nodeSel (forced != kUndefinedNodeId)
    bool isControl;    // control (cap 2) vs data (cap 15) -- see reachability note below
    uint32_t counter;  // does not gate reaching FindOrAddPeer; kept for state variety
};

// Base for attacker node IDs. 256 distinct values (via nodeSel) is enough to over-fill the
// 15/2 caps and force many evictions + MRU re-inserts.
constexpr NodeId kNodeBase = 0x0000000100000000ull;

// Reset gGroupPeerTable to empty so each fuzz input is self-contained and any crash reproduces
// standalone. SessionManager::FabricRemoved is public and clears that fabric's slot.
void ResetPeerTable(Fixture & fx)
{
    for (size_t i = 0; i < fx.fabricCount; i++)
    {
        fx.sessionManager.FabricRemoved(fx.fabricIndices[i]);
    }
}

// Drive a sequence of attacker datagrams through the real entry point, accumulating state in
// gGroupPeerTable. The fuzzer controls the record count and every per-record field.
void GroupPeerTableDoesNotCorrupt(const std::vector<Record> & records)
{
    Fixture & fx = GetFixture();
    ResetPeerTable(fx);

    for (const Record & r : records)
    {
        const size_t slot   = r.fabricSel % fx.fabricCount;
        const NodeId nodeId = kNodeBase + r.nodeSel; // always != kUndefinedNodeId (0)

        std::vector<uint8_t> datagram;
        if (EncodeGroupDatagram(fx, slot, nodeId, r.counter, r.isControl, datagram) != CHIP_NO_ERROR)
        {
            continue;
        }

        PacketBufferHandle msg = MessagePacketBuffer::NewWithData(datagram.data(), datagram.size());
        if (msg.IsNull())
        {
            continue;
        }

        fx.sessionManager.OnMessageReceived(fx.peer, std::move(msg));
    }
}

// Programmatic seeds (record sequences), one per transition the table cares about, so the
// mutator starts with a representative of every fill/evict/re-insert/first-add path.
std::vector<std::vector<Record>> GroupCounterSeeds()
{
    std::vector<std::vector<Record>> seeds;

    auto data = [](uint8_t node) { return Record{ 0, node, false, 1 }; };

    // 1. A single valid data-message record (baseline reach of FindOrAddPeer non-control branch).
    seeds.push_back({ data(1) });

    // 2. A single control-message record (control branch, cap 2). NOTE: control datagrams are
    //    dropped before FindOrAddPeer (see reachability note in README); kept for completeness.
    seeds.push_back({ Record{ 0, 1, true, 1 } });

    // 3. > MAX_GROUP_DATA_PEERS (17) distinct data nodes, one fabric: fill -> evict past cap 15.
    {
        std::vector<Record> s;
        for (uint8_t n = 1; n <= 17; n++)
        {
            s.push_back(data(n));
        }
        seeds.push_back(std::move(s));
    }

    // 4. > MAX_GROUP_CONTROL_PEERS (3) control records (control-cap eviction, if reachable).
    seeds.push_back({ Record{ 0, 1, true, 1 }, Record{ 0, 2, true, 1 }, Record{ 0, 3, true, 1 } });

    // 5. Mix >=2 fabrics: drives the first-add branch for a second mGroupFabrics slot.
    seeds.push_back({ Record{ 0, 1, false, 1 }, Record{ 1, 2, false, 1 }, Record{ 2, 3, false, 1 } });

    // 6. Fill the data cap, then re-send an already-present node id: drives the search-hit
    //    MRU-move ShiftAndInsert(list, i, ...) path.
    {
        std::vector<Record> s;
        for (uint8_t n = 1; n <= 15; n++)
        {
            s.push_back(data(n));
        }
        s.push_back(data(1));  // re-send present node (MRU move)
        s.push_back(data(8));  // re-send present node (MRU move from middle)
        seeds.push_back(std::move(s));
    }

    return seeds;
}

// Record domain: fabricSel/nodeSel/isControl/counter, each field fuzzer-controlled. The fuzzer
// picks the record count (bounded to keep per-input cost low). The 1-byte nodeSel concentrates
// entropy on transition structure rather than ID uniqueness.
auto RecordDomain()
{
    return StructOf<Record>(Arbitrary<uint8_t>(),                       // fabricSel
                            Arbitrary<uint8_t>(),                       // nodeSel
                            Arbitrary<bool>(),                          // isControl
                            Arbitrary<uint32_t>());                     // counter
}

FUZZ_TEST(FuzzSessionManagerGroupCounterPW, GroupPeerTableDoesNotCorrupt)
    .WithDomains(VectorOf(RecordDomain()).WithMaxSize(64).WithSeeds(&GroupCounterSeeds));

} // namespace
