#include <cstddef>
#include <cstdint>
#include <stdarg.h>
#include <string.h>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

#include <app/icd/server/ICDServerConfig.h>
#include <lib/core/CHIPCore.h>
#include <lib/core/CHIPSafeCasts.h>
#include <lib/core/StringBuilderAdapters.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/UnitTestUtils.h>
#include <messaging/tests/MessagingContext.h>
#include <protocols/secure_channel/CASESession.h>
#include <system/TLVPacketBufferBackingStore.h>

// added for supporting classes
#include "credentials/tests/CHIPCert_test_vectors.h"
#include <protocols/secure_channel/CASEServer.h>

#include <credentials/GroupDataProviderImpl.h>

namespace chip {
namespace Testing {

using namespace std;

using namespace Crypto;
using namespace fuzztest;
using namespace Transport;
using namespace Messaging;
using namespace System::Clock::Literals;

using namespace Credentials;
using namespace TestCerts;

using namespace Inet;
using namespace Protocols;

// TODO fuzz?

class TestCASESecurePairingDelegate;

class FuzzLoopbackMessagingContext : public chip::Test::MessagingContext
{
public:
    ~FuzzLoopbackMessagingContext() {}

    // These functions wrap spLoopbackTransportManager methods
    static auto & GetSystemLayer() { return spLoopbackTransportManager->GetSystemLayer(); }
    static auto & GetLoopback() { return spLoopbackTransportManager->GetLoopback(); }
    static auto & GetTransportMgr() { return spLoopbackTransportManager->GetTransportMgr(); }
    static auto & GetIOContext() { return spLoopbackTransportManager->GetIOContext(); }

    template <typename... Ts>
    static void DrainAndServiceIO(Ts... args)
    {
        return spLoopbackTransportManager->DrainAndServiceIO(args...);
    }

    // Performs shared setup for all tests in the test suite
    static void SetUpTestSuite()
    {
        // Initialize memory.
        ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
        // Instantiate the LoopbackTransportManager.
        ASSERT_EQ(spLoopbackTransportManager, nullptr);
        spLoopbackTransportManager = new chip::Test::LoopbackTransportManager();
        ASSERT_NE(spLoopbackTransportManager, nullptr);
        // Initialize the LoopbackTransportManager.
        ASSERT_EQ(spLoopbackTransportManager->Init(), CHIP_NO_ERROR);
    }

    // Performs shared teardown for all tests in the test suite
    static void TearDownTestSuite()
    {
        // Shutdown the LoopbackTransportManager.
        spLoopbackTransportManager->Shutdown();
        // Destroy the LoopbackTransportManager.
        if (spLoopbackTransportManager != nullptr)
        {
            delete spLoopbackTransportManager;
            spLoopbackTransportManager = nullptr;
        }
        // Shutdown memory.
        chip::Platform::MemoryShutdown();
    }

    // Performs setup for each individual test in the test suite
    void SetUp() { ASSERT_EQ(MessagingContext::Init(&GetTransportMgr(), &GetIOContext()), CHIP_NO_ERROR); }

    // Performs teardown for each individual test in the test suite
    void TearDown() { MessagingContext::Shutdown(); }

    static chip::Test::LoopbackTransportManager * spLoopbackTransportManager;
};
chip::Test::LoopbackTransportManager * FuzzLoopbackMessagingContext::spLoopbackTransportManager = nullptr;

class FuzzCASESession : public FuzzLoopbackMessagingContext
{
public:
    FuzzCASESession()
    {
        ConfigInitializeNodes(false);
        SetUpTestSuite();

        // SetUp()
        FuzzLoopbackMessagingContext::SetUp();
    }
    ~FuzzCASESession()
    {
        FuzzLoopbackMessagingContext::TearDown();
        TearDownTestSuite();
    }

    void SetUpTestSuite();
    void TearDownTestSuite();

    void ServiceEvents();
    void SecurePairingHandshakeTestCommon(SessionManager & sessionManager, CASESession & pairingCommissioner,
                                          TestCASESecurePairingDelegate & delegateCommissioner);

    void SimulateUpdateNOCInvalidatePendingEstablishment();

    System::PacketBufferHandle GenerateSigma1(const vector<uint8_t> & InitiatorRandom, uint32_t fuzzInitiatorSessionId,
                                              FabricId fuzzedFabricId, const vector<uint8_t> & IPK,
                                              const vector<uint8_t> & rootPubKey);
    void HandleSigma1(const vector<uint8_t> & InitiatorRandom, uint32_t fuzzInitiatorSessionId, FabricId fuzzedFabricId,
                      const vector<uint8_t> & IPK, const vector<uint8_t> & rootPubKey);

    void ParseSigma1(const vector<uint8_t> & InitiatorRandom, uint32_t fuzzInitiatorSessionId, FabricId fuzzedFabricId,
                     const vector<uint8_t> & IPK, const vector<uint8_t> & rootPubKey);
};

void FuzzCASESession::ServiceEvents()
{
    // Takes a few rounds of this because handling IO messages may schedule work,
    // and scheduled work may queue messages for sending...
    for (int i = 0; i < 3; ++i)
    {
        DrainAndServiceIO();

        chip::DeviceLayer::PlatformMgr().ScheduleWork(
            [](intptr_t) -> void { chip::DeviceLayer::PlatformMgr().StopEventLoopTask(); }, (intptr_t) nullptr);
        chip::DeviceLayer::PlatformMgr().RunEventLoop();
    }
}

class TemporarySessionManager
{
public:
    TemporarySessionManager(FuzzCASESession & ctx) : mCtx(ctx)
    {
        EXPECT_EQ(CHIP_NO_ERROR,
                  mSessionManager.Init(&ctx.GetSystemLayer(), &ctx.GetTransportMgr(), &ctx.GetMessageCounterManager(), &mStorage,
                                       &ctx.GetFabricTable(), ctx.GetSessionKeystore()));
        // The setup here is really weird: we are using one session manager for
        // the actual messages we send (the PASE handshake, so the
        // unauthenticated sessions) and a different one for allocating the PASE
        // sessions.  Since our Init() set us up as the thing to handle messages
        // on the transport manager, undo that.
        mCtx.GetTransportMgr().SetSessionManager(&mCtx.GetSecureSessionManager());
    }

    ~TemporarySessionManager()
    {
        mSessionManager.Shutdown();
        // Reset the session manager on the transport again, just in case
        // shutdown messed with it.
        mCtx.GetTransportMgr().SetSessionManager(&mCtx.GetSecureSessionManager());
    }

    operator SessionManager &() { return mSessionManager; }

private:
    FuzzCASESession & mCtx;
    TestPersistentStorageDelegate mStorage;
    SessionManager mSessionManager;
};

CHIP_ERROR InitFabricTable(chip::FabricTable & fabricTable, chip::TestPersistentStorageDelegate * testStorage,
                           chip::Crypto::OperationalKeystore * opKeyStore,
                           chip::Credentials::PersistentStorageOpCertStore * opCertStore)
{
    ReturnErrorOnFailure(opCertStore->Init(testStorage));

    chip::FabricTable::InitParams initParams;
    initParams.storage             = testStorage;
    initParams.operationalKeystore = opKeyStore;
    initParams.opCertStore         = opCertStore;

    return fabricTable.Init(initParams);
}

class TestCASESecurePairingDelegate : public SessionEstablishmentDelegate
{
public:
    void OnSessionEstablishmentError(CHIP_ERROR error) override
    {
        mNumPairingErrors++;
        if (error == CHIP_ERROR_BUSY)
        {
            mNumBusyResponses++;
        }
    }

    void OnSessionEstablished(const SessionHandle & session) override
    {
        mSession.Grab(session);
        mNumPairingComplete++;
    }

    SessionHolder & GetSessionHolder() { return mSession; }

    SessionHolder mSession;

    // TODO: Rename mNumPairing* to mNumEstablishment*
    uint32_t mNumPairingErrors   = 0;
    uint32_t mNumPairingComplete = 0;
    uint32_t mNumBusyResponses   = 0;
};

class TestOperationalKeystore : public chip::Crypto::OperationalKeystore
{
public:
    void Init(FabricIndex fabricIndex, Platform::UniquePtr<P256Keypair> keypair)
    {
        mSingleFabricIndex = fabricIndex;
        mKeypair           = std::move(keypair);
    }
    void Shutdown()
    {
        mSingleFabricIndex = kUndefinedFabricIndex;
        mKeypair           = nullptr;
    }

    bool HasPendingOpKeypair() const override { return false; }
    bool HasOpKeypairForFabric(FabricIndex fabricIndex) const override { return mSingleFabricIndex != kUndefinedFabricIndex; }

    CHIP_ERROR NewOpKeypairForFabric(FabricIndex fabricIndex, MutableByteSpan & outCertificateSigningRequest) override
    {
        return CHIP_ERROR_NOT_IMPLEMENTED;
    }

    CHIP_ERROR ActivateOpKeypairForFabric(FabricIndex fabricIndex, const Crypto::P256PublicKey & nocPublicKey) override
    {
        return CHIP_NO_ERROR;
    }

    CHIP_ERROR CommitOpKeypairForFabric(FabricIndex fabricIndex) override { return CHIP_ERROR_NOT_IMPLEMENTED; }
    CHIP_ERROR RemoveOpKeypairForFabric(FabricIndex fabricIndex) override { return CHIP_ERROR_NOT_IMPLEMENTED; }

    void RevertPendingKeypair() override {}

    CHIP_ERROR SignWithOpKeypair(FabricIndex fabricIndex, const ByteSpan & message,
                                 Crypto::P256ECDSASignature & outSignature) const override
    {
        VerifyOrReturnError(mKeypair != nullptr, CHIP_ERROR_INCORRECT_STATE);
        VerifyOrReturnError(fabricIndex == mSingleFabricIndex, CHIP_ERROR_INVALID_FABRIC_INDEX);
        return mKeypair->ECDSA_sign_msg(message.data(), message.size(), outSignature);
    }

    Crypto::P256Keypair * AllocateEphemeralKeypairForCASE() override { return Platform::New<Crypto::P256Keypair>(); }

    void ReleaseEphemeralKeypair(Crypto::P256Keypair * keypair) override { Platform::Delete<Crypto::P256Keypair>(keypair); }

protected:
    Platform::UniquePtr<P256Keypair> mKeypair;
    FabricIndex mSingleFabricIndex = kUndefinedFabricIndex;
};

#if CHIP_CONFIG_SLOW_CRYPTO
constexpr uint32_t sTestCaseMessageCount           = 8;
constexpr uint32_t sTestCaseResumptionMessageCount = 6;
#else  // CHIP_CONFIG_SLOW_CRYPTO
constexpr uint32_t sTestCaseMessageCount           = 5;
constexpr uint32_t sTestCaseResumptionMessageCount = 4;
#endif // CHIP_CONFIG_SLOW_CRYPTO

FabricTable gCommissionerFabrics;
FabricIndex gCommissionerFabricIndex;
GroupDataProviderImpl gCommissionerGroupDataProvider;
TestPersistentStorageDelegate gCommissionerStorageDelegate;
Crypto::DefaultSessionKeystore gCommissionerSessionKeystore;

Credentials::PersistentStorageOpCertStore gCommissionerOpCertStore;

FabricTable gDeviceFabrics;
FabricIndex gDeviceFabricIndex;
GroupDataProviderImpl gDeviceGroupDataProvider;
TestPersistentStorageDelegate gDeviceStorageDelegate;
TestOperationalKeystore gDeviceOperationalKeystore;
Crypto::DefaultSessionKeystore gDeviceSessionKeystore;

Credentials::PersistentStorageOpCertStore gDeviceOpCertStore;

CASEServer gPairingServer;

NodeId Node01_01 = 0xDEDEDEDE00010001;
NodeId Node01_02 = 0xDEDEDEDE00010002;

CHIP_ERROR InitTestIpk(GroupDataProvider & groupDataProvider, const FabricInfo & fabricInfo, size_t numIpks)
{
    VerifyOrReturnError((numIpks > 0) && (numIpks <= 3), CHIP_ERROR_INVALID_ARGUMENT);
    using KeySet         = chip::Credentials::GroupDataProvider::KeySet;
    using SecurityPolicy = chip::Credentials::GroupDataProvider::SecurityPolicy;

    KeySet ipkKeySet(GroupDataProvider::kIdentityProtectionKeySetId, SecurityPolicy::kTrustFirst, static_cast<uint8_t>(numIpks));

    for (size_t ipkIndex = 0; ipkIndex < numIpks; ++ipkIndex)
    {
        // Set start time to 0, 1000, 2000, etc
        ipkKeySet.epoch_keys[ipkIndex].start_time = static_cast<uint64_t>(ipkIndex * 1000);
        // Set IPK Epoch key to 00.....00, 01....01, 02.....02, etc
        memset(&ipkKeySet.epoch_keys[ipkIndex].key, static_cast<int>(ipkIndex), sizeof(ipkKeySet.epoch_keys[ipkIndex].key));
    }

    uint8_t compressedId[sizeof(uint64_t)];
    MutableByteSpan compressedIdSpan(compressedId);
    ReturnErrorOnFailure(fabricInfo.GetCompressedFabricIdBytes(compressedIdSpan));
    return groupDataProvider.SetKeySet(fabricInfo.GetFabricIndex(), compressedIdSpan, ipkKeySet);
}

CHIP_ERROR InitCredentialSets()
{
    gCommissionerStorageDelegate.ClearStorage();
    gCommissionerGroupDataProvider.SetStorageDelegate(&gCommissionerStorageDelegate);
    gCommissionerGroupDataProvider.SetSessionKeystore(&gCommissionerSessionKeystore);
    ReturnErrorOnFailure(gCommissionerGroupDataProvider.Init());

    FabricInfo commissionerFabric;
    {
        P256SerializedKeypair opKeysSerialized;

        // TODO: Rename gCommissioner* to gInitiator*
        memcpy(opKeysSerialized.Bytes(), sTestCert_Node01_02_PublicKey.data(), sTestCert_Node01_02_PublicKey.size());
        memcpy(opKeysSerialized.Bytes() + sTestCert_Node01_02_PublicKey.size(), sTestCert_Node01_02_PrivateKey.data(),
               sTestCert_Node01_02_PrivateKey.size());

        ReturnErrorOnFailure(
            opKeysSerialized.SetLength(sTestCert_Node01_02_PublicKey.size() + sTestCert_Node01_02_PrivateKey.size()));

        chip::ByteSpan rcacSpan(sTestCert_Root01_Chip);
        chip::ByteSpan icacSpan(sTestCert_ICA01_Chip);
        chip::ByteSpan nocSpan(sTestCert_Node01_02_Chip);
        chip::ByteSpan opKeySpan(opKeysSerialized.ConstBytes(), opKeysSerialized.Length());

        ReturnErrorOnFailure(
            gCommissionerFabrics.AddNewFabricForTest(rcacSpan, icacSpan, nocSpan, opKeySpan, &gCommissionerFabricIndex));
    }

    const FabricInfo * newFabric = gCommissionerFabrics.FindFabricWithIndex(gCommissionerFabricIndex);
    VerifyOrReturnError(newFabric != nullptr, CHIP_ERROR_INTERNAL);
    ReturnErrorOnFailure(InitTestIpk(gCommissionerGroupDataProvider, *newFabric, /* numIpks= */ 1));

    gDeviceStorageDelegate.ClearStorage();
    gDeviceGroupDataProvider.SetStorageDelegate(&gDeviceStorageDelegate);
    gDeviceGroupDataProvider.SetSessionKeystore(&gDeviceSessionKeystore);
    ReturnErrorOnFailure(gDeviceGroupDataProvider.Init());
    FabricInfo deviceFabric;

    {
        P256SerializedKeypair opKeysSerialized;

        auto deviceOpKey = Platform::MakeUnique<Crypto::P256Keypair>();
        memcpy(opKeysSerialized.Bytes(), sTestCert_Node01_01_PublicKey.data(), sTestCert_Node01_01_PublicKey.size());
        memcpy(opKeysSerialized.Bytes() + sTestCert_Node01_01_PublicKey.size(), sTestCert_Node01_01_PrivateKey.data(),
               sTestCert_Node01_01_PrivateKey.size());

        ReturnErrorOnFailure(
            opKeysSerialized.SetLength(sTestCert_Node01_01_PublicKey.size() + sTestCert_Node01_01_PrivateKey.size()));

        ReturnErrorOnFailure(deviceOpKey->Deserialize(opKeysSerialized));

        // Use an injected operational key for device
        gDeviceOperationalKeystore.Init(1, std::move(deviceOpKey));

        ReturnErrorOnFailure(
            InitFabricTable(gDeviceFabrics, &gDeviceStorageDelegate, &gDeviceOperationalKeystore, &gDeviceOpCertStore));

        chip::ByteSpan rcacSpan(sTestCert_Root01_Chip);
        chip::ByteSpan icacSpan(sTestCert_ICA01_Chip);
        chip::ByteSpan nocSpan(sTestCert_Node01_01_Chip);

        ReturnErrorOnFailure(gDeviceFabrics.AddNewFabricForTest(rcacSpan, icacSpan, nocSpan, ByteSpan{}, &gDeviceFabricIndex));
    }

    // TODO: Validate more cases of number of IPKs on both sides
    newFabric = gDeviceFabrics.FindFabricWithIndex(gDeviceFabricIndex);
    VerifyOrReturnError(newFabric != nullptr, CHIP_ERROR_INTERNAL);
    ReturnErrorOnFailure(InitTestIpk(gDeviceGroupDataProvider, *newFabric, /* numIpks= */ 1));

    return CHIP_NO_ERROR;
}

void FuzzCASESession::SetUpTestSuite()
{
    FuzzLoopbackMessagingContext::SetUpTestSuite();

    ASSERT_EQ(chip::DeviceLayer::PlatformMgr().InitChipStack(), CHIP_NO_ERROR);

    ASSERT_EQ(
        InitFabricTable(gCommissionerFabrics, &gCommissionerStorageDelegate, /* opKeyStore = */ nullptr, &gCommissionerOpCertStore),
        CHIP_NO_ERROR);

    ASSERT_EQ(InitCredentialSets(), CHIP_NO_ERROR);

    chip::DeviceLayer::SetSystemLayerForTesting(&GetSystemLayer());
}
void FuzzCASESession::TearDownTestSuite()
{
    chip::DeviceLayer::SetSystemLayerForTesting(nullptr);
    gDeviceOperationalKeystore.Shutdown();
    gPairingServer.Shutdown();
    gCommissionerStorageDelegate.ClearStorage();
    gDeviceStorageDelegate.ClearStorage();
    // TODO: Amine Added this, to make PersistentStorageOpCertStore.mStorage = nullptr for both Device and Commissioner
    // We need to Finalize the certificate store, to be able to Initialise it again in Subsequent Fuzzing iterations
    gDeviceOpCertStore.Finish();
    gCommissionerOpCertStore.Finish();

    gCommissionerFabrics.DeleteAllFabrics();
    gDeviceFabrics.DeleteAllFabrics();
    chip::DeviceLayer::PlatformMgr().Shutdown();
    FuzzLoopbackMessagingContext::TearDownTestSuite();
}

/*******************************************************************************************************************************************************************************
******************************************************************************************************
**************************** */

void FuzzCASESession::SecurePairingHandshakeTestCommon(SessionManager & sessionManager, CASESession & pairingCommissioner,
                                                       TestCASESecurePairingDelegate & delegateCommissioner)
{
    // Test all combinations of invalid parameters
    TestCASESecurePairingDelegate delegateAccessory;
    CASESession pairingAccessory;
    ReliableMessageProtocolConfig verySleepyAccessoryRmpConfig(
        System::Clock::Milliseconds32(360000), System::Clock::Milliseconds32(100000), System::Clock::Milliseconds16(300));
    ReliableMessageProtocolConfig nonSleepyCommissionerRmpConfig(
        System::Clock::Milliseconds32(5000), System::Clock::Milliseconds32(300), System::Clock::Milliseconds16(4000));

    auto & loopback            = GetLoopback();
    loopback.mSentMessageCount = 0;

    EXPECT_EQ(GetExchangeManager().RegisterUnsolicitedMessageHandlerForType(Protocols::SecureChannel::MsgType::CASE_Sigma1,
                                                                            &pairingAccessory),
              CHIP_NO_ERROR);

    ExchangeContext * contextCommissioner = NewUnauthenticatedExchangeToBob(&pairingCommissioner);

    pairingAccessory.SetGroupDataProvider(&gDeviceGroupDataProvider);
    EXPECT_EQ(pairingAccessory.PrepareForSessionEstablishment(sessionManager, &gDeviceFabrics, nullptr, nullptr, &delegateAccessory,
                                                              ScopedNodeId(), MakeOptional(verySleepyAccessoryRmpConfig)),
              CHIP_NO_ERROR);
    EXPECT_EQ(pairingCommissioner.EstablishSession(
                  sessionManager, &gCommissionerFabrics, ScopedNodeId{ Node01_01, gCommissionerFabricIndex }, contextCommissioner,
                  nullptr, nullptr, &delegateCommissioner, MakeOptional(nonSleepyCommissionerRmpConfig)),
              CHIP_NO_ERROR);
    ServiceEvents();

    EXPECT_EQ(loopback.mSentMessageCount, sTestCaseMessageCount);
    EXPECT_EQ(delegateAccessory.mNumPairingComplete, 1u);
    EXPECT_EQ(delegateCommissioner.mNumPairingComplete, 1u);
    EXPECT_EQ(delegateAccessory.mNumPairingErrors, 0u);
    EXPECT_EQ(delegateCommissioner.mNumPairingErrors, 0u);
    EXPECT_EQ(pairingAccessory.GetRemoteMRPConfig().mIdleRetransTimeout, System::Clock::Milliseconds32(5000));
    EXPECT_EQ(pairingAccessory.GetRemoteMRPConfig().mActiveRetransTimeout, System::Clock::Milliseconds32(300));
    EXPECT_EQ(pairingAccessory.GetRemoteMRPConfig().mActiveThresholdTime, System::Clock::Milliseconds16(4000));
    EXPECT_EQ(pairingCommissioner.GetRemoteMRPConfig().mIdleRetransTimeout, System::Clock::Milliseconds32(360000));
    EXPECT_EQ(pairingCommissioner.GetRemoteMRPConfig().mActiveRetransTimeout, System::Clock::Milliseconds32(100000));
    EXPECT_EQ(pairingCommissioner.GetRemoteMRPConfig().mActiveThresholdTime, System::Clock::Milliseconds16(300));
#if CONFIG_BUILD_FOR_HOST_UNIT_TEST
    // Confirming that FabricTable sending a notification that fabric was updated doesn't affect
    // already established connections.
    //
    // This is compiled for host tests which is enough test coverage
    gCommissionerFabrics.SendUpdateFabricNotificationForTest(gCommissionerFabricIndex);
    gDeviceFabrics.SendUpdateFabricNotificationForTest(gDeviceFabricIndex);
    EXPECT_EQ(loopback.mSentMessageCount, sTestCaseMessageCount);
    EXPECT_EQ(delegateAccessory.mNumPairingComplete, 1u);
    EXPECT_EQ(delegateCommissioner.mNumPairingComplete, 1u);
    EXPECT_EQ(delegateAccessory.mNumPairingErrors, 0u);
    EXPECT_EQ(delegateCommissioner.mNumPairingErrors, 0u);
#endif // CONFIG_BUILD_FOR_HOST_UNIT_TEST
}

void SecurePairingHandshake(const vector<uint8_t> & InitiatorRandom, uint32_t fuzzInitiatorSessionId, FabricId fuzzedFabricId,
                            const vector<uint8_t> & IPK, const vector<uint8_t> & rootPubKey)
{
    FuzzCASESession CASE;

    TemporarySessionManager sessionManager(CASE);
    TestCASESecurePairingDelegate delegateCommissioner;
    CASESession pairingCommissioner;
    pairingCommissioner.SetGroupDataProvider(&gCommissionerGroupDataProvider);
    CASE.SecurePairingHandshakeTestCommon(sessionManager, pairingCommissioner, delegateCommissioner);
}

FUZZ_TEST(FuzzCASE_PW, SecurePairingHandshake)
    .WithDomains(
        // InitiatorRandom (Original size = kSigmaParamRandomNumberSize)
        Arbitrary<vector<uint8_t>>().WithSize(kSigmaParamRandomNumberSize),
        // fuzzInitiatorSessionId
        Arbitrary<uint32_t>(),
        // FabricId
        Arbitrary<FabricId>(),
        // fuzzIPK, (Original size = CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES)
        Arbitrary<vector<uint8_t>>().WithSize(CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES),
        // rootPubKey (Original size = kP256_PublicKey_Length)
        Arbitrary<vector<uint8_t>>().WithSize(kP256_PublicKey_Length));

/*******************************************************************************************************************************************************************************
******************************************************************************************************
**************************** */

/*------------------------------------------------------------------------------------------------------------------------------------*/
// In This Test we start by constructing a Fuzzed Pake3 Message, by fuzzing the payload cA. The Fuzzed message is then injected into
// a PASE Session to test the behavior of PASESession::HandleMsg3(); which will be called by the Accessory/Commissionee.
void FuzzCASESession::HandleSigma1(const vector<uint8_t> & InitiatorRandom, uint32_t fuzzInitiatorSessionId,
                                   FabricId fuzzedFabricId, const vector<uint8_t> & IPK, const vector<uint8_t> & rootPubKey)
{

    ByteSpan fuzzInitiatorRandom(InitiatorRandom.data(), InitiatorRandom.size());
    ByteSpan fuzzedIPK(IPK.data(), IPK.size());
    ByteSpan fuzzedRootPubKey(rootPubKey.data(), rootPubKey.size());
    // Construct Sigma1
    size_t data_len = TLV::EstimateStructOverhead(fuzzInitiatorRandom.size(),           // initiatorRandom
                                                  sizeof(fuzzInitiatorSessionId),       // initiatorSessionId,
                                                  kSHA256_Hash_Length,                  // destinationId
                                                  kP256_PublicKey_Length,               // InitiatorEphPubKey,
                                                  SessionParameters::kEstimatedTLVSize, // initiatorSessionParams
                                                  SessionResumptionStorage::kResumptionIdSize, CHIP_CRYPTO_AEAD_MIC_LENGTH_BYTES);

    System::PacketBufferTLVWriter tlvWriter;
    System::PacketBufferHandle msg_R1;
    TLV::TLVType outerContainerType                    = TLV::kTLVType_NotSpecified;
    uint8_t destinationIdentifier[kSHA256_Hash_Length] = { 0 };

    // Validate that we have a session ID allocated.
    // VerifyOrReturnError(GetLocalSessionId().HasValue(), CHIP_ERROR_INCORRECT_STATE);

    // Generate an ephemeral keypair
    // in TestCASESession, this is done in TestOperationalKeystore::AllocateEphemeralKeypairForCASE
    Crypto::P256Keypair * EphemeralKey = Platform::New<Crypto::P256Keypair>();

    EXPECT_EQ(CHIP_NO_ERROR, EphemeralKey->Initialize(ECPKeyTarget::ECDH));

    // Construct Sigma1 Msg
    msg_R1 = System::PacketBufferHandle::New(data_len);
    EXPECT_FALSE(msg_R1.IsNull());

    tlvWriter.Init(std::move(msg_R1));
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.StartContainer(TLV::AnonymousTag(), TLV::kTLVType_Structure, outerContainerType));
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Put(TLV::ContextTag(1), fuzzInitiatorRandom));

    // Session Identifier, in Spec it is uint16_t
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Put(TLV::ContextTag(2), fuzzInitiatorSessionId));

    // Generate a Destination Identifier based on the node we are attempting to reach
    {
        // Obtain originator IPK matching the fabric where we are trying to open a session. mIPK
        // will be properly set thereafter.
        //   EXPECT_EQ(CHIP_NO_ERROR, RecoverInitiatorIpk());
        // TODO fuzz?
        FabricIndex zz = 44;

        MutableByteSpan destinationIdSpan(destinationIdentifier);
        EXPECT_EQ(CHIP_NO_ERROR,
                  GenerateCaseDestinationId(fuzzedIPK, fuzzInitiatorRandom, fuzzedRootPubKey, fuzzedFabricId, Node01_01,
                                            destinationIdSpan));
    }
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.PutBytes(TLV::ContextTag(3), destinationIdentifier, sizeof(destinationIdentifier)));

    EXPECT_EQ(
        CHIP_NO_ERROR,
        tlvWriter.PutBytes(TLV::ContextTag(4), EphemeralKey->Pubkey(), static_cast<uint32_t>(EphemeralKey->Pubkey().Length())));

    ReliableMessageProtocolConfig LocalMRPConfig(System::Clock::Milliseconds32(100), System::Clock::Milliseconds32(200),
                                                 System::Clock::Milliseconds16(4000));

    EXPECT_EQ(CHIP_NO_ERROR, CASESession::EncodeSessionParameters(TLV::ContextTag(5), LocalMRPConfig, tlvWriter));

    /*--------------------This is for mSessionResumptionStorage--------------------------*/
    // // Try to find persistent session, and resume it.
    // bool resuming = false;
    // if (mSessionResumptionStorage != nullptr)
    // {
    //     CHIP_ERROR err = mSessionResumptionStorage->FindByScopedNodeId(fabricInfo->GetScopedNodeIdForNode(mPeerNodeId),
    //                                                                    mResumeResumptionId, mSharedSecret, mPeerCATs);
    //     if (err == CHIP_NO_ERROR)
    //     {
    //         // Found valid resumption state, try to resume the session.
    //         EXPECT_EQ(CHIP_NO_ERROR,tlvWriter.Put(TLV::ContextTag(6), mResumeResumptionId));

    //         uint8_t initiatorResume1MIC[CHIP_CRYPTO_AEAD_MIC_LENGTH_BYTES];
    //         MutableByteSpan resumeMICSpan(initiatorResume1MIC);
    //         EXPECT_EQ(CHIP_NO_ERROR,GenerateSigmaResumeMIC(ByteSpan(mInitiatorRandom), ByteSpan(mResumeResumptionId),
    //                                                     ByteSpan(kKDFS1RKeyInfo), ByteSpan(kResume1MIC_Nonce), resumeMICSpan));

    //         EXPECT_EQ(CHIP_NO_ERROR,tlvWriter.Put(TLV::ContextTag(7), resumeMICSpan));
    //         resuming = true;
    //     }
    // }
    /*----------------------------------------------------------------------------------------*/

    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.EndContainer(outerContainerType));
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Finalize(&msg_R1));

    Hash_SHA256_stream CommissioningHash;
    CommissioningHash.Begin();
    EXPECT_EQ(CHIP_NO_ERROR, CommissioningHash.AddData(ByteSpan{ msg_R1->Start(), msg_R1->DataLength() }));

    CASESession pairingAccessory;

    // I need to add this, because A failure will automatically send a Status Report (which needs context). However to Add Exchange
    // Context, I need to inherit Loopback
    // ExchangeContext * contextAccessory = NewUnauthenticatedExchangeToBob(&pairingAccessory);

    pairingAccessory.mCommissioningHash.Begin();

    // TODO: I am facing Failures here because I need an exchange Context, to have an Exchange Context, I need to have networking
    // and all. For the moment I am testing another implmentation BELOW
    //   pairingAccessory.HandleSigma1(std::move(msg_R1));

    EphemeralKey->Clear();
}

void HandleSigma1(const vector<uint8_t> & InitiatorRandom, uint32_t fuzzInitiatorSessionId, FabricId fuzzedFabricId,
                  const vector<uint8_t> & IPK, const vector<uint8_t> & rootPubKey)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);

    FuzzCASESession CaseSession;
    CaseSession.HandleSigma1(InitiatorRandom, fuzzInitiatorSessionId, fuzzedFabricId, IPK, rootPubKey);
    chip::Platform::MemoryShutdown();
}

FUZZ_TEST(FuzzCASE_PW, HandleSigma1)
    .WithDomains(
        // InitiatorRandom (Original size = kSigmaParamRandomNumberSize)
        Arbitrary<vector<uint8_t>>().WithSize(kSigmaParamRandomNumberSize),
        // fuzzInitiatorSessionId
        Arbitrary<uint32_t>(),
        // FabricId
        Arbitrary<FabricId>(),
        // fuzzIPK, (Original size = CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES)
        Arbitrary<vector<uint8_t>>().WithSize(CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES),
        // rootPubKey (Original size = kP256_PublicKey_Length)
        Arbitrary<vector<uint8_t>>().WithSize(kP256_PublicKey_Length));

System::PacketBufferHandle FuzzCASESession::GenerateSigma1(const vector<uint8_t> & InitiatorRandom, uint32_t fuzzInitiatorSessionId,
                                                           FabricId fuzzedFabricId, const vector<uint8_t> & IPK,
                                                           const vector<uint8_t> & rootPubKey)

{
    ByteSpan fuzzInitiatorRandom(InitiatorRandom.data(), InitiatorRandom.size());
    ByteSpan fuzzedIPK(IPK.data(), IPK.size());
    ByteSpan fuzzedRootPubKey(rootPubKey.data(), rootPubKey.size());
    // Construct Sigma1
    size_t data_len = TLV::EstimateStructOverhead(fuzzInitiatorRandom.size(),           // initiatorRandom
                                                  sizeof(fuzzInitiatorSessionId),       // initiatorSessionId,
                                                  kSHA256_Hash_Length,                  // destinationId
                                                  kP256_PublicKey_Length,               // InitiatorEphPubKey,
                                                  SessionParameters::kEstimatedTLVSize, // initiatorSessionParams
                                                  SessionResumptionStorage::kResumptionIdSize, CHIP_CRYPTO_AEAD_MIC_LENGTH_BYTES);

    System::PacketBufferTLVWriter tlvWriter;
    System::PacketBufferHandle msg_R1;
    TLV::TLVType outerContainerType                    = TLV::kTLVType_NotSpecified;
    uint8_t destinationIdentifier[kSHA256_Hash_Length] = { 0 };

    // Validate that we have a session ID allocated.
    // VerifyOrReturnError(GetLocalSessionId().HasValue(), CHIP_ERROR_INCORRECT_STATE);

    // Generate an ephemeral keypair
    // in TestCASESession, this is done in TestOperationalKeystore::AllocateEphemeralKeypairForCASE
    Crypto::P256Keypair * EphemeralKey = Platform::New<Crypto::P256Keypair>();

    EXPECT_EQ(CHIP_NO_ERROR, EphemeralKey->Initialize(ECPKeyTarget::ECDH));

    // Construct Sigma1 Msg
    msg_R1 = System::PacketBufferHandle::New(data_len);
    EXPECT_FALSE(msg_R1.IsNull());

    tlvWriter.Init(std::move(msg_R1));
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.StartContainer(TLV::AnonymousTag(), TLV::kTLVType_Structure, outerContainerType));
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Put(TLV::ContextTag(1), fuzzInitiatorRandom));

    // Session Identifier, in Spec it is uint16_t
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Put(TLV::ContextTag(2), fuzzInitiatorSessionId));

    // Generate a Destination Identifier based on the node we are attempting to reach
    {
        // Obtain originator IPK matching the fabric where we are trying to open a session. mIPK
        // will be properly set thereafter.
        //   EXPECT_EQ(CHIP_NO_ERROR, RecoverInitiatorIpk());
        // TODO fuzz?
        FabricIndex zz = 44;

        MutableByteSpan destinationIdSpan(destinationIdentifier);
        EXPECT_EQ(CHIP_NO_ERROR,
                  GenerateCaseDestinationId(fuzzedIPK, fuzzInitiatorRandom, fuzzedRootPubKey, fuzzedFabricId, Node01_01,
                                            destinationIdSpan));
    }
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.PutBytes(TLV::ContextTag(3), destinationIdentifier, sizeof(destinationIdentifier)));

    EXPECT_EQ(
        CHIP_NO_ERROR,
        tlvWriter.PutBytes(TLV::ContextTag(4), EphemeralKey->Pubkey(), static_cast<uint32_t>(EphemeralKey->Pubkey().Length())));

    ReliableMessageProtocolConfig LocalMRPConfig(System::Clock::Milliseconds32(100), System::Clock::Milliseconds32(200),
                                                 System::Clock::Milliseconds16(4000));

    EXPECT_EQ(CHIP_NO_ERROR, CASESession::EncodeSessionParameters(TLV::ContextTag(5), LocalMRPConfig, tlvWriter));

    /*--------------------This is for mSessionResumptionStorage--------------------------*/
    // // Try to find persistent session, and resume it.
    // bool resuming = false;
    // if (mSessionResumptionStorage != nullptr)
    // {
    //     CHIP_ERROR err = mSessionResumptionStorage->FindByScopedNodeId(fabricInfo->GetScopedNodeIdForNode(mPeerNodeId),
    //                                                                    mResumeResumptionId, mSharedSecret, mPeerCATs);
    //     if (err == CHIP_NO_ERROR)
    //     {
    //         // Found valid resumption state, try to resume the session.
    //         EXPECT_EQ(CHIP_NO_ERROR,tlvWriter.Put(TLV::ContextTag(6), mResumeResumptionId));

    //         uint8_t initiatorResume1MIC[CHIP_CRYPTO_AEAD_MIC_LENGTH_BYTES];
    //         MutableByteSpan resumeMICSpan(initiatorResume1MIC);
    //         EXPECT_EQ(CHIP_NO_ERROR,GenerateSigmaResumeMIC(ByteSpan(mInitiatorRandom), ByteSpan(mResumeResumptionId),
    //                                                     ByteSpan(kKDFS1RKeyInfo), ByteSpan(kResume1MIC_Nonce), resumeMICSpan));

    //         EXPECT_EQ(CHIP_NO_ERROR,tlvWriter.Put(TLV::ContextTag(7), resumeMICSpan));
    //         resuming = true;
    //     }
    // }
    /*----------------------------------------------------------------------------------------*/

    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.EndContainer(outerContainerType));
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Finalize(&msg_R1));

    EphemeralKey->Clear();

    return msg_R1;
}

void FuzzCASESession::ParseSigma1(const vector<uint8_t> & InitiatorRandom, uint32_t fuzzInitiatorSessionId, FabricId fuzzedFabricId,
                                  const vector<uint8_t> & IPK, const vector<uint8_t> & rootPubKey)
{

    /*CONSTRUCT SIGMA1*/
    System::PacketBufferHandle msg = GenerateSigma1(InitiatorRandom, fuzzInitiatorSessionId, fuzzedFabricId, IPK, rootPubKey);

    System::PacketBufferTLVReader tlvReader;

    tlvReader.Init(std::move(msg));

    uint16_t initiatorSessionId;
    ByteSpan destinationIdentifier;
    ByteSpan initiatorRandom;

    bool sessionResumptionRequested = false;
    ByteSpan resumptionId;
    ByteSpan resume1MIC;
    ByteSpan initiatorPubKey;

    CASESession pairingAccessory;

    // TODO: PARSERSIGMA1 NEEDS TO HAVE an EXCHANGE CONTEXT and to have an exchange context we need to have loopbackmessaging (or
    // sessions and other stuff)
    // TODO: SO LIEK THIS, I WILL GET A VERIFYORDIE RELATED TO MISSSING CONTEXT

    //  ExchangeContext * contextAccessory = NewUnauthenticatedExchangeToBob(&pairingAccessory);

    // pairingAccessory.mExchangeCtxt.Emplace(*contextAccessory);
    // TODO: reactivate ParseSigma1 when no more ASAN error
    //     pairingAccessory.ParseSigma1(tlvReader, initiatorRandom, initiatorSessionId, destinationIdentifier, initiatorPubKey,
    //                                  sessionResumptionRequested, resumptionId, resume1MIC);
}

void ParseSigma1(const vector<uint8_t> & InitiatorRandom, uint32_t fuzzInitiatorSessionId, FabricId fuzzedFabricId,
                 const vector<uint8_t> & IPK, const vector<uint8_t> & rootPubKey)
{

    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    FuzzCASESession CaseSession;
    // CaseSession.GenerateSigma1(InitiatorRandom, fuzzInitiatorSessionId, fuzzedFabricId, IPK, rootPubKey);
    // CaseSession.HandleSigma1;
    CaseSession.ParseSigma1(InitiatorRandom, fuzzInitiatorSessionId, fuzzedFabricId, IPK, rootPubKey);
    chip::Platform::MemoryShutdown();
}
FUZZ_TEST(FuzzCASE_PW, ParseSigma1)
    .WithDomains(
        // InitiatorRandom (Original size = kSigmaParamRandomNumberSize)
        Arbitrary<vector<uint8_t>>().WithSize(kSigmaParamRandomNumberSize),
        // fuzzInitiatorSessionId
        Arbitrary<uint32_t>(),
        // FabricId
        Arbitrary<FabricId>(),
        // fuzzIPK, (Original size = CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES)
        Arbitrary<vector<uint8_t>>().WithSize(CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES),
        // rootPubKey (Original size = kP256_PublicKey_Length)
        Arbitrary<vector<uint8_t>>().WithSize(kP256_PublicKey_Length));

} // namespace Testing
} // namespace chip
