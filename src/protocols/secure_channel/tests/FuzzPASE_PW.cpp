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
#include <protocols/secure_channel/PASESession.h>
#include <system/TLVPacketBufferBackingStore.h>

namespace Fuzzchip {

using namespace chip;
using namespace std;

using namespace chip::Crypto;
using namespace fuzztest;
using namespace chip::Transport;
using namespace chip::Messaging;
using namespace System::Clock::Literals;

// TODO: #35369 Refactor the classes below to Fixtures once Errors related to FuzzTest Fixtures are resolved
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

class TestSecurePairingDelegate : public SessionEstablishmentDelegate
{
public:
    void OnSessionEstablishmentError(CHIP_ERROR error) override { mNumPairingErrors++; }

    void OnSessionEstablished(const SessionHandle & session) override { mNumPairingComplete++; }

    uint32_t mNumPairingErrors   = 0;
    uint32_t mNumPairingComplete = 0;
};

class TestPASESession : public FuzzLoopbackMessagingContext
{
public:
    TestPASESession()
    {
        ConfigInitializeNodes(false);
        FuzzLoopbackMessagingContext::SetUpTestSuite();
        FuzzLoopbackMessagingContext::SetUp();
    }
    ~TestPASESession()
    {
        FuzzLoopbackMessagingContext::TearDown();
        FuzzLoopbackMessagingContext::TearDownTestSuite();
    }

    void SecurePairingHandshake(SessionManager & sessionManager, PASESession & pairingCommissioner,
                                TestSecurePairingDelegate & delegateCommissioner, TestSecurePairingDelegate & delegateAccessory,
                                const Spake2pVerifier & verifier, uint32_t pbkdf2IterCount, const ByteSpan & salt,
                                uint32_t SetUpPINCode);

    void FuzzHandlePBKDFParamRequest(System::PacketBufferHandle && msg, PASESession & pairingCommissioner,
                                     SessionManager & sessionManager);

    //  this one is working, but commented it to try 2nd versoin

    //  void FuzzSpake1(const uint32_t fuzzedSetupPasscode, const ByteSpan & fuzzedSalt, uint32_t fuzzedPBKDF2Iter);

    void FuzzSpake1(const uint32_t fuzzedSetupPasscode, const ByteSpan & fuzzedSalt, uint32_t fuzzedPBKDF2Iter,
                    const uint16_t FuzzedMAX_Point_Length);

    void FuzzHandleMsg1(const uint32_t fuzzedSetupPasscode, const vector<uint8_t> & fuzzedSalt, uint32_t fuzzedPBKDF2Iter,
                        const uint32_t FuzzedMAX_Point_Length);

    void FuzzHandleMsg2(const uint32_t fuzzedSetupPasscode, const vector<uint8_t> & fuzzedSalt, uint32_t fuzzedPBKDF2Iter,
                        const uint32_t FuzzedMAX_Point_Length, const uint32_t FuzzedMAX_Hash_Length, ByteSpan & pB, ByteSpan & cB);

    void FuzzHandleMsg3(const uint32_t fuzzedSetupPasscode, const vector<uint8_t> & fuzzedSalt, uint32_t fuzzedPBKDF2Iter,
                        const uint32_t FuzzedMAX_Point_Length, const uint32_t FuzzedMAX_Hash_Length, ByteSpan & cB);

    // TO BE ABLE TO CALL AllocateSecureSession for usage in FuzzPASE_PW.HandlePBKDFParamRequest
    CHIP_ERROR CallAllocateSecureSession(SessionManager & sessionManager, PASESession & pairingCommissioner)
    {
        return pairingCommissioner.AllocateSecureSession(sessionManager);
    }
};

class TemporarySessionManager
{
public:
    TemporarySessionManager(TestPASESession & ctx) : mCtx(ctx)
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
    TestPASESession & mCtx;
    TestPersistentStorageDelegate mStorage;
    SessionManager mSessionManager;
};

class PASETestLoopbackTransportDelegate : public Test::LoopbackTransportDelegate
{
public:
    void OnMessageDropped() override { mMessageDropped = true; }
    bool mMessageDropped = false;
};

void TestPASESession::SecurePairingHandshake(SessionManager & sessionManager, PASESession & pairingCommissioner,
                                             TestSecurePairingDelegate & delegateCommissioner,
                                             TestSecurePairingDelegate & delegateAccessory, const Spake2pVerifier & verifier,
                                             uint32_t pbkdf2IterCount, const ByteSpan & salt, uint32_t SetUpPINCode)
{

    PASESession pairingAccessory;

    PASETestLoopbackTransportDelegate delegate;
    auto & loopback = GetLoopback();
    loopback.SetLoopbackTransportDelegate(&delegate);
    loopback.mSentMessageCount = 0;

    ExchangeContext * contextCommissioner = NewUnauthenticatedExchangeToBob(&pairingCommissioner);

    EXPECT_EQ(GetExchangeManager().RegisterUnsolicitedMessageHandlerForType(Protocols::SecureChannel::MsgType::PBKDFParamRequest,
                                                                            &pairingAccessory),
              CHIP_NO_ERROR);

    pairingAccessory.WaitForPairing(sessionManager, verifier, pbkdf2IterCount, salt,
                                    Optional<ReliableMessageProtocolConfig>::Missing(), &delegateAccessory);
    DrainAndServiceIO();

    pairingCommissioner.Pair(sessionManager, SetUpPINCode, Optional<ReliableMessageProtocolConfig>::Missing(), contextCommissioner,
                             &delegateCommissioner);

    DrainAndServiceIO();
}

//----------------------------------------**********Fuzz Tests*********------------------------------------------------

// This Fuzz Test should always result in Successful PASE Pairing, since all fuzzed inputs are within the valid bounds
void PASESession_Bounded(const uint32_t fuzzedSetupPasscode, const vector<uint8_t> & fuzzedSalt, uint32_t fuzzedPBKDF2Iter)
{

    Spake2pVerifier fuzzedSpake2pVerifier;
    ByteSpan fuzzedSaltSpan{ fuzzedSalt.data(), fuzzedSalt.size() };

    // Generating the Spake2+ verifier from the fuzzed inputs
    EXPECT_EQ(fuzzedSpake2pVerifier.Generate(fuzzedPBKDF2Iter, fuzzedSaltSpan, fuzzedSetupPasscode), CHIP_NO_ERROR);

    // TODO: #35369 Move this to a Fixture once Errors related to FuzzTest Fixtures are resolved
    TestPASESession PASELoopBack;
    TemporarySessionManager sessionManager(PASELoopBack);

    PASESession pairingCommissioner;

    TestSecurePairingDelegate delegateCommissioner;
    TestSecurePairingDelegate delegateCommissionee;

    PASELoopBack.SecurePairingHandshake(sessionManager, pairingCommissioner, delegateCommissioner, delegateCommissionee,
                                        fuzzedSpake2pVerifier, fuzzedPBKDF2Iter, fuzzedSaltSpan, fuzzedSetupPasscode);

    // Given that the inputs to this Fuzz Test are within the expected boundaries, the Pairing should Always be successful.
    EXPECT_EQ(delegateCommissionee.mNumPairingComplete, 1u);
    EXPECT_EQ(delegateCommissioner.mNumPairingComplete, 1u);

    EXPECT_EQ(delegateCommissionee.mNumPairingErrors, 0u);
    EXPECT_EQ(delegateCommissioner.mNumPairingErrors, 0u);
}

FUZZ_TEST(FuzzPASE_PW, PASESession_Bounded)
    .WithDomains(
        InRange(00000000, 99999998),
        Arbitrary<vector<uint8_t>>().WithMinSize(kSpake2p_Min_PBKDF_Salt_Length).WithMaxSize(kSpake2p_Max_PBKDF_Salt_Length),
        InRange(kSpake2p_Min_PBKDF_Iterations, kSpake2p_Max_PBKDF_Iterations));

/* -------------------------------------------------------------------------------------------*/
// This Fuzz Test is the equivalent of the previous one, but with the fuzzed inputs not being within the valid bounds.
void PASESession_Unbounded(const uint32_t fuzzedSetupPasscode, const vector<uint8_t> & fuzzedSalt, uint32_t fuzzedPBKDF2Iter)
{

    Spake2pVerifier fuzzedSpake2pVerifier;
    ByteSpan fuzzedSaltSpan{ fuzzedSalt.data(), fuzzedSalt.size() };

    // Generating the Spake2+ verifier from fuzzed inputs
    fuzzedSpake2pVerifier.Generate(fuzzedPBKDF2Iter, fuzzedSaltSpan, fuzzedSetupPasscode);

    TestPASESession PASELoopBack;
    TemporarySessionManager sessionManager(PASELoopBack);

    PASESession pairingCommissioner;

    TestSecurePairingDelegate delegateCommissioner;
    TestSecurePairingDelegate delegateCommissionee;

    PASELoopBack.SecurePairingHandshake(sessionManager, pairingCommissioner, delegateCommissioner, delegateCommissionee,
                                        fuzzedSpake2pVerifier, fuzzedPBKDF2Iter, fuzzedSaltSpan, fuzzedSetupPasscode);
}

FUZZ_TEST(FuzzPASE_PW, PASESession_Unbounded)
    .WithDomains(Arbitrary<uint32_t>(), Arbitrary<vector<uint8_t>>(), Arbitrary<uint32_t>());

/* -------------------------------------------------------------------------------------------*/
// In This FuzzTest, the Spake2pVerifier is fuzzed.
void FuzzSpake2pVerifier(const vector<uint8_t> & aW0, const vector<uint8_t> & aL, const vector<uint8_t> & aSalt,
                         const uint32_t fuzzedPBKDF2Iter, const uint32_t fuzzedSetupPasscode)
{
    Spake2pVerifier fuzzedSpake2pVerifier;

    copy_n(aW0.data(), aW0.size(), fuzzedSpake2pVerifier.mW0);
    copy_n(aL.data(), aL.size(), fuzzedSpake2pVerifier.mL);

    ByteSpan fuzzedSaltSpan(aSalt.data(), aSalt.size());

    TestPASESession PASELoopBack;
    TemporarySessionManager sessionManager(PASELoopBack);

    PASESession pairingCommissioner;

    TestSecurePairingDelegate delegateCommissioner;
    TestSecurePairingDelegate delegateCommissionee;

    PASELoopBack.SecurePairingHandshake(sessionManager, pairingCommissioner, delegateCommissioner, delegateCommissionee,
                                        fuzzedSpake2pVerifier, fuzzedPBKDF2Iter, fuzzedSaltSpan, fuzzedSetupPasscode);
}
FUZZ_TEST(FuzzPASE_PW, FuzzSpake2pVerifier)
    .WithDomains(Arbitrary<std::vector<uint8_t>>().WithMaxSize(kP256_FE_Length),
                 Arbitrary<std::vector<uint8_t>>().WithMaxSize(kP256_Point_Length), Arbitrary<vector<uint8_t>>(),
                 Arbitrary<uint32_t>(), Arbitrary<uint32_t>());

/* -------------------------------------------------------------------------------------------*/
// In This FuzzTest, Fuzzed Serialized Verifier is deserialized and Serialized Again, comparing the original with RoundTrip result.
void Spake2pVerifier_Serialize_RoundTrip(const vector<uint8_t> & FuzzedSerializedVerifier)
{

    Spake2pVerifierSerialized FuzzedSerializedVerifierArray;

    copy_n(FuzzedSerializedVerifier.data(), FuzzedSerializedVerifier.size(), FuzzedSerializedVerifierArray);

    // Deserialize the fuzzed SPAKE2+ Verifier
    Spake2pVerifier verifier;
    EXPECT_EQ(verifier.Deserialize(ByteSpan(FuzzedSerializedVerifierArray)), CHIP_NO_ERROR);

    // Serialize the fuzzed SPAKE2+ Verifier again
    Spake2pVerifierSerialized reserializedVerifier;
    MutableByteSpan reserializedVerifierSpan(reserializedVerifier);
    EXPECT_EQ(verifier.Serialize(reserializedVerifierSpan), CHIP_NO_ERROR);
    EXPECT_EQ(reserializedVerifierSpan.size(), kSpake2p_VerifierSerialized_Length);

    // The original fuzzed SPAKE2+ verifier should be the same as the deserialized and re-serialized verifier (RoundTrip).
    EXPECT_EQ(memcmp(reserializedVerifier, FuzzedSerializedVerifierArray, kSpake2p_VerifierSerialized_Length), 0);
}

FUZZ_TEST(FuzzPASE_PW, Spake2pVerifier_Serialize_RoundTrip)
    .WithDomains(Arbitrary<vector<uint8_t>>().WithSize(kSpake2p_VerifierSerialized_Length));

/* -------------------------------------------------------------------------------------------*/

void TestPASESession::FuzzHandlePBKDFParamRequest(System::PacketBufferHandle && msg, PASESession & pairingCommissioner,
                                                  SessionManager & sessionManager)
{
    PASESession pairingAccessory;

    PASETestLoopbackTransportDelegate delegate;
    auto & loopback = GetLoopback();
    loopback.SetLoopbackTransportDelegate(&delegate);
    loopback.mSentMessageCount = 0;

    TestSecurePairingDelegate delegateCommissioner;
    TestSecurePairingDelegate delegateCommissionee;

    pairingCommissioner.mNextExpectedMsg.SetValue(Protocols::SecureChannel::MsgType::PBKDFParamResponse);

    //   ExchangeContext * contextCommissioner = NewUnauthenticatedExchangeToBob(&pairingCommissioner);

    // One Limitation of using this is that contextAccessory will automatically be an Initiator, while in real-life it should be a
    // responder.
    ExchangeContext * contextAccessory = NewUnauthenticatedExchangeToBob(&pairingAccessory);
    //   ExchangeContext * contextCommissioner = NewUnauthenticatedExchangeToBob(&pairingCommissioner);

    // mFlags is a protected member of ReliableMessageContext, I can not set it from an ExchangeContext
    // contextAccessory->mFlags.Set(Flags::kFlagInitiator, 0);

    // EXPECT_EQ(GetExchangeManager().RegisterUnsolicitedMessageHandlerForType(Protocols::SecureChannel::MsgType::PBKDFParamRequest,
    //                                                                         &pairingAccessory),
    //           CHIP_NO_ERROR);

    PayloadHeader payloadHeaderAccessory;

    // Adding PASESession::Init in order to AllocateSecureSession and have a localsessionID generated for pairingAccessory
    pairingAccessory.Init(sessionManager, 0, &delegateCommissionee);

    pairingCommissioner.mRole = CryptoContext::SessionRole::kInitiator;
    pairingAccessory.mRole    = CryptoContext::SessionRole::kResponder;

    // This was done to have an exchange context
    pairingAccessory.mExchangeCtxt.Emplace(*contextAccessory);
    //   pairingCommissioner.mExchangeCtxt.Emplace(*contextCommissioner);

    // This was added because we get a Crash in .mCommissioningHash.AddData if it was called without a Begin
    // TODO: Consider doing a PR for a check inside AddData that an Init(SHA256_Init) did occur (maybe add a flag)

    // NO NEED FOR THIS LINE SINCE ALREADY CALLED IN Init above pairingAccessory.mCommissioningHash.Begin();
    //  uint8_t Y[10];
    // pairingAccessory.mCommissioningHash.AddData(ByteSpan(Y));

    pairingAccessory.mLocalMRPConfig = MakeOptional(ReliableMessageProtocolConfig(
        System::Clock::Milliseconds32(100), System::Clock::Milliseconds32(200), System::Clock::Milliseconds16(4000)));

    payloadHeaderAccessory.SetMessageType(Protocols::SecureChannel::MsgType::PBKDFParamRequest);
    pairingAccessory.mNextExpectedMsg.SetValue(Protocols::SecureChannel::MsgType::PBKDFParamRequest);

    pairingAccessory.OnMessageReceived(&pairingAccessory.mExchangeCtxt.Value().Get(), payloadHeaderAccessory, std::move(msg));

    // uint8_t context[kSHA256_Hash_Length] = { 0 };
    // MutableByteSpan contextSpan{ context };
    // pairingAccessory.mCommissioningHash.Finish(contextSpan);

    DrainAndServiceIO();

    // if an error happens in PASESession::ValidateReceivedMessage, I will get a crash related to ReferenceCount(after destructor of
    // exchangecontext)
    // the below solves it
    // contextAccessory->Close();

    // pairingAccessory.HandlePBKDFParamRequest(std::move(msg));
}

// In This FuzzTest
void HandlePBKDFParamRequest(vector<uint8_t> fuzzPBKDFLocalRandomData)
{
    TestPASESession PASELoopBack;
    TemporarySessionManager sessionManager(PASELoopBack);

    PASESession pairingCommissioner;

    /**************************************************************************************** */
    const size_t max_msg_len = TLV::EstimateStructOverhead(kPBKDFParamRandomNumberSize,         // initiatorRandom,
                                                           sizeof(uint16_t),                    // initiatorSessionId
                                                           sizeof(PasscodeId),                  // passcodeId,
                                                           sizeof(uint8_t),                     // hasPBKDFParameters
                                                           SessionParameters::kEstimatedTLVSize // Session Parameters
    );

    System::PacketBufferHandle req = System::PacketBufferHandle::New(max_msg_len);
    ASSERT_FALSE(req.IsNull());

    System::PacketBufferTLVWriter tlvWriter;
    tlvWriter.Init(std::move(req));

    TLV::TLVType outerContainerType = TLV::kTLVType_NotSpecified;
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.StartContainer(TLV::AnonymousTag(), TLV::kTLVType_Structure, outerContainerType));
    EXPECT_EQ(CHIP_NO_ERROR,
              tlvWriter.PutBytes(TLV::ContextTag(1), fuzzPBKDFLocalRandomData.data(), fuzzPBKDFLocalRandomData.size()));

    PASELoopBack.CallAllocateSecureSession(sessionManager, pairingCommissioner);

    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Put(TLV::ContextTag(2), pairingCommissioner.GetLocalSessionId().Value()));
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Put(TLV::ContextTag(3), kDefaultCommissioningPasscodeId));
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.PutBoolean(TLV::ContextTag(4), true));

    // VerifyOrReturnError(mLocalMRPConfig.HasValue(), CHIP_ERROR_INCORRECT_STATE);

    ReliableMessageProtocolConfig config(System::Clock::Milliseconds32(100), System::Clock::Milliseconds32(200),
                                         System::Clock::Milliseconds16(4000));

    EXPECT_EQ(CHIP_NO_ERROR, PASESession::EncodeSessionParameters(TLV::ContextTag(5), config, tlvWriter));

    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.EndContainer(outerContainerType));
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Finalize(&req));

    /**************************************************************************************************************** */

    //  System::PacketBufferHandle req = System::PacketBufferHandle::NewWithData(buffer.data(), buffer.size());
    PASELoopBack.FuzzHandlePBKDFParamRequest(std::move(req), pairingCommissioner, sessionManager);
}

// FUZZ_TEST(FuzzPASE_PW, HandlePBKDFParamRequest).WithDomains(Arbitrary<vector<uint8_t>>());
FUZZ_TEST(FuzzPASE_PW, HandlePBKDFParamRequest).WithDomains(Arbitrary<vector<uint8_t>>().WithSize(32));

// In This FuzzTest
void HandlePBKDFParamRequestv2(vector<uint8_t> fuzzPBKDFLocalRandomData, bool fuzzHavePBKDFParameters)
{
    TestPASESession PASELoopBack;
    TemporarySessionManager sessionManager(PASELoopBack);

    PASESession pairingCommissioner;

    /**************************************************************************************** */
    const size_t max_msg_len = TLV::EstimateStructOverhead(fuzzPBKDFLocalRandomData.size(),     // initiatorRandom,
                                                           sizeof(uint16_t),                    // initiatorSessionId
                                                           sizeof(PasscodeId),                  // passcodeId,
                                                           sizeof(uint8_t),                     // hasPBKDFParameters
                                                           SessionParameters::kEstimatedTLVSize // Session Parameters
    );

    System::PacketBufferHandle req = System::PacketBufferHandle::New(max_msg_len);
    ASSERT_FALSE(req.IsNull());

    System::PacketBufferTLVWriter tlvWriter;
    tlvWriter.Init(std::move(req));

    TLV::TLVType outerContainerType = TLV::kTLVType_NotSpecified;
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.StartContainer(TLV::AnonymousTag(), TLV::kTLVType_Structure, outerContainerType));
    EXPECT_EQ(CHIP_NO_ERROR,
              tlvWriter.PutBytes(TLV::ContextTag(1), fuzzPBKDFLocalRandomData.data(), fuzzPBKDFLocalRandomData.size()));

    PASELoopBack.CallAllocateSecureSession(sessionManager, pairingCommissioner);

    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Put(TLV::ContextTag(2), pairingCommissioner.GetLocalSessionId().Value()));
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Put(TLV::ContextTag(3), kDefaultCommissioningPasscodeId));
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.PutBoolean(TLV::ContextTag(4), fuzzHavePBKDFParameters));

    // VerifyOrReturnError(mLocalMRPConfig.HasValue(), CHIP_ERROR_INCORRECT_STATE);

    ReliableMessageProtocolConfig config(System::Clock::Milliseconds32(100), System::Clock::Milliseconds32(200),
                                         System::Clock::Milliseconds16(4000));

    PASESession::EncodeSessionParameters(TLV::ContextTag(5), config, tlvWriter);

    tlvWriter.EndContainer(outerContainerType);
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Finalize(&req));

    /**************************************************************************************************************** */

    //  System::PacketBufferHandle req = System::PacketBufferHandle::NewWithData(buffer.data(), buffer.size());
    PASELoopBack.FuzzHandlePBKDFParamRequest(std::move(req), pairingCommissioner, sessionManager);
}

// FUZZ_TEST(FuzzPASE_PW, HandlePBKDFParamRequest).WithDomains(Arbitrary<vector<uint8_t>>());
FUZZ_TEST(FuzzPASE_PW, HandlePBKDFParamRequestv2).WithDomains(Arbitrary<vector<uint8_t>>(), Arbitrary<bool>());

/* In This Test, I will Begin Fuzzing Spake Protocol
I Will initialise Spake using PBKDF Parameters*/

//------------------------------------THIS IS WORKING FINE------------------------------------------------------------------------
// void TestPASESession::FuzzSpake1(const uint32_t fuzzedSetupPasscode, const ByteSpan & fuzzedSalt, uint32_t fuzzedPBKDF2Iter)

// {
//     //  const size_t max_msg_len       = TLV::EstimateStructOverhead(kMAX_Point_Length);
//     //   System::PacketBufferHandle msg = System::PacketBufferHandle::New(max_msg_len);

//     //   System::PacketBufferTLVWriter tlvWriter;
//     //  tlvWriter.Init(std::move(msg));

//     // Initialising mCommissioningHash, which will be used to Initialize Spake2+ in SetupSpake2p();

//     /*
//     ReturnErrorOnFailure(mCommissioningHash.Begin());
//     SuccessOrExit(err = mCommissioningHash.AddData(ByteSpan{ msg->Start(), msg->DataLength() }));
//     */

//     /* SIMULATING PBKDFResponse Reception */

//     // SetPeerSessionId(responderSessionId);

//     PASESession pairingCommissioner;
//     PASESession pairingNode;

//     pairingCommissioner.mCommissioningHash.Begin();
//     // TODO fuzzedsalt doesnt make sense here, I did it just o  have some data
//     pairingCommissioner.mCommissioningHash.AddData(fuzzedSalt);

//     CHIP_ERROR err = pairingCommissioner.SetupSpake2p();
//     EXPECT_EQ(CHIP_NO_ERROR, err);

//     uint8_t serializedWS[kSpake2p_WS_Length * 2] = { 0 };

//     err = Spake2pVerifier::ComputeWS(fuzzedPBKDF2Iter, fuzzedSalt, fuzzedSetupPasscode, serializedWS, sizeof(serializedWS));
//     EXPECT_EQ(CHIP_NO_ERROR, err);

//     err = pairingCommissioner.mSpake2p.BeginProver(nullptr, 0, nullptr, 0, &serializedWS[0], kSpake2p_WS_Length,
//                                                    &serializedWS[kSpake2p_WS_Length], kSpake2p_WS_Length);
//     EXPECT_EQ(CHIP_NO_ERROR, err);

//     /*
//     err = SendMsg1();
//     SuccessOrExit(err);
// */
//     ////////////////////////////////
//     /*SendMsg1*/

//     const size_t max_msg_len       = TLV::EstimateStructOverhead(kMAX_Point_Length);
//     System::PacketBufferHandle msg = System::PacketBufferHandle::New(max_msg_len);
//     ASSERT_FALSE(msg.IsNull());

//     System::PacketBufferTLVWriter tlvWriter;
//     tlvWriter.Init(std::move(msg));

//     TLV::TLVType outerContainerType = TLV::kTLVType_NotSpecified;
//     EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.StartContainer(TLV::AnonymousTag(), TLV::kTLVType_Structure, outerContainerType));

//     uint8_t X[kMAX_Point_Length];
//     size_t X_len = sizeof(X);

//     constexpr uint8_t kPake1_pA = 1;

//     EXPECT_EQ(CHIP_NO_ERROR, pairingCommissioner.mSpake2p.ComputeRoundOne(nullptr, 0, X, &X_len));
//     EXPECT_EQ(X_len, sizeof(X));
//     EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Put(TLV::ContextTag(kPake1_pA), ByteSpan(X)));
//     EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.EndContainer(outerContainerType));
//     EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Finalize(&msg));

//     // HANDLE SPAKE1 --> happens at RESPONDER/NODE

//     uint8_t Y[kMAX_Point_Length];
//     size_t Y_len = sizeof(Y);

//     const uint8_t * X_Reader;
//     size_t X_Reader_len = 0;

//     uint8_t verifier[kMAX_Hash_Length];
//     size_t verifier_len = kMAX_Hash_Length;

//     System::PacketBufferTLVReader tlvReader;
//     TLV::TLVType containerType = TLV::kTLVType_Structure;

//     tlvReader.Init(std::move(msg));
//     EXPECT_EQ(CHIP_NO_ERROR, tlvReader.Next(containerType, TLV::AnonymousTag()));
//     EXPECT_EQ(CHIP_NO_ERROR, tlvReader.EnterContainer(containerType));

//     EXPECT_EQ(CHIP_NO_ERROR, tlvReader.Next());
//     EXPECT_EQ(TLV::TagNumFromTag(tlvReader.GetTag()), 1);
//     X_Reader_len = tlvReader.GetLength();
//     EXPECT_EQ(CHIP_NO_ERROR, tlvReader.GetDataPtr(X_Reader));

//     // WORKAROUND, THE STATE WAS RESET TO "PROVER" --> THIS IS HAPPENING BECAUSE I AM TREATING SENDER AND RECEIVER AS SAME DEVICE
//     // THIS IS USUALLY CALLED in `SendPBKDFParamResponse`
//     err = pairingNode.SetupSpake2p();

//     // COMPUTE VERIFIER TO BE ABLE TO PASS IT TO BeginVerifier
//     EXPECT_EQ(pairingNode.mPASEVerifier.Generate(fuzzedPBKDF2Iter, fuzzedSalt, fuzzedSetupPasscode), CHIP_NO_ERROR);

//     EXPECT_EQ(CHIP_NO_ERROR,
//               pairingNode.mSpake2p.BeginVerifier(nullptr, 0, nullptr, 0, pairingNode.mPASEVerifier.mW0, kP256_FE_Length,
//                                                  pairingNode.mPASEVerifier.mL, kP256_Point_Length));

//     EXPECT_EQ(CHIP_NO_ERROR, pairingNode.mSpake2p.ComputeRoundOne(X_Reader, X_Reader_len, Y, &Y_len));
//     EXPECT_EQ(Y_len, sizeof(Y));
//     EXPECT_EQ(CHIP_NO_ERROR, pairingNode.mSpake2p.ComputeRoundTwo(X_Reader, X_Reader_len, verifier, &verifier_len));
// }

// void Spake1(const uint32_t fuzzedSetupPasscode, const vector<uint8_t> & fuzzedSalt, uint32_t fuzzedPBKDF2Iter)
// {
//     TestPASESession PASELoopBack;
//     TemporarySessionManager sessionManager(PASELoopBack);

//     ByteSpan fuzzedSaltSpan(fuzzedSalt.data(), fuzzedSalt.size());

//     PASELoopBack.FuzzSpake1(fuzzedSetupPasscode, fuzzedSaltSpan, fuzzedPBKDF2Iter);
// }
//------------------------------------ABOVE IS WORKING FINE------------------------------------------------------------------------

void TestPASESession::FuzzSpake1(const uint32_t fuzzedSetupPasscode, const ByteSpan & fuzzedSalt, uint32_t fuzzedPBKDF2Iter,
                                 const uint16_t FuzzedMAX_Point_Length)

{
    //  const size_t max_msg_len       = TLV::EstimateStructOverhead(kMAX_Point_Length);
    //   System::PacketBufferHandle msg = System::PacketBufferHandle::New(max_msg_len);

    //   System::PacketBufferTLVWriter tlvWriter;
    //  tlvWriter.Init(std::move(msg));

    // Initialising mCommissioningHash, which will be used to Initialize Spake2+ in SetupSpake2p();

    /*
    ReturnErrorOnFailure(mCommissioningHash.Begin());
    SuccessOrExit(err = mCommissioningHash.AddData(ByteSpan{ msg->Start(), msg->DataLength() }));
    */

    /* SIMULATING PBKDFResponse Reception */

    // SetPeerSessionId(responderSessionId);

    PASESession pairingCommissioner;
    PASESession pairingNode;

    pairingCommissioner.mCommissioningHash.Begin();
    // TODO fuzzedsalt doesnt make sense here, I did it just o  have some data
    //  pairingCommissioner.mCommissioningHash.AddData(fuzzedSalt);

    CHIP_ERROR err = pairingCommissioner.SetupSpake2p();
    EXPECT_EQ(CHIP_NO_ERROR, err);

    uint8_t serializedWS[kSpake2p_WS_Length * 2] = { 0 };

    err = Spake2pVerifier::ComputeWS(fuzzedPBKDF2Iter, fuzzedSalt, fuzzedSetupPasscode, serializedWS, sizeof(serializedWS));
    EXPECT_EQ(CHIP_NO_ERROR, err);

    err = pairingCommissioner.mSpake2p.BeginProver(nullptr, 0, nullptr, 0, &serializedWS[0], kSpake2p_WS_Length,
                                                   &serializedWS[kSpake2p_WS_Length], kSpake2p_WS_Length);
    EXPECT_EQ(CHIP_NO_ERROR, err);

    /*
    err = SendMsg1();
    SuccessOrExit(err);
*/

    /*-----------------------------------------------------------------------------------------------------------------------------*/
    /*-----------------------------------------------------------------------------------------------------------------------------*/
    /*SendMsg1*/

    const size_t max_msg_len       = TLV::EstimateStructOverhead(FuzzedMAX_Point_Length);
    System::PacketBufferHandle msg = System::PacketBufferHandle::New(max_msg_len);
    ASSERT_FALSE(msg.IsNull());

    System::PacketBufferTLVWriter tlvWriter;
    tlvWriter.Init(std::move(msg));

    TLV::TLVType outerContainerType = TLV::kTLVType_NotSpecified;
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.StartContainer(TLV::AnonymousTag(), TLV::kTLVType_Structure, outerContainerType));

    //   uint8_t X[kMAX_Point_Length];
    // size_t X_len = sizeof(X);

    std::vector<uint8_t> X(FuzzedMAX_Point_Length);
    size_t X_len = X.size();
    std::cout << "X_len = " << X_len << endl;

    constexpr uint8_t kPake1_pA = 1;

    pairingCommissioner.mSpake2p.ComputeRoundOne(nullptr, 0, X.data(), &X_len);
    //    EXPECT_EQ(CHIP_NO_ERROR, pairingCommissioner.mSpake2p.ComputeRoundOne(nullptr, 0, X.data(), &X_len));

    //---***ARRAY VARIANT
    //  EXPECT_EQ(CHIP_NO_ERROR, pairingCommissioner.mSpake2p.ComputeRoundOne(nullptr, 0, X, &X_len));

    // Below fails when FuzzedMAX_Point_Length > 65
    //  EXPECT_EQ(X_len, X.size());

    //---***ARRAY VARIANT
    //    EXPECT_EQ(X_len, sizeof(X));

    tlvWriter.Put(TLV::ContextTag(kPake1_pA), ByteSpan(X.data(), X.size()));
    //    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Put(TLV::ContextTag(kPake1_pA), ByteSpan(X.data(), X.size())));

    //---***ARRAY VARIANT
    // EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Put(TLV::ContextTag(kPake1_pA), ByteSpan(X)));

    tlvWriter.EndContainer(outerContainerType);
    tlvWriter.Finalize(&msg);
    // EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.EndContainer(outerContainerType));
    // EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Finalize(&msg));

    /*-----------------------------------------------------------------------------------------------------------------------------*/
    /*-----------------------------------------------------------------------------------------------------------------------------*/
    // HANDLE SPAKE1 --> happens at RESPONDER/NODE

    uint8_t Y[kMAX_Point_Length];
    size_t Y_len = sizeof(Y);

    const uint8_t * X_Reader;
    size_t X_Reader_len = 0;

    uint8_t verifier[kMAX_Hash_Length];
    size_t verifier_len = kMAX_Hash_Length;

    System::PacketBufferTLVReader tlvReader;
    TLV::TLVType containerType = TLV::kTLVType_Structure;

    tlvReader.Init(std::move(msg));
    EXPECT_EQ(CHIP_NO_ERROR, tlvReader.Next(containerType, TLV::AnonymousTag()));
    EXPECT_EQ(CHIP_NO_ERROR, tlvReader.EnterContainer(containerType));

    tlvReader.Next();
    // EXPECT_EQ(CHIP_NO_ERROR, tlvReader.Next());
    EXPECT_EQ(TLV::TagNumFromTag(tlvReader.GetTag()), 1);
    X_Reader_len = tlvReader.GetLength();
    std::cout << "X_Reader_len = " << X_Reader_len << endl;

    tlvReader.GetDataPtr(X_Reader);
    //  EXPECT_EQ(CHIP_NO_ERROR, tlvReader.GetDataPtr(X_Reader));

    //// WORKAROUND, THE STATE WAS RESET TO "PROVER" --> THIS IS HAPPENING BECAUSE I AM TREATING SENDER AND RECEIVER AS SAME DEVICE
    // THIS IS USUALLY CALLED in `SendPBKDFParamResponse`, I am calling it here since PairingNode is being initialised here

    pairingNode.mCommissioningHash.Begin();
    // TODO fuzzedsalt doesnt make sense here, I did it just o  have some data
    pairingNode.mCommissioningHash.AddData(fuzzedSalt);
    err = pairingNode.SetupSpake2p();

    // COMPUTE VERIFIER TO BE ABLE TO PASS IT TO BeginVerifier
    EXPECT_EQ(pairingNode.mPASEVerifier.Generate(fuzzedPBKDF2Iter, fuzzedSalt, fuzzedSetupPasscode), CHIP_NO_ERROR);

    EXPECT_EQ(CHIP_NO_ERROR,
              pairingNode.mSpake2p.BeginVerifier(nullptr, 0, nullptr, 0, pairingNode.mPASEVerifier.mW0, kP256_FE_Length,
                                                 pairingNode.mPASEVerifier.mL, kP256_Point_Length));

    EXPECT_EQ(CHIP_NO_ERROR, pairingNode.mSpake2p.ComputeRoundOne(X_Reader, X_Reader_len, Y, &Y_len));
    EXPECT_EQ(Y_len, sizeof(Y));

    pairingNode.mSpake2p.ComputeRoundTwo(X_Reader, X_Reader_len, verifier, &verifier_len);
    // EXPECT_EQ(CHIP_NO_ERROR, pairingNode.mSpake2p.ComputeRoundTwo(X_Reader, X_Reader_len, verifier, &verifier_len));

    // IT IS WORKING UNTILL HERE 28Oct

    /*-----------------------------------------------------------------------------------------------------------------------------*/
    /*-----------------------------------------------------------------------------------------------------------------------------*/
    // Send PAKE2

    const size_t max_msg2_len   = TLV::EstimateStructOverhead(Y_len, verifier_len);
    constexpr uint8_t kPake2_pB = 1;
    constexpr uint8_t kPake2_cB = 2;

    System::PacketBufferHandle msg2 = System::PacketBufferHandle::New(max_msg2_len);
    ASSERT_FALSE(msg2.IsNull());

    System::PacketBufferTLVWriter tlvWriter2;
    tlvWriter2.Init(std::move(msg2));

    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter2.StartContainer(TLV::AnonymousTag(), TLV::kTLVType_Structure, outerContainerType));
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter2.Put(TLV::ContextTag(kPake2_pB), ByteSpan(Y)));
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter2.Put(TLV::ContextTag(kPake2_cB), ByteSpan(verifier, verifier_len)));
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter2.EndContainer(outerContainerType));
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter2.Finalize(&msg2));
}

void Spake1(const uint32_t fuzzedSetupPasscode, const vector<uint8_t> & fuzzedSalt, uint32_t fuzzedPBKDF2Iter,
            const uint32_t FuzzedMAX_Point_Length)
{
    TestPASESession PASELoopBack;
    TemporarySessionManager sessionManager(PASELoopBack);

    ByteSpan fuzzedSaltSpan(fuzzedSalt.data(), fuzzedSalt.size());

    PASELoopBack.FuzzSpake1(fuzzedSetupPasscode, fuzzedSaltSpan, fuzzedPBKDF2Iter, FuzzedMAX_Point_Length);
}

FUZZ_TEST(FuzzPASE_PW, Spake1)
    .WithDomains(
        InRange(00000000, 99999998),
        Arbitrary<vector<uint8_t>>().WithMinSize(kSpake2p_Min_PBKDF_Salt_Length).WithMaxSize(kSpake2p_Max_PBKDF_Salt_Length),
        InRange(kSpake2p_Min_PBKDF_Iterations, kSpake2p_Max_PBKDF_Iterations),
        // MaximumBuffer capacity is 64000, overhead is around 44
        InRange(1, 63956));
// NonZero<uint16_t>());

/*-+-+-++++++----------+++++++++++++++-----------------------------+++++++++++++++++++----------++++++++++++++----------++++++++*/

void TestPASESession::FuzzHandleMsg1(const uint32_t fuzzedSetupPasscode, const vector<uint8_t> & fuzzedSalt,
                                     uint32_t fuzzedPBKDF2Iter, const uint32_t FuzzedMAX_Point_Length)
{

    TemporarySessionManager sessionManager(*this);

    PASESession pairingCommissioner;

    ByteSpan fuzzedSaltSpan(fuzzedSalt.data(), fuzzedSalt.size());

    // Steps that happen before PAKE1 Message is constructed
    pairingCommissioner.mCommissioningHash.Begin();
    // TODO fuzzedsalt doesnt make sense here, I did it just o  have some data
    pairingCommissioner.mCommissioningHash.AddData(fuzzedSaltSpan);

    CHIP_ERROR err = pairingCommissioner.SetupSpake2p();
    EXPECT_EQ(CHIP_NO_ERROR, err);

    uint8_t serializedWS[kSpake2p_WS_Length * 2] = { 0 };

    err = Spake2pVerifier::ComputeWS(fuzzedPBKDF2Iter, fuzzedSaltSpan, fuzzedSetupPasscode, serializedWS, sizeof(serializedWS));
    EXPECT_EQ(CHIP_NO_ERROR, err);

    err = pairingCommissioner.mSpake2p.BeginProver(nullptr, 0, nullptr, 0, &serializedWS[0], kSpake2p_WS_Length,
                                                   &serializedWS[kSpake2p_WS_Length], kSpake2p_WS_Length);
    EXPECT_EQ(CHIP_NO_ERROR, err);

    // CONSTRUCTING PAKE1 Message, to later it pass it to FuzzHandleMsg1
    const size_t max_msg_len       = TLV::EstimateStructOverhead(FuzzedMAX_Point_Length);
    System::PacketBufferHandle msg = System::PacketBufferHandle::New(max_msg_len);
    ASSERT_FALSE(msg.IsNull());

    System::PacketBufferTLVWriter tlvWriter;
    tlvWriter.Init(std::move(msg));

    TLV::TLVType outerContainerType = TLV::kTLVType_NotSpecified;
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.StartContainer(TLV::AnonymousTag(), TLV::kTLVType_Structure, outerContainerType));

    //   uint8_t X[kMAX_Point_Length];
    // size_t X_len = sizeof(X);

    std::vector<uint8_t> X(FuzzedMAX_Point_Length);
    size_t X_len = X.size();
    std::cout << "X_len = " << X_len << endl;

    constexpr uint8_t kPake1_pA = 1;

    pairingCommissioner.mSpake2p.ComputeRoundOne(nullptr, 0, X.data(), &X_len);
    //    EXPECT_EQ(CHIP_NO_ERROR, pairingCommissioner.mSpake2p.ComputeRoundOne(nullptr, 0, X.data(), &X_len));

    //---***ARRAY VARIANT
    //  EXPECT_EQ(CHIP_NO_ERROR, pairingCommissioner.mSpake2p.ComputeRoundOne(nullptr, 0, X, &X_len));

    // Below fails when FuzzedMAX_Point_Length > 65
    //  EXPECT_EQ(X_len, X.size());

    //---***ARRAY VARIANT
    //    EXPECT_EQ(X_len, sizeof(X));

    tlvWriter.Put(TLV::ContextTag(kPake1_pA), ByteSpan(X.data(), X.size()));
    //    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Put(TLV::ContextTag(kPake1_pA), ByteSpan(X.data(), X.size())));

    //---***ARRAY VARIANT
    // EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Put(TLV::ContextTag(kPake1_pA), ByteSpan(X)));

    tlvWriter.EndContainer(outerContainerType);
    tlvWriter.Finalize(&msg);
    // EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.EndContainer(outerContainerType));
    // EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Finalize(&msg));

    //////////////////////////////////////////////////////////

    /**************************************************************************************** */

    // SHOULD I ADD THIS?
    //    PASELoopBack.CallAllocateSecureSession(sessionManager, pairingCommissioner);

    // VerifyOrReturnError(mLocalMRPConfig.HasValue(), CHIP_ERROR_INCORRECT_STATE);

    /**************************************************************************************************************** */

    //  System::PacketBufferHandle req = System::PacketBufferHandle::NewWithData(buffer.data(), buffer.size());
    //    PASELoopBack.FuzzHandleMsg1(std::move(req), pairingCommissioner, sessionManager);
    ///////////////////////////////////////////
    PASESession pairingAccessory;

    PASETestLoopbackTransportDelegate delegate;
    auto & loopback = GetLoopback();
    loopback.SetLoopbackTransportDelegate(&delegate);
    loopback.mSentMessageCount = 0;

    TestSecurePairingDelegate delegateCommissioner;
    TestSecurePairingDelegate delegateCommissionee;

    // pairingCommissioner.mNextExpectedMsg.SetValue(Protocols::SecureChannel::MsgType::PBKDFParamResponse);

    //   ExchangeContext * contextCommissioner = NewUnauthenticatedExchangeToBob(&pairingCommissioner);

    // One Limitation of using this is that contextAccessory will automatically be an Initiator, while in real-life it should be a
    // responder.
    ExchangeContext * contextAccessory = NewUnauthenticatedExchangeToBob(&pairingAccessory);
    //   ExchangeContext * contextCommissioner = NewUnauthenticatedExchangeToBob(&pairingCommissioner);

    // mFlags is a protected member of ReliableMessageContext, I can not set it from an ExchangeContext
    // contextAccessory->mFlags.Set(Flags::kFlagInitiator, 0);

    // EXPECT_EQ(GetExchangeManager().RegisterUnsolicitedMessageHandlerForType(Protocols::SecureChannel::MsgType::PBKDFParamRequest,
    //                                                                         &pairingAccessory),
    //           CHIP_NO_ERROR);

    PayloadHeader payloadHeaderAccessory;

    // Adding PASESession::Init in order to AllocateSecureSession and have a localsessionID generated for pairingAccessory
    //  pairingAccessory.Init(sessionManager, 0, &delegateCommissionee);

    //  pairingCommissioner.mRole = CryptoContext::SessionRole::kInitiator;
    // pairingAccessory.mRole    = CryptoContext::SessionRole::kResponder;

    // This was done to have an exchange context
    pairingAccessory.mExchangeCtxt.Emplace(*contextAccessory);
    //   pairingCommissioner.mExchangeCtxt.Emplace(*contextCommissioner);

    // This was added because we get a Crash in .mCommissioningHash.AddData if it was called without a Begin
    // TODO: Consider doing a PR for a check inside AddData that an Init(SHA256_Init) did occur (maybe add a flag)
    pairingAccessory.mCommissioningHash.Begin();

    pairingAccessory.mLocalMRPConfig = MakeOptional(ReliableMessageProtocolConfig(
        System::Clock::Milliseconds32(100), System::Clock::Milliseconds32(200), System::Clock::Milliseconds16(4000)));

    payloadHeaderAccessory.SetMessageType(Protocols::SecureChannel::MsgType::PASE_Pake1);
    pairingAccessory.mNextExpectedMsg.SetValue(Protocols::SecureChannel::MsgType::PASE_Pake1);

    pairingAccessory.SetupSpake2p();

    // COMPUTE VERIFIER TO BE ABLE TO PASS IT TO BeginVerifier
    EXPECT_EQ(pairingAccessory.mPASEVerifier.Generate(fuzzedPBKDF2Iter, fuzzedSaltSpan, fuzzedSetupPasscode), CHIP_NO_ERROR);

    pairingAccessory.OnMessageReceived(&pairingAccessory.mExchangeCtxt.Value().Get(), payloadHeaderAccessory, std::move(msg));

    // uint8_t context[kSHA256_Hash_Length] = { 0 };
    // MutableByteSpan contextSpan{ context };
    // pairingAccessory.mCommissioningHash.Finish(contextSpan);

    DrainAndServiceIO();

    // if an error happens in PASESession::ValidateReceivedMessage, I will get a crash related to ReferenceCount(after destructor of
    // exchangecontext)
    // the below solves it
    // contextAccessory->Close();

    // pairingAccessory.HandlePBKDFParamRequest(std::move(msg));
}

void HandleMsg1(const uint32_t fuzzedSetupPasscode, const vector<uint8_t> & fuzzedSalt, uint32_t fuzzedPBKDF2Iter,
                const uint32_t FuzzedMAX_Point_Length)
{
    TestPASESession PASELoopBack;
    PASELoopBack.FuzzHandleMsg1(fuzzedSetupPasscode, fuzzedSalt, fuzzedPBKDF2Iter, FuzzedMAX_Point_Length);
}

// In This FuzzTest, we will construct a PAKE1 Message with a fuzzed TLV length, and send it through a PASESession
FUZZ_TEST(FuzzPASE_PW, HandleMsg1)
    .WithDomains(
        // Setup Code Range
        InRange(00000000, 99999998),
        // Salt accepted range
        Arbitrary<vector<uint8_t>>().WithMinSize(kSpake2p_Min_PBKDF_Salt_Length).WithMaxSize(kSpake2p_Max_PBKDF_Salt_Length),
        // PBKDF2Iterations count range
        InRange(kSpake2p_Min_PBKDF_Iterations, kSpake2p_Max_PBKDF_Iterations),
        // FuzzedMAX_Point_Length
        InRange(0, 60005));

/*-+-+-++++++++----------+++++++++++++-----------------------------++++++++++++++----------++++++++++++----------+++++++++++++++*/
// In This Test we start by constructing a Fuzzed PAKE2 Message, then sending it into a PASE Session.
// Limitation of Test, since the pB and cB are fuzzed, the Function gets blocked in ComputerRoundTwo
void TestPASESession::FuzzHandleMsg2(const uint32_t fuzzedSetupPasscode, const vector<uint8_t> & fuzzedSalt,
                                     uint32_t fuzzedPBKDF2Iter, const uint32_t FuzzedMAX_Point_Length,
                                     const uint32_t FuzzedMAX_Hash_Length, ByteSpan & pB, ByteSpan & cB)
{

    TemporarySessionManager sessionManager(*this);

    // Commissioner: The Receiver of PAKE2
    PASESession pairingCommissioner;
    // Accessory: The Sender of PAKE2
    PASESession pairingAccessory;

    ByteSpan fuzzedSaltSpan(fuzzedSalt.data(), fuzzedSalt.size());

    /*************************** Prepare Accessory for Spake2+ ***************************/
    pairingAccessory.mCommissioningHash.Begin();
    // TODO fuzzedsalt doesnt make sense here, I did it just o  have some data
    pairingAccessory.mCommissioningHash.AddData(fuzzedSaltSpan);
    EXPECT_EQ(CHIP_NO_ERROR, pairingAccessory.SetupSpake2p());

    // Below Steps take place in HandleMsg1
    //  COMPUTE VERIFIER TO BE ABLE TO PASS IT TO BeginVerifier
    EXPECT_EQ(pairingAccessory.mPASEVerifier.Generate(fuzzedPBKDF2Iter, fuzzedSaltSpan, fuzzedSetupPasscode), CHIP_NO_ERROR);

    EXPECT_EQ(CHIP_NO_ERROR,
              pairingAccessory.mSpake2p.BeginVerifier(nullptr, 0, nullptr, 0, pairingAccessory.mPASEVerifier.mW0, kP256_FE_Length,
                                                      pairingAccessory.mPASEVerifier.mL, kP256_Point_Length));

    /*************************** Prepare Commissioner for Spake2+ ***************************/

    // This was added because we get a Crash in .mCommissioningHash.AddData if it was called without a Begin
    // TODO: Consider doing a PR for a check inside AddData that an Init(SHA256_Init) did occur (maybe add a flag)
    EXPECT_EQ(CHIP_NO_ERROR, pairingCommissioner.mCommissioningHash.Begin());
    EXPECT_EQ(CHIP_NO_ERROR, pairingCommissioner.mCommissioningHash.AddData(fuzzedSaltSpan));
    EXPECT_EQ(CHIP_NO_ERROR, pairingCommissioner.SetupSpake2p());

    /*************************** Prepare Commissioner for Receiving PAKE2 Message ***************************/

    uint8_t serializedWS[kSpake2p_WS_Length * 2] = { 0 };

    EXPECT_EQ(
        CHIP_NO_ERROR,
        Spake2pVerifier::ComputeWS(fuzzedPBKDF2Iter, fuzzedSaltSpan, fuzzedSetupPasscode, serializedWS, sizeof(serializedWS)));

    EXPECT_EQ(CHIP_NO_ERROR,
              pairingCommissioner.mSpake2p.BeginProver(nullptr, 0, nullptr, 0, &serializedWS[0], kSpake2p_WS_Length,
                                                       &serializedWS[kSpake2p_WS_Length], kSpake2p_WS_Length));

    // The Commissioner should have already called ComputeRoundOne As part of the Exchange  (and consequently have state =
    // CHIP_SPAKE2P_STATE::R1), the computed values are not used.
    uint8_t X[kMAX_Point_Length];
    size_t X_len = sizeof(X);
    pairingCommissioner.mSpake2p.ComputeRoundOne(nullptr, 0, X, &X_len);

    /*************************** Prepare Accessory for Sending PAKE2 Message ***************************/

    uint8_t Y[kMAX_Point_Length];
    size_t Y_len = sizeof(Y);

    uint8_t verifier[kMAX_Hash_Length];
    size_t verifier_len = kMAX_Hash_Length;

    // Remove the two below, since I fuzz Y and Verifier instead of compute them
    pairingAccessory.mSpake2p.ComputeRoundOne(X, X_len, Y, &Y_len);
    pairingAccessory.mSpake2p.ComputeRoundTwo(X, X_len, verifier, &verifier_len);
    /*********************** CONSTRUCTING Fuzzed PAKE2 Message, to later inject it into PASE Session *********************/

    // Y is equivalent to pB, it should have been computed
    constexpr uint8_t kPake2_pB = 1;
    constexpr uint8_t kPake2_cB = 2;

    const size_t max_msg_len        = TLV::EstimateStructOverhead(pB.size(), cB.size());
    System::PacketBufferHandle msg2 = System::PacketBufferHandle::New(max_msg_len);
    ASSERT_FALSE(msg2.IsNull());

    System::PacketBufferTLVWriter tlvWriter;
    tlvWriter.Init(std::move(msg2));

    TLV::TLVType outerContainerType = TLV::kTLVType_NotSpecified;
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.StartContainer(TLV::AnonymousTag(), TLV::kTLVType_Structure, outerContainerType));
    //  EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Put(TLV::ContextTag(kPake2_pB), ByteSpan(Y)));
    //  EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Put(TLV::ContextTag(kPake2_cB), ByteSpan(verifier, verifier_len)));
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Put(TLV::ContextTag(kPake2_pB), pB));
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Put(TLV::ContextTag(kPake2_cB), cB));
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.EndContainer(outerContainerType));
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Finalize(&msg2));

    // After PAKE2 is sent, the pairingAccessory will expect a StatusReport
    pairingAccessory.mNextExpectedMsg.SetValue(Protocols::SecureChannel::MsgType::PASE_Pake3);

    /**************************************************************************************** */

    // SHOULD I ADD THIS?
    //    PASELoopBack.CallAllocateSecureSession(sessionManager, pairingCommissioner);
    CallAllocateSecureSession(sessionManager, pairingCommissioner);

    // VerifyOrReturnError(mLocalMRPConfig.HasValue(), CHIP_ERROR_INCORRECT_STATE);

    /**************************************************************************************************************** */

    //  System::PacketBufferHandle req = System::PacketBufferHandle::NewWithData(buffer.data(), buffer.size());
    //    PASELoopBack.FuzzHandleMsg1(std::move(req), pairingCommissioner, sessionManager);
    ///////////////////////////////////////////

    PASETestLoopbackTransportDelegate delegate;
    auto & loopback = GetLoopback();
    loopback.SetLoopbackTransportDelegate(&delegate);
    loopback.mSentMessageCount = 0;

    TestSecurePairingDelegate delegateCommissioner;
    TestSecurePairingDelegate delegateCommissionee;

    ExchangeContext * contextCommissioner = NewUnauthenticatedExchangeToBob(&pairingCommissioner);

    // EXPECT_EQ(GetExchangeManager().RegisterUnsolicitedMessageHandlerForType(Protocols::SecureChannel::MsgType::PBKDFParamRequest,
    //                                                                         &pairingAccessory),
    //           CHIP_NO_ERROR);

    PayloadHeader payloadHeaderCommissioner;

    // Adding PASESession::Init in order to AllocateSecureSession and have a localsessionID generated for pairingAccessory
    //  pairingAccessory.Init(sessionManager, 0, &delegateCommissionee);
    //    pairingCommissioner.Init(sessionManager, 0, &delegateCommissioner);
    //  pairingCommissioner.mRole = CryptoContext::SessionRole::kInitiator;
    // pairingAccessory.mRole    = CryptoContext::SessionRole::kResponder;

    // This was done to have an exchange context
    pairingCommissioner.mExchangeCtxt.Emplace(*contextCommissioner);
    //   pairingCommissioner.mExchangeCtxt.Emplace(*contextCommissioner);

    pairingCommissioner.mLocalMRPConfig = MakeOptional(ReliableMessageProtocolConfig(
        System::Clock::Milliseconds32(100), System::Clock::Milliseconds32(200), System::Clock::Milliseconds16(4000)));

    // Below two lines are done in order for OnMessageReceived to call HandleMsg2_and_SendMsg3
    payloadHeaderCommissioner.SetMessageType(Protocols::SecureChannel::MsgType::PASE_Pake2);
    pairingCommissioner.mNextExpectedMsg.SetValue(Protocols::SecureChannel::MsgType::PASE_Pake2);

    pairingCommissioner.OnMessageReceived(&pairingCommissioner.mExchangeCtxt.Value().Get(), payloadHeaderCommissioner,
                                          std::move(msg2));

    DrainAndServiceIO();

    // if an error happens in PASESession::ValidateReceivedMessage, I will get a crash related to ReferenceCount(after destructor of
    // exchangecontext)
    // the below solves it
    // contextAccessory->Close();
}

void HandleMsg2(const uint32_t fuzzedSetupPasscode, const vector<uint8_t> & fuzzedSalt, uint32_t fuzzedPBKDF2Iter,
                const uint32_t FuzzedMAX_Point_Length, const uint32_t FuzzedMAX_Hash_Length, const vector<uint8_t> & Y,
                const vector<uint8_t> & verifier)
{
    TestPASESession PASELoopBack;
    vector<uint8_t> YY{ 0x04 };
    YY.insert(YY.end(), Y.begin(), Y.end());

    ByteSpan pBspan{ YY.data(), YY.size() };
    ByteSpan cBspan{ verifier.data(), verifier.size() };

    PASELoopBack.FuzzHandleMsg2(fuzzedSetupPasscode, fuzzedSalt, fuzzedPBKDF2Iter, FuzzedMAX_Point_Length, FuzzedMAX_Hash_Length,
                                pBspan, cBspan);
}

// In This FuzzTest, we will construct a PAKE2 Message with fuzzed TLV lengths, and send it through a PASESession
FUZZ_TEST(FuzzPASE_PW, HandleMsg2)
    .WithDomains(
        // Setup Code Range
        InRange(00000000, 99999998),
        // Salt accepted range
        Arbitrary<vector<uint8_t>>().WithMinSize(kSpake2p_Min_PBKDF_Salt_Length).WithMaxSize(kSpake2p_Max_PBKDF_Salt_Length),
        // PBKDF2Iterations count range
        InRange(kSpake2p_Min_PBKDF_Iterations, kSpake2p_Max_PBKDF_Iterations),
        // FuzzedMAX_Point_Length
        InRange(0, 60005),
        //  FuzzedMAX_Hash_Length
        InRange(32, 32),
        //  Fuzzed pB (Y in Code)
        // Arbitrary<vector<uint8_t>>(),
        Arbitrary<vector<uint8_t>>().WithMinSize(64).WithMaxSize(64),

        // Fuzzed cB (verifier in Code)
        Arbitrary<vector<uint8_t>>().WithMinSize(32).WithMaxSize(32));
// Arbitrary<vector<uint8_t>>());

/*-+-+-++++++++----------+++++++++++++-----------------------------++++++++++++++----------++++++++++++----------+++++++++++++++*/
// In This Test we start by constructing a Fuzzed PAKE3 Message, then sending it into a PASE Session.
void TestPASESession::FuzzHandleMsg3(const uint32_t fuzzedSetupPasscode, const vector<uint8_t> & fuzzedSalt,
                                     uint32_t fuzzedPBKDF2Iter, const uint32_t FuzzedMAX_Point_Length,
                                     const uint32_t FuzzedMAX_Hash_Length, ByteSpan & cB)
{

    TemporarySessionManager sessionManager(*this);

    // Commissioner: The Sender of PAKE3
    PASESession pairingCommissioner;
    // Accessory: The Receiver of PAKE3
    PASESession pairingAccessory;

    ByteSpan fuzzedSaltSpan(fuzzedSalt.data(), fuzzedSalt.size());

    /*************************** Prepare Accessory for Spake2+ ***************************/
    pairingAccessory.mCommissioningHash.Begin();
    // TODO fuzzedsalt doesnt make sense here, I did it just o  have some data
    pairingAccessory.mCommissioningHash.AddData(fuzzedSaltSpan);
    EXPECT_EQ(CHIP_NO_ERROR, pairingAccessory.SetupSpake2p());

    // Below Steps take place in HandleMsg1
    //  COMPUTE VERIFIER TO BE ABLE TO PASS IT TO BeginVerifier
    EXPECT_EQ(pairingAccessory.mPASEVerifier.Generate(fuzzedPBKDF2Iter, fuzzedSaltSpan, fuzzedSetupPasscode), CHIP_NO_ERROR);

    EXPECT_EQ(CHIP_NO_ERROR,
              pairingAccessory.mSpake2p.BeginVerifier(nullptr, 0, nullptr, 0, pairingAccessory.mPASEVerifier.mW0, kP256_FE_Length,
                                                      pairingAccessory.mPASEVerifier.mL, kP256_Point_Length));

    /*************************** Prepare Commissioner for Spake2+ ***************************/

    // This was added because we get a Crash in .mCommissioningHash.AddData if it was called without a Begin
    // TODO: Consider doing a PR for a check inside AddData that an Init(SHA256_Init) did occur (maybe add a flag)
    EXPECT_EQ(CHIP_NO_ERROR, pairingCommissioner.mCommissioningHash.Begin());
    EXPECT_EQ(CHIP_NO_ERROR, pairingCommissioner.mCommissioningHash.AddData(fuzzedSaltSpan));
    EXPECT_EQ(CHIP_NO_ERROR, pairingCommissioner.SetupSpake2p());

    /*************************** Prepare Commissioner for Receiving PAKE2 Message ***************************/

    uint8_t serializedWS[kSpake2p_WS_Length * 2] = { 0 };

    EXPECT_EQ(
        CHIP_NO_ERROR,
        Spake2pVerifier::ComputeWS(fuzzedPBKDF2Iter, fuzzedSaltSpan, fuzzedSetupPasscode, serializedWS, sizeof(serializedWS)));

    EXPECT_EQ(CHIP_NO_ERROR,
              pairingCommissioner.mSpake2p.BeginProver(nullptr, 0, nullptr, 0, &serializedWS[0], kSpake2p_WS_Length,
                                                       &serializedWS[kSpake2p_WS_Length], kSpake2p_WS_Length));

    // The Commissioner should have already called ComputeRoundOne As part of the Exchange  (and consequently have state =
    // CHIP_SPAKE2P_STATE::R1), the computed values are not used.
    uint8_t X[kMAX_Point_Length];
    size_t X_len = sizeof(X);
    pairingCommissioner.mSpake2p.ComputeRoundOne(nullptr, 0, X, &X_len);

    /*************************** Prepare Accessory for Sending PAKE2 Message ***************************/

    uint8_t Y[kMAX_Point_Length];
    size_t Y_len = sizeof(Y);

    uint8_t verifier[kMAX_Hash_Length];
    size_t verifier_len = kMAX_Hash_Length;

    pairingAccessory.mSpake2p.ComputeRoundOne(X, X_len, Y, &Y_len);
    pairingAccessory.mSpake2p.ComputeRoundTwo(X, X_len, verifier, &verifier_len);
    /*********************** CONSTRUCTING Fuzzed PAKE2 Message, to later inject it into PASE Session *********************/

    constexpr uint8_t kPake2_cB = 1;

    const size_t max_msg_len        = TLV::EstimateStructOverhead(cB.size());
    System::PacketBufferHandle msg3 = System::PacketBufferHandle::New(max_msg_len);
    ASSERT_FALSE(msg3.IsNull());

    System::PacketBufferTLVWriter tlvWriter;
    tlvWriter.Init(std::move(msg3));

    TLV::TLVType outerContainerType = TLV::kTLVType_NotSpecified;
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.StartContainer(TLV::AnonymousTag(), TLV::kTLVType_Structure, outerContainerType));
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Put(TLV::ContextTag(kPake2_cB), cB));
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.EndContainer(outerContainerType));
    EXPECT_EQ(CHIP_NO_ERROR, tlvWriter.Finalize(&msg3));

    // After PAKE3 is sent, the pairingCommissioner will expect a StatusReport
    pairingCommissioner.mNextExpectedMsg.SetValue(Protocols::SecureChannel::MsgType::StatusReport);

    /**************************************************************************************** */

    // SHOULD I ADD THIS?
    //    PASELoopBack.CallAllocateSecureSession(sessionManager, pairingCommissioner);
    CallAllocateSecureSession(sessionManager, pairingCommissioner);

    // VerifyOrReturnError(mLocalMRPConfig.HasValue(), CHIP_ERROR_INCORRECT_STATE);

    /**************************************************************************************************************** */

    //  System::PacketBufferHandle req = System::PacketBufferHandle::NewWithData(buffer.data(), buffer.size());
    //    PASELoopBack.FuzzHandleMsg1(std::move(req), pairingCommissioner, sessionManager);
    ///////////////////////////////////////////

    PASETestLoopbackTransportDelegate delegate;
    auto & loopback = GetLoopback();
    loopback.SetLoopbackTransportDelegate(&delegate);
    loopback.mSentMessageCount = 0;

    TestSecurePairingDelegate delegateCommissioner;
    TestSecurePairingDelegate delegateCommissionee;

    ExchangeContext * contextAccessory = NewUnauthenticatedExchangeToBob(&pairingAccessory);

    // EXPECT_EQ(GetExchangeManager().RegisterUnsolicitedMessageHandlerForType(Protocols::SecureChannel::MsgType::PBKDFParamRequest,
    //                                                                         &pairingAccessory),
    //           CHIP_NO_ERROR);

    PayloadHeader payloadHeaderAccessory;

    // Adding PASESession::Init in order to AllocateSecureSession and have a localsessionID generated for pairingAccessory
    //  pairingAccessory.Init(sessionManager, 0, &delegateCommissionee);
    //    pairingCommissioner.Init(sessionManager, 0, &delegateCommissioner);
    //  pairingCommissioner.mRole = CryptoContext::SessionRole::kInitiator;
    // pairingAccessory.mRole    = CryptoContext::SessionRole::kResponder;

    // This was done to have an exchange context
    pairingAccessory.mExchangeCtxt.Emplace(*contextAccessory);
    //   pairingCommissioner.mExchangeCtxt.Emplace(*contextCommissioner);

    pairingAccessory.mLocalMRPConfig = MakeOptional(ReliableMessageProtocolConfig(
        System::Clock::Milliseconds32(100), System::Clock::Milliseconds32(200), System::Clock::Milliseconds16(4000)));

    // Below two lines are done in order for OnMessageReceived to call HandleMsg3
    payloadHeaderAccessory.SetMessageType(Protocols::SecureChannel::MsgType::PASE_Pake3);
    pairingAccessory.mNextExpectedMsg.SetValue(Protocols::SecureChannel::MsgType::PASE_Pake3);

    pairingAccessory.OnMessageReceived(&pairingAccessory.mExchangeCtxt.Value().Get(), payloadHeaderAccessory, std::move(msg3));

    DrainAndServiceIO();

    // if an error happens in PASESession::ValidateReceivedMessage, I will get a crash related to ReferenceCount(after destructor of
    // exchangecontext)
    // the below solves it
    // contextAccessory->Close();
}

void HandleMsg3(const uint32_t fuzzedSetupPasscode, const vector<uint8_t> & fuzzedSalt, uint32_t fuzzedPBKDF2Iter,
                const uint32_t FuzzedMAX_Point_Length, const uint32_t FuzzedMAX_Hash_Length, const vector<uint8_t> & verifier)
{
    TestPASESession PASELoopBack;

    //  ByteSpan pBspan{ Y.data(), Y.size() };
    ByteSpan cBspan{ verifier.data(), verifier.size() };

    PASELoopBack.FuzzHandleMsg3(fuzzedSetupPasscode, fuzzedSalt, fuzzedPBKDF2Iter, FuzzedMAX_Point_Length, FuzzedMAX_Hash_Length,
                                cBspan);
}

// In This FuzzTest, we will construct a PAKE2 Message with fuzzed TLV lengths, and send it through a PASESession
FUZZ_TEST(FuzzPASE_PW, HandleMsg3)
    .WithDomains(
        // Setup Code Range
        InRange(00000000, 99999998),
        // Salt accepted range
        Arbitrary<vector<uint8_t>>().WithMinSize(kSpake2p_Min_PBKDF_Salt_Length).WithMaxSize(kSpake2p_Max_PBKDF_Salt_Length),
        // PBKDF2Iterations count range
        InRange(kSpake2p_Min_PBKDF_Iterations, kSpake2p_Max_PBKDF_Iterations),
        // FuzzedMAX_Point_Length
        InRange(0, 60005),
        //  FuzzedMAX_Hash_Length
        InRange(32, 32),
        //  Fuzzed pB (Y in Code)
        // Arbitrary<vector<uint8_t>>(),
        //   Arbitrary<vector<uint8_t>>().WithMinSize(65).WithMaxSize(65),

        // Fuzzed cB (verifier in Code)
        Arbitrary<vector<uint8_t>>().WithMinSize(32).WithMaxSize(32));
// Arbitrary<vector<uint8_t>>());
// Arbitrary<vector<uint8_t>>());

} // namespace Fuzzchip
