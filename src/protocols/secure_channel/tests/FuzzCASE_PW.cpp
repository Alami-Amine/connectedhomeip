#include <algorithm> // std::copy
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

#include <credentials/tests/CHIPCert_test_vectors.h>

namespace chip {
namespace Testing {

using namespace std;

using namespace Crypto;
using namespace Credentials;
using namespace fuzztest;
using namespace Transport;
using namespace Messaging;
using namespace System::Clock::Literals;
using namespace TLV;

// TODO: should i put this in CASESession.h

inline constexpr uint8_t kInitiatorRandomTag    = 1;
inline constexpr uint8_t kInitiatorSessionIdTag = 2;
inline constexpr uint8_t kDestinationIdTag      = 3;
inline constexpr uint8_t kInitiatorPubKeyTag    = 4;
inline constexpr uint8_t kInitiatorMRPParamsTag = 5;
inline constexpr uint8_t kResumptionIDTag       = 6;
inline constexpr uint8_t kResume1MICTag         = 7;

// TODO fuzz?
NodeId Node01_01 = 0xDEDEDEDE00010001;

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

class FuzzCASESession : public CASESession
{
public:
    using CASESession::HandleSigma3Data;
    using CASESession::ParsedSigma2;

    using CASESession::ParseSigma2;
    using CASESession::ParseSigma3;
    using CASESession::ParseSigma3TBEData;

    System::PacketBufferHandle GenerateSigma1(const vector<uint8_t> & InitiatorRandom, uint32_t fuzzInitiatorSessionId,
                                              FabricId fuzzedFabricId, const vector<uint8_t> & IPK,
                                              const vector<uint8_t> & rootPubKey);
    void HandleSigma1(const vector<uint8_t> & InitiatorRandom, uint32_t fuzzInitiatorSessionId, FabricId fuzzedFabricId,
                      const vector<uint8_t> & IPK, const vector<uint8_t> & rootPubKey);

    void ParseSigma1(const vector<uint8_t> & InitiatorRandom, uint32_t fuzzInitiatorSessionId,
                     const vector<uint8_t> & destinationIdentifier, FabricId fuzzedFabricId, const vector<uint8_t> & IPK,
                     const vector<uint8_t> & rootPubKey, const vector<uint8_t> & fuzzResumptionID,
                     const vector<uint8_t> & fuzzInitiatorResumeMIC, bool fuzzSessionResumptionRequested,
                     const vector<uint8_t> & garbagePayload);

    void HandleSigma2(const vector<uint8_t> & InitiatorRandom, uint32_t fuzzInitiatorSessionId, FabricId fuzzedFabricId,
                      const vector<uint8_t> & IPK, const vector<uint8_t> & rootPubKey);

    void EncodeParseSigma1RoundTrip(const vector<uint8_t> & InitiatorRandom, uint32_t fuzzInitiatorSessionId,
                                    const vector<uint8_t> & destinationIdentifier, FabricId fuzzedFabricId,
                                    const vector<uint8_t> & IPK, const vector<uint8_t> & rootPubKey,
                                    const vector<uint8_t> & fuzzResumptionID, const vector<uint8_t> & fuzzInitiatorResumeMIC,
                                    bool fuzzSessionResumptionRequested);

    // void ParseSigma2(const vector<uint8_t> & fuzzResponderRandom, uint16_t fuzzResponderSessionId,
    //                  const vector<uint8_t> & fuzzRootPubKey, const vector<uint8_t> & fuzzEncrypted2,
    //                  const vector<uint8_t> & fuzzSessionParameters, const vector<uint8_t> & garbagePayload);

    void EncodeParseSigma2RoundTrip(const vector<uint8_t> & fuzzResponderRandom, uint32_t fuzzResponderSessionId,
                                    const vector<uint8_t> & fuzzRootPubKey, const vector<uint8_t> fuzzEncrypted2);

    void ParseSigma2TBE(const vector<uint8_t> & responderNOC, vector<uint8_t> responderICAC, const vector<uint8_t> & signature,
                        const vector<uint8_t> & resumptionID, const vector<uint8_t> & garbagePayload, size_t bitflipIndex,
                        size_t bitflipPosition);

    void HandleSigma3b(const std::string & fuzzResponderNOC, const std::string & fuzzResponderICAC,
                       const std::string & fuzzFabricRCAC, const vector<uint8_t> & fuzzMsg3TBSData,
                       const vector<uint8_t> & fuzzTbs3Signature, const vector<uint8_t> & garbagePayload, size_t bitflipIndex,
                       size_t bitflipPosition, FabricId fuzzFabricId, const Credentials::ValidationContext & fuzzValidContext);

    // Helper Functions
    CHIP_ERROR EncodeSigma1Mock(System::PacketBufferHandle & msg, CASESession::EncodeSigma1Inputs & inputParams,
                                ByteSpan & initiatorEphPubKey);

    // CHIP_ERROR EncodeSigma2Mock(System::PacketBufferHandle & msg, const vector<uint8_t> & fuzzResponderRandom,
    //                             uint32_t fuzzResponderSessionId, const vector<uint8_t> & fuzzRootPubKey,
    //                             const vector<uint8_t> & fuzzEncrypted2, const vector<uint8_t> & fuzzSessionParameters);

    // CHIP_ERROR EncodeSigma2TBEDataMock(System::PacketBufferHandle & msg, ByteSpan & responderNOC, ByteSpan & responderICAC,
    //    ByteSpan & signature, ByteSpan & resumptionID);
};

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
    size_t dataLen = TLV::EstimateStructOverhead(fuzzInitiatorRandom.size(),           // initiatorRandom
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
    msg_R1 = System::PacketBufferHandle::New(dataLen);
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
        //        FabricIndex zz = 44;

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

    // TODO: no need for this?
    EphemeralKey->Clear();

    Platform::Delete<Crypto::P256Keypair>(EphemeralKey);
}

void HandleSigma1(const vector<uint8_t> & InitiatorRandom, uint32_t fuzzInitiatorSessionId, FabricId fuzzedFabricId,
                  const vector<uint8_t> & IPK, const vector<uint8_t> & rootPubKey)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);

    FuzzCASESession CaseSession;
    CaseSession.HandleSigma1(InitiatorRandom, fuzzInitiatorSessionId, fuzzedFabricId, IPK, rootPubKey);
    chip::Platform::MemoryShutdown();
}

FUZZ_TEST(FuzzCASE, HandleSigma1)
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
    size_t dataLen = TLV::EstimateStructOverhead(fuzzInitiatorRandom.size(),           // initiatorRandom
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
    msg_R1 = System::PacketBufferHandle::New(dataLen);
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
        //    FabricIndex zz = 44;

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

CHIP_ERROR FuzzCASESession::EncodeSigma1Mock(System::PacketBufferHandle & msg, CASESession::EncodeSigma1Inputs & inputParams,
                                             ByteSpan & initiatorEphPubKey)
{

    size_t dataLen = TLV::EstimateStructOverhead(inputParams.initiatorRandom.size(),     // initiatorRandom
                                                 sizeof(inputParams.initiatorSessionId), // initiatorSessionId
                                                 inputParams.destinationId.size(),       // destinationId
                                                 initiatorEphPubKey.size(),              // InitiatorEphPubKey,
                                                 SessionParameters::kEstimatedTLVSize,   // initiatorSessionParams
                                                 inputParams.resumptionId.size(),        // resumptionId
                                                 inputParams.initiatorResumeMIC.size()   // initiatorResumeMIC
    );

    msg = System::PacketBufferHandle::New(dataLen);
    VerifyOrReturnError(!msg.IsNull(), CHIP_ERROR_NO_MEMORY);

    System::PacketBufferTLVWriter tlvWriter;
    TLV::TLVType outerContainerType = TLV::kTLVType_NotSpecified;

    tlvWriter.Init(std::move(msg));
    ReturnErrorOnFailure(tlvWriter.StartContainer(TLV::AnonymousTag(), TLV::kTLVType_Structure, outerContainerType));
    ReturnErrorOnFailure(tlvWriter.Put(TLV::ContextTag(kInitiatorRandomTag), inputParams.initiatorRandom));
    ReturnErrorOnFailure(tlvWriter.Put(TLV::ContextTag(kInitiatorSessionIdTag), inputParams.initiatorSessionId));
    ReturnErrorOnFailure(tlvWriter.Put(TLV::ContextTag(kDestinationIdTag), inputParams.destinationId));

    // // TODO Pass this in the struct?
    // VerifyOrReturnError(inputParams.pEphPubKey != nullptr, CHIP_ERROR_INCORRECT_STATE);
    // ReturnErrorOnFailure(tlvWriter.PutBytes(TLV::ContextTag(kInitiatorPubKeyTag), *inputParams.pEphPubKey,
    //                                         static_cast<uint32_t>(inputParams.pEphPubKey->Length())));

    // VerifyOrReturnError(inputParams.pEphPubKey != nullptr, CHIP_ERROR_INCORRECT_STATE);
    ReturnErrorOnFailure(
        tlvWriter.PutBytes(TLV::ContextTag(kInitiatorPubKeyTag), initiatorEphPubKey.data(), initiatorEphPubKey.size()));

    VerifyOrReturnError(inputParams.initiatorMrpConfig != nullptr, CHIP_ERROR_INCORRECT_STATE);
    ReturnErrorOnFailure(
        CASESession::EncodeSessionParameters(TLV::ContextTag(kInitiatorMRPParamsTag), *inputParams.initiatorMrpConfig, tlvWriter));

    // TODO, should I seperate this into different if statements, one for each TLV element (check by length or something?) ? just
    // like done in UnitTest Sigma1Parse
    if (inputParams.sessionResumptionRequested)
    {
        ReturnErrorOnFailure(tlvWriter.Put(TLV::ContextTag(kResumptionIDTag), inputParams.resumptionId));
        ReturnErrorOnFailure(tlvWriter.Put(TLV::ContextTag(kResume1MICTag), inputParams.initiatorResumeMIC));
    }

    ReturnErrorOnFailure(tlvWriter.EndContainer(outerContainerType));
    ReturnErrorOnFailure(tlvWriter.Finalize(&msg));

    return CHIP_NO_ERROR;
}
// This Test looks ok
void FuzzCASESession::ParseSigma1(const vector<uint8_t> & InitiatorRandom, uint32_t fuzzInitiatorSessionId,
                                  const vector<uint8_t> & destinationIdentifier, FabricId fuzzedFabricId,
                                  const vector<uint8_t> & IPK, const vector<uint8_t> & rootPubKey,
                                  const vector<uint8_t> & fuzzResumptionID, const vector<uint8_t> & fuzzInitiatorResumeMIC,
                                  bool fuzzSessionResumptionRequested, const vector<uint8_t> & garbagePayload)
{

    /*CONSTRUCT SIGMA1*/
    //  System::PacketBufferHandle msg = GenerateSigma1(InitiatorRandom, fuzzInitiatorSessionId, fuzzedFabricId, IPK, rootPubKey);

    ByteSpan fuzzInitiatorRandom(InitiatorRandom.data(), InitiatorRandom.size());
    // ToDo consider removing IPK from all these tests
    ByteSpan fuzzedIPK(IPK.data(), IPK.size());
    ByteSpan fuzzedRootPubKey(rootPubKey.data(), rootPubKey.size());

    CASESession pairingCommissioner;
    CASESession pairingAccessory;

    /*********************************Constructing Sigma1*********************************/
    CASESession::EncodeSigma1Inputs encodeParams;
    encodeParams.initiatorRandom    = fuzzInitiatorRandom;
    encodeParams.initiatorSessionId = fuzzInitiatorSessionId;

    if (fuzzSessionResumptionRequested)
    {
        encodeParams.sessionResumptionRequested = true;
        // TODO : make all encodeParams initialisations similar to the below ones
        encodeParams.resumptionId       = ByteSpan(fuzzResumptionID.data(), fuzzResumptionID.size());
        encodeParams.initiatorResumeMIC = ByteSpan(fuzzInitiatorResumeMIC.data(), fuzzInitiatorResumeMIC.size());
    }

    // TODO, how will I generate Public Key
    // TEMORARY WAY
    // Generate an ephemeral keypair

    // // TODO: this is what works , but not fuzzable
    // Crypto::P256Keypair * EphemeralKey = nullptr;
    // EphemeralKey                       = Platform::New<Crypto::P256Keypair>();
    // EXPECT_NE(EphemeralKey, nullptr);
    // EXPECT_EQ(CHIP_NO_ERROR, EphemeralKey->Initialize(ECPKeyTarget::ECDH));
    // encodeParams.pEphPubKey = &EphemeralKey->Pubkey();

    // *encodeParams.pEphPubKey = fuzzedRootPubKey.data();
    //   memcpy(encodeParams.pEphPubKey->Bytes(), fuzzedRootPubKey.data(), fuzzedRootPubKey.size());

    // Allocate memory for a new public key
    // encodeParams.pEphPubKey = new Crypto::P256PublicKey();

    // Copy the bytes into the newly allocated public key
    //  memcpy(encodeParams.pEphPubKey->Bytes(), fuzzedRootPubKey.data(), fuzzedRootPubKey.size());

    // encodeParams.pEphPubKey = SafePointerCast<Crypto::P256PublicKey *>(&fuzzedRootPubKey),

    // P256PublicKey
    // encodeParams.pEphPubKey = Bytespan(fuzzedRootPubKey.data(), fuzzedRootPubKey.size())

    // DestinationID
    //  uint8_t destinationIdentifier[kSHA256_Hash_Length] = { 0 };
    // MutableByteSpan destinationIdSpan(destinationIdentifier);

    // EXPECT_EQ(CHIP_NO_ERROR,
    //           GenerateCaseDestinationId(fuzzedIPK, encodeParams.initiatorRandom,
    //                                     // temporary, till i figure out
    //                                     fuzzedRootPubKey, fuzzedFabricId, Node01_01, destinationIdSpan));

    encodeParams.destinationId = ByteSpan(destinationIdentifier.data(), destinationIdentifier.size());
    ReliableMessageProtocolConfig LocalMRPConfig(System::Clock::Milliseconds32(100), System::Clock::Milliseconds32(200),
                                                 System::Clock::Milliseconds16(4000));
    encodeParams.initiatorMrpConfig = &LocalMRPConfig;
    // encodeParams.mrpConfig = nullptr;

    // Encoding Sigma1 into PacketBufferHandle

    // FixedByteSpan<65> EphemeralTest(*EphemeralKey->Pubkey().Bytes());
    // mEphemeralKey->Pubkey() = EphemeralTest;

    ByteSpan PubKey(fuzzedRootPubKey.data(), fuzzedRootPubKey.size());

    System::PacketBufferHandle msg;

    EXPECT_EQ(CHIP_NO_ERROR, EncodeSigma1Mock(msg, encodeParams, PubKey));

    // TODO: or use the API for this, ReleaseEphemeralKeypair
    // EphemeralKey->Clear();
    // Platform::Delete<Crypto::P256Keypair>(EphemeralKey);

    System::PacketBufferTLVReader tlvReader;

    // EXPECT_FALSE(msg.IsNull());

    // THE BELOW CONDITION MIGHT BE NEEDED IF EncodeSigma1Mock could fail
    // if (msg.IsNull())
    // {
    //     // In case EncodeSigma1 fails, we need to release buffers owned by the PacketBufferHandle `msg`
    //     // msg = nullptr;
    //     // We should skip the iteration when EncodeSigma1 fails
    //     GTEST_SKIP() << "skipping because msg is null";
    // }
    tlvReader.Init(std::move(msg));

    // uint16_t initiatorSessionId;
    // ByteSpan destinationIdentifier;
    // ByteSpan initiatorRandom;

    // bool sessionResumptionRequested = false;
    // bool InitiatorMRPParamsPresent  = false;
    // ByteSpan resumptionId;
    // ByteSpan resume1MIC;
    // ByteSpan initiatorPubKey;

    // TODO: PARSERSIGMA1 NEEDS TO HAVE an EXCHANGE CONTEXT and to have an exchange context we need to have loopbackmessaging (or
    // sessions and other stuff)
    // TODO: SO LIEK THIS, I WILL GET A VERIFYORDIE RELATED TO MISSSING CONTEXT

    //  ExchangeContext * contextAccessory = NewUnauthenticatedExchangeToBob(&pairingAccessory);

    // pairingAccessory.mExchangeCtxt.Emplace(*contextAccessory);
    // EXPECT_EQ(CHIP_NO_ERROR, pairingAccessory.ParseSigma1(tlvReader, parsedMessage));
    CHIP_ERROR err = CHIP_NO_ERROR;

    CASESession::ParsedSigma1 parsedMessage;
    err = pairingAccessory.ParseSigma1(tlvReader, parsedMessage);
    std::cout << "ParseSigma1: " << err.Format() << std::endl;

    // I NEED TO FINALIZE TLVREADER IF IT CRASHES

    // tlvReader.ExitContainer(TLV::kTLVType_Structure);

    //  msg = nullptr;

    //  2nd TestCase: Passing Garbage to ParseSigma1 to test if it crashes
    {
        System::PacketBufferHandle garbageMsg =
            System::PacketBufferHandle::NewWithData(garbagePayload.data(), garbagePayload.size(), 0, 38);
        System::PacketBufferTLVReader tlvReaderGarbage;
        tlvReaderGarbage.Init(std::move(garbageMsg));

        CASESession pairingAccessory2;
        pairingAccessory2.ParseSigma1(tlvReaderGarbage, parsedMessage);
    }
}

void ParseSigma1(const vector<uint8_t> & InitiatorRandom, uint32_t fuzzInitiatorSessionId,
                 const vector<uint8_t> & destinationIdentifier, FabricId fuzzedFabricId, const vector<uint8_t> & IPK,
                 const vector<uint8_t> & rootPubKey, const vector<uint8_t> & fuzzResumptionID,
                 const vector<uint8_t> & fuzzInitiatorResumeMIC, bool fuzzSessionResumptionRequested,
                 const vector<uint8_t> & garbagePayload)
{

    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    FuzzCASESession CaseSession;
    // CaseSession.GenerateSigma1(InitiatorRandom, fuzzInitiatorSessionId, fuzzedFabricId, IPK, rootPubKey);
    // CaseSession.HandleSigma1;
    CaseSession.ParseSigma1(InitiatorRandom, fuzzInitiatorSessionId, destinationIdentifier, fuzzedFabricId, IPK, rootPubKey,
                            fuzzResumptionID, fuzzInitiatorResumeMIC, fuzzSessionResumptionRequested, garbagePayload);
    chip::Platform::MemoryShutdown();
}

// These messages are extracted from unit tests to serve as fuzzing seeds, allowing the fuzzer to start with realistic inputs.
// TODO #37654: Replace this extracted data with official test vectors when available
uint8_t FuzzSeed_EncodedSigma1_Node01_02_Chip[] = {
    0x15, 0x30, 0x01, 0x20, 0x3b, 0x0d, 0xee, 0xab, 0x7b, 0x79, 0x31, 0xc8, 0x10, 0x9e, 0x58, 0xb2, 0x90, 0xc0, 0x9c, 0x5a,
    0x33, 0xa2, 0x10, 0xe7, 0x91, 0xf2, 0x69, 0x79, 0x93, 0x44, 0xce, 0xb3, 0xd9, 0x44, 0x84, 0x06, 0x25, 0x02, 0xa0, 0xc1,
    0x30, 0x03, 0x20, 0x47, 0xf1, 0x42, 0x0c, 0xa6, 0xd7, 0x2a, 0xea, 0x3f, 0x68, 0x97, 0x17, 0xd9, 0x27, 0x0e, 0x7f, 0x0e,
    0x7d, 0x62, 0x21, 0x73, 0x98, 0x04, 0x53, 0x81, 0x06, 0xc0, 0x14, 0x9a, 0x50, 0xa0, 0x04, 0x30, 0x04, 0x41, 0x04, 0x8f,
    0xb3, 0x21, 0xc9, 0xad, 0x4e, 0x55, 0xe0, 0xac, 0xfa, 0xe6, 0x56, 0x83, 0xf3, 0xe2, 0x3b, 0xa3, 0xeb, 0x45, 0x6f, 0x4c,
    0xb1, 0x00, 0xc5, 0x73, 0x24, 0x3a, 0x80, 0xc7, 0xbd, 0xf4, 0xd7, 0x9c, 0xaa, 0x96, 0xbb, 0xce, 0x7c, 0x6e, 0xf3, 0x8c,
    0x7b, 0xc4, 0xbb, 0xe9, 0xb8, 0xf5, 0xeb, 0xe8, 0x90, 0xa9, 0x0a, 0x85, 0xc2, 0x0a, 0x1b, 0x2e, 0x9d, 0x14, 0x4d, 0x6c,
    0x73, 0x13, 0xf9, 0x35, 0x05, 0x25, 0x01, 0x88, 0x13, 0x25, 0x02, 0x2c, 0x01, 0x25, 0x03, 0xa0, 0x0f, 0x24, 0x04, 0x12,
    0x24, 0x05, 0x0c, 0x26, 0x06, 0x00, 0x01, 0x04, 0x01, 0x24, 0x07, 0x01, 0x18, 0x18
};

auto SeededEncodedSigma1()
{
    std::vector<uint8_t> dataVec(std::begin(FuzzSeed_EncodedSigma1_Node01_02_Chip),
                                 std::end(FuzzSeed_EncodedSigma1_Node01_02_Chip));

    return Arbitrary<vector<uint8_t>>().WithSeeds({ dataVec });
}

FUZZ_TEST(FuzzCASE, ParseSigma1)
    .WithDomains(
        // InitiatorRandom (Original size = kSigmaParamRandomNumberSize)
        Arbitrary<vector<uint8_t>>(),
        // InitiatorSessionId
        Arbitrary<uint32_t>(),
        // DestinationIdentifier .WithSize(32), .WithSize(kSHA256_Hash_Length - 2)
        Arbitrary<vector<uint8_t>>(),
        // FabricId
        Arbitrary<FabricId>(),
        // fuzzIPK, (Original size = CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES)
        Arbitrary<vector<uint8_t>>(),
        // rootPubKey (Original size = kP256_PublicKey_Length)
        Arbitrary<vector<uint8_t>>(),
        // fuzzResumptionID, (Original size = SessionResumptionStorage::kResumptionIdSize)
        Arbitrary<vector<uint8_t>>(),
        // fuzzInitiatorResumeMIC, (Original size =CHIP_CRYPTO_AEAD_MIC_LENGTH_BYTES)
        Arbitrary<vector<uint8_t>>(),
        // fuzzSessionResumptionRequested
        Arbitrary<bool>(),
        // Garbage Message to pass to ParseSigma1
        Arbitrary<vector<uint8_t>>());

/****************************************************************************************************************** */
/********************************************************************************************************************* */
void FuzzCASESession::EncodeParseSigma1RoundTrip(const vector<uint8_t> & fuzzInitiatorRandom, uint32_t fuzzInitiatorSessionId,
                                                 const vector<uint8_t> & fuzzDestinationIdentifier, FabricId fuzzedFabricId,
                                                 const vector<uint8_t> & IPK, const vector<uint8_t> & fuzzInitiatorEphPubKey,
                                                 const vector<uint8_t> & resumptionID, const vector<uint8_t> & initiatorResumeMIC,
                                                 bool fuzzSessionResumptionRequested)
{

    /*CONSTRUCT SIGMA1*/

    System::PacketBufferHandle msg;

    CASESession pairingCommissioner;
    CASESession pairingAccessory;

    /*********************************Constructing Sigma1*********************************/
    CASESession::EncodeSigma1Inputs encodeParams;
    encodeParams.initiatorRandom    = ByteSpan(fuzzInitiatorRandom.data(), fuzzInitiatorRandom.size());
    encodeParams.initiatorSessionId = fuzzInitiatorSessionId;
    encodeParams.destinationId      = ByteSpan(fuzzDestinationIdentifier.data(), fuzzDestinationIdentifier.size());

    ReliableMessageProtocolConfig LocalMRPConfig(System::Clock::Milliseconds32(100), System::Clock::Milliseconds32(200),
                                                 System::Clock::Milliseconds16(4000));
    encodeParams.initiatorMrpConfig = &LocalMRPConfig;

    if (fuzzSessionResumptionRequested)
    {
        encodeParams.sessionResumptionRequested = true;
        // TODO : make all encodeParams initialisations similar to the below ones
        encodeParams.resumptionId       = ByteSpan(resumptionID.data(), resumptionID.size());
        encodeParams.initiatorResumeMIC = ByteSpan(initiatorResumeMIC.data(), initiatorResumeMIC.size());
    }
    // encodeParams.mrpConfig = nullptr;

    // Encoding Sigma1 into PacketBufferHandle

    // FixedByteSpan<65> EphemeralTest(*EphemeralKey->Pubkey().Bytes());
    // mEphemeralKey->Pubkey() = EphemeralTest;

    /*
        ByteSpan PubKey(fuzzedRootPubKey.data(), fuzzedRootPubKey.size());

        EXPECT_EQ(CHIP_NO_ERROR, EncodeSigma1Mock(msg, encodeParams, PubKey));
    */

    P256PublicKey pubKey(FixedByteSpan<kP256_PublicKey_Length>(fuzzInitiatorEphPubKey.data()));

    encodeParams.initiatorEphPubKey = &pubKey;
    ASSERT_EQ(CHIP_NO_ERROR, pairingAccessory.EncodeSigma1(msg, encodeParams));
    // TODO: or use the API for this, ReleaseEphemeralKeypair
    // EphemeralKey->Clear();
    // Platform::Delete<Crypto::P256Keypair>(EphemeralKey);

    System::PacketBufferTLVReader tlvReader;

    // EXPECT_FALSE(msg.IsNull());

    // THE BELOW CONDITION MIGHT BE NEEDED IF EncodeSigma1Mock could fail
    if (msg.IsNull())
    {
        //     // In case EncodeSigma1 fails, we need to release buffers owned by the PacketBufferHandle `msg`
        //     // msg = nullptr;
        //     // We should skip the iteration when EncodeSigma1 fails
        GTEST_SKIP() << "skipping because msg is null";
    }
    tlvReader.Init(std::move(msg));

    // uint16_t initiatorSessionId;
    // ByteSpan destinationIdentifier;
    // ByteSpan initiatorRandom;

    // bool sessionResumptionRequested = false;
    // bool InitiatorMRPParamsPresent  = false;
    // ByteSpan resumptionId;
    // ByteSpan resume1MIC;
    // ByteSpan initiatorPubKey;

    // TODO: PARSERSIGMA1 NEEDS TO HAVE an EXCHANGE CONTEXT and to have an exchange context we need to have loopbackmessaging (or
    // sessions and other stuff)
    // TODO: SO LIEK THIS, I WILL GET A VERIFYORDIE RELATED TO MISSSING CONTEXT

    //  ExchangeContext * contextAccessory = NewUnauthenticatedExchangeToBob(&pairingAccessory);

    // pairingAccessory.mExchangeCtxt.Emplace(*contextAccessory);
    // EXPECT_EQ(CHIP_NO_ERROR, pairingAccessory.ParseSigma1(tlvReader, parsedMessage));

    CASESession::ParsedSigma1 parsedMessage;
    pairingAccessory.ParseSigma1(tlvReader, parsedMessage);

    // compare parsed values with original values
    EXPECT_TRUE(parsedMessage.initiatorRandom.data_equal(encodeParams.initiatorRandom));
    EXPECT_EQ(parsedMessage.initiatorSessionId, encodeParams.initiatorSessionId);
    EXPECT_TRUE(parsedMessage.destinationId.data_equal(encodeParams.destinationId));
    EXPECT_TRUE(parsedMessage.initiatorEphPubKey.data_equal(
        ByteSpan(encodeParams.initiatorEphPubKey->ConstBytes(), encodeParams.initiatorEphPubKey->Length())));

    if (fuzzSessionResumptionRequested)
    {
        EXPECT_TRUE(parsedMessage.resumptionId.data_equal(encodeParams.resumptionId));
        EXPECT_TRUE(parsedMessage.initiatorResumeMIC.data_equal(encodeParams.initiatorResumeMIC));
        EXPECT_TRUE(parsedMessage.sessionResumptionRequested);
    }
    // I NEED TO FINALIZE TLVREADER IF IT CRASHES

    // tlvReader.ExitContainer(TLV::kTLVType_Structure);
}

void EncodeParseSigma1RoundTrip(const vector<uint8_t> & InitiatorRandom, uint32_t fuzzInitiatorSessionId,
                                const vector<uint8_t> & destinationIdentifier, FabricId fuzzedFabricId, const vector<uint8_t> & IPK,
                                const vector<uint8_t> & rootPubKey, const vector<uint8_t> & fuzzResumptionID,
                                const vector<uint8_t> & fuzzInitiatorResumeMIC, bool fuzzSessionResumptionRequested)
{

    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    FuzzCASESession CaseSession;
    // CaseSession.GenerateSigma1(InitiatorRandom, fuzzInitiatorSessionId, fuzzedFabricId, IPK, rootPubKey);
    // CaseSession.HandleSigma1;
    CaseSession.EncodeParseSigma1RoundTrip(InitiatorRandom, fuzzInitiatorSessionId, destinationIdentifier, fuzzedFabricId, IPK,
                                           rootPubKey, fuzzResumptionID, fuzzInitiatorResumeMIC, fuzzSessionResumptionRequested);
    chip::Platform::MemoryShutdown();
}
FUZZ_TEST(FuzzCASE, EncodeParseSigma1RoundTrip)
    .WithDomains(
        // InitiatorRandom (Original size = kSigmaParamRandomNumberSize)
        Arbitrary<vector<uint8_t>>().WithSize(kSigmaParamRandomNumberSize),
        // InitiatorSessionId
        Arbitrary<uint32_t>(),
        // DestinationIdentifier .WithSize(32), .WithSize(kSHA256_Hash_Length - 2)
        Arbitrary<vector<uint8_t>>().WithSize(32),
        // FabricId
        Arbitrary<FabricId>(),
        // fuzzIPK, (Original size = CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES)
        Arbitrary<vector<uint8_t>>().WithSize(CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES),
        // rootPubKey (Original size = kP256_PublicKey_Length)
        Arbitrary<vector<uint8_t>>().WithSize(kP256_PublicKey_Length),
        // fuzzResumptionID, (Original size = SessionResumptionStorage::kResumptionIdSize)
        Arbitrary<vector<uint8_t>>().WithSize(SessionResumptionStorage::kResumptionIdSize),
        // fuzzInitiatorResumeMIC, (Original size =CHIP_CRYPTO_AEAD_MIC_LENGTH_BYTES)
        Arbitrary<vector<uint8_t>>().WithSize(CHIP_CRYPTO_AEAD_MIC_LENGTH_BYTES),
        // fuzzSessionResumptionRequested
        Arbitrary<bool>());

/***************************** */
/***************************** */

/***************************** */
/***************************** */

/***************************** */

CHIP_ERROR FuzzEncodeSessionParameters(TLV::Tag tag, const ReliableMessageProtocolConfig & mrpLocalConfig,
                                       TLV::TLVWriter & tlvWriter, const vector<uint8_t> & fuzzSessionParameters)
{
    TLV::TLVType mrpParamsContainer;
    ReturnErrorOnFailure(tlvWriter.StartContainer(tag, TLV::kTLVType_Structure, mrpParamsContainer));
    ReturnErrorOnFailure(
        tlvWriter.Put(TLV::ContextTag(SessionParameters::Tag::kSessionIdleInterval), mrpLocalConfig.mIdleRetransTimeout.count()));
    ReturnErrorOnFailure(tlvWriter.Put(TLV::ContextTag(SessionParameters::Tag::kSessionActiveInterval),
                                       mrpLocalConfig.mActiveRetransTimeout.count()));
    ReturnErrorOnFailure(tlvWriter.Put(TLV::ContextTag(SessionParameters::Tag::kSessionActiveThreshold),
                                       mrpLocalConfig.mActiveThresholdTime.count()));

    uint16_t dataModel = 555;
    ReturnErrorOnFailure(tlvWriter.Put(TLV::ContextTag(SessionParameters::Tag::kDataModelRevision), dataModel));

    uint16_t interactionModel = 666;
    ReturnErrorOnFailure(tlvWriter.Put(TLV::ContextTag(SessionParameters::Tag::kInteractionModelRevision), interactionModel));

    uint32_t specVersion = 777;
    ReturnErrorOnFailure(tlvWriter.Put(TLV::ContextTag(SessionParameters::Tag::kSpecificationVersion), specVersion));

    uint16_t maxPathsPerInvoke = CHIP_CONFIG_MAX_PATHS_PER_INVOKE;
    ReturnErrorOnFailure(tlvWriter.Put(TLV::ContextTag(SessionParameters::Tag::kMaxPathsPerInvoke), maxPathsPerInvoke));

    // uint32_t test = 9999;
    // ReturnErrorOnFailure(tlvWriter.Put(TLV::ContextTag(8), test));

    // ReturnErrorOnFailure(tlvWriter.Put(TLV::ContextTag(9), fuzzSessionParameters.data()));

    return tlvWriter.EndContainer(mrpParamsContainer);
}

CHIP_ERROR EncodeSigma2Mock(MutableByteSpan & mem, const vector<uint8_t> & fuzzResponderRandom, uint32_t fuzzResponderSessionId,
                            const vector<uint8_t> & fuzzRootPubKey, const vector<uint8_t> & fuzzEncrypted2,
                            const vector<uint8_t> & fuzzSessionParameters)
{

    TLV::TLVType outerContainerType = TLV::kTLVType_NotSpecified;

    TLVWriter tlvWriter;

    tlvWriter.Init(mem);
    ReturnErrorOnFailure(tlvWriter.StartContainer(TLV::AnonymousTag(), TLV::kTLVType_Structure, outerContainerType));
    ReturnErrorOnFailure(tlvWriter.PutBytes(TLV::ContextTag(1), fuzzResponderRandom.data(), fuzzResponderRandom.size()));
    ReturnErrorOnFailure(tlvWriter.Put(TLV::ContextTag(2), fuzzResponderSessionId));
    ReturnErrorOnFailure(tlvWriter.PutBytes(TLV::ContextTag(3), fuzzRootPubKey.data(), fuzzRootPubKey.size()));
    ReturnErrorOnFailure(tlvWriter.PutBytes(TLV::ContextTag(4), fuzzEncrypted2.data(), fuzzEncrypted2.size()));

    ReliableMessageProtocolConfig LocalMRPConfig(System::Clock::Milliseconds32(100), System::Clock::Milliseconds32(200),
                                                 System::Clock::Milliseconds16(4000));

    FuzzEncodeSessionParameters(TLV::ContextTag(5), LocalMRPConfig, tlvWriter, fuzzSessionParameters);

    ReturnErrorOnFailure(tlvWriter.EndContainer(outerContainerType));
    mem.reduce_size(tlvWriter.GetLengthWritten());

    ReturnErrorOnFailure(tlvWriter.Finalize());

    return CHIP_NO_ERROR;
}

void ParseSigma2(const vector<uint8_t> & fuzzResponderRandom, uint16_t fuzzResponderSessionId,
                 const vector<uint8_t> & fuzzRootPubKey, const vector<uint8_t> & fuzzEncrypted2,
                 const vector<uint8_t> & fuzzSessionParameters, const vector<uint8_t> & garbagePayload)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);

    /*********************************Constructing Sigma2*********************************/

    ReliableMessageProtocolConfig LocalMRPConfig(System::Clock::Milliseconds32(100), System::Clock::Milliseconds32(200),
                                                 System::Clock::Milliseconds16(4000));

    System::PacketBufferHandle msg;

    chip::Platform::ScopedMemoryBuffer<uint8_t> mem;

    size_t dataLen =
        TLV::EstimateStructOverhead(fuzzResponderRandom.size(),                                         // responderRandom
                                    sizeof(fuzzResponderSessionId),                                     // responderSessionId
                                    fuzzRootPubKey.size(),                                              // signature
                                    fuzzEncrypted2.size(),                                              // msgR2Encrypted
                                    SessionParameters::kEstimatedTLVSize + fuzzSessionParameters.size() // SessionParameters

        );

    ASSERT_TRUE(mem.Calloc(dataLen));
    MutableByteSpan encodedSpan(mem.Get(), dataLen);
    ASSERT_EQ(CHIP_NO_ERROR,
              EncodeSigma2Mock(encodedSpan, fuzzResponderRandom, fuzzResponderSessionId, fuzzRootPubKey, fuzzEncrypted2,
                               fuzzSessionParameters));

    // 1st TestCase, passing a structured payload to ParseSigma2
    {
        TLV::ContiguousBufferTLVReader tlvReader;
        tlvReader.Init(encodedSpan);
        FuzzCASESession::ParsedSigma2 parsedSigma2;

        CHIP_ERROR err = CHIP_NO_ERROR;
        err            = FuzzCASESession::ParseSigma2(tlvReader, parsedSigma2);
        std::cout << err.Format() << std::endl;
    }

    //  2nd TestCase: Passing a Garbage payload to ParseSigma2 to test if it crashes
    {
        FuzzCASESession::ParsedSigma2 parsedSigma2;

        System::PacketBufferHandle garbageMsg =
            System::PacketBufferHandle::NewWithData(garbagePayload.data(), garbagePayload.size(), 0, 38);
        System::PacketBufferTLVReader tlvReaderGarbage;
        tlvReaderGarbage.Init(std::move(garbageMsg));

        //      CASESession::ParseSigma2(tlvReaderGarbage, parsedSigma2);
    }

    mem.Free();
    chip::Platform::MemoryShutdown();
}

FUZZ_TEST(FuzzCASE, ParseSigma2)
    .WithDomains(
        // responderRandom (Original size = kSigmaParamRandomNumberSize)
        Arbitrary<vector<uint8_t>>().WithSize(kSigmaParamRandomNumberSize),
        // responderSessionId
        Arbitrary<uint16_t>(),
        // responderEphPubKey (Original size = kP256_PublicKey_Length)
        Arbitrary<vector<uint8_t>>().WithSize(kP256_PublicKey_Length),
        // Encrypted2 (WithMinSize(kP256_PublicKey_Length))
        Arbitrary<vector<uint8_t>>().WithMinSize(CHIP_CRYPTO_AEAD_MIC_LENGTH_BYTES + 1),
        // FuzzSessionParameters
        Arbitrary<vector<uint8_t>>(),
        // Garbage Message to pass to ParseSigma1
        Arbitrary<vector<uint8_t>>());
/****************** */

void ParseSigma2Seeded(const vector<uint8_t> & garbagePayload)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);

    //  2nd TestCase: Passing a Garbage payload to ParseSigma2 to test if it crashes
    {
        FuzzCASESession::ParsedSigma2 parsedSigma2;

        System::PacketBufferHandle garbageMsg =
            System::PacketBufferHandle::NewWithData(garbagePayload.data(), garbagePayload.size(), 0, 38);
        System::PacketBufferTLVReader tlvReaderGarbage;
        tlvReaderGarbage.Init(std::move(garbageMsg));

        FuzzCASESession::ParseSigma2(tlvReaderGarbage, parsedSigma2);
    }

    chip::Platform::MemoryShutdown();
}
// These messages are extracted from unit tests to serve as fuzzing seeds, allowing the fuzzer to start with realistic inputs.
// TODO #37654: Replace this extracted data with official test vectors when available
uint8_t FuzzSeed_EncodedSigma2_Node01_02_Chip[] = {
    0x15, 0x30, 0x01, 0x20, 0xb7, 0x4a, 0xb7, 0x9e, 0x2a, 0xab, 0x6d, 0xca, 0xa2, 0x83, 0x76, 0x43, 0x2f, 0xc8, 0x66, 0xf0, 0x47,
    0x4a, 0x49, 0x7f, 0xd4, 0xbe, 0x7c, 0x08, 0x80, 0xa0, 0x3d, 0x6e, 0xf5, 0xf2, 0x6f, 0x9b, 0x25, 0x02, 0x9f, 0xc1, 0x30, 0x03,
    0x41, 0x04, 0x97, 0x4b, 0x02, 0x8e, 0xda, 0xb0, 0x62, 0x00, 0x46, 0x78, 0xf8, 0x34, 0xc0, 0x5d, 0x53, 0x79, 0xb8, 0x44, 0xd1,
    0x84, 0x2a, 0x34, 0x7d, 0xec, 0x9e, 0x6d, 0x9b, 0x56, 0x0a, 0x6f, 0x2e, 0x95, 0xb1, 0x58, 0x62, 0x4b, 0x23, 0x21, 0xc9, 0xb1,
    0x12, 0x66, 0xc8, 0x55, 0x7e, 0xa5, 0xef, 0xe7, 0x75, 0xa7, 0x1c, 0xc4, 0x30, 0x8a, 0xad, 0x42, 0xce, 0x62, 0x02, 0x52, 0x48,
    0xd9, 0x74, 0x74, 0x31, 0x04, 0x78, 0x02, 0x5e, 0xa5, 0xc6, 0x2e, 0xce, 0x0f, 0x35, 0xeb, 0x30, 0x8b, 0x30, 0x45, 0x8d, 0xf1,
    0x20, 0x48, 0xe2, 0xf3, 0x9f, 0xae, 0x90, 0x78, 0xa8, 0xb2, 0xc8, 0x57, 0x88, 0x71, 0x86, 0x21, 0x8b, 0x55, 0x86, 0x39, 0xab,
    0x10, 0x9d, 0x78, 0x22, 0x70, 0x51, 0x86, 0x19, 0xd1, 0x16, 0x0f, 0x9e, 0xa1, 0xb4, 0x0b, 0x32, 0x28, 0x48, 0xb4, 0x23, 0xd4,
    0xd4, 0xa0, 0x81, 0xe9, 0xba, 0x59, 0xd5, 0x75, 0xa7, 0x3e, 0xdf, 0x1a, 0xa0, 0x21, 0x12, 0x56, 0x96, 0x81, 0x69, 0x60, 0x5e,
    0x49, 0xa3, 0xd9, 0xa1, 0x0d, 0xed, 0x9a, 0xb4, 0x0d, 0x40, 0xaf, 0x0d, 0x05, 0x7e, 0x2c, 0xb1, 0x30, 0xf7, 0x78, 0x0a, 0x39,
    0x77, 0x90, 0x62, 0x36, 0xae, 0x3b, 0x57, 0x31, 0x5f, 0xbd, 0x67, 0x57, 0x36, 0x48, 0x10, 0x5f, 0x68, 0x1b, 0x2f, 0xf6, 0xeb,
    0xb3, 0x53, 0x69, 0x88, 0xfe, 0xf4, 0x8b, 0xa0, 0x3f, 0x93, 0xa7, 0x19, 0x87, 0x6b, 0xc8, 0xd2, 0x1e, 0xbf, 0x8e, 0x6c, 0xfc,
    0xbb, 0x87, 0x07, 0x19, 0xdf, 0xea, 0xad, 0xf2, 0xf5, 0x53, 0x0e, 0x2c, 0x2c, 0x71, 0x7b, 0xbe, 0xf4, 0xd9, 0x22, 0x94, 0x7d,
    0x15, 0xa5, 0x71, 0x67, 0xf4, 0xf9, 0x98, 0x69, 0x95, 0x93, 0x26, 0x1a, 0x52, 0x55, 0x27, 0x26, 0x32, 0xc6, 0xb3, 0x63, 0x96,
    0x1f, 0xde, 0xca, 0xf7, 0x20, 0xe6, 0x7d, 0xcf, 0x6c, 0xd4, 0xaa, 0x7f, 0xe2, 0xfe, 0x7b, 0x2c, 0xff, 0x4b, 0x7c, 0x1c, 0xc3,
    0x75, 0x3b, 0xcf, 0xf8, 0x28, 0x9d, 0x79, 0x47, 0x86, 0x4a, 0xba, 0x5f, 0x70, 0x6a, 0x64, 0xef, 0x3e, 0xb9, 0xaa, 0x75, 0xdb,
    0x29, 0xe6, 0x93, 0x2a, 0x76, 0x9d, 0x06, 0x61, 0x54, 0x21, 0x51, 0xa6, 0x78, 0x1c, 0x54, 0x95, 0x7f, 0x93, 0x2a, 0x1f, 0x36,
    0x1b, 0xda, 0x9c, 0x55, 0x45, 0xaf, 0x87, 0xa6, 0xc5, 0x1e, 0x4c, 0x81, 0x92, 0x55, 0x58, 0xc4, 0xaa, 0x63, 0x8f, 0xef, 0x07,
    0x46, 0xf1, 0x65, 0xb9, 0x00, 0x13, 0x8b, 0xb8, 0xf9, 0xd8, 0x57, 0xea, 0x8c, 0xe9, 0xe4, 0x84, 0x1c, 0x7b, 0x02, 0x44, 0x37,
    0xb2, 0x3e, 0x99, 0x86, 0x47, 0xac, 0xc1, 0x05, 0xa6, 0x35, 0x8b, 0xc5, 0x98, 0x43, 0x94, 0xab, 0x7a, 0xfe, 0x97, 0xa2, 0xb2,
    0x9d, 0xbb, 0xe3, 0xc9, 0xe3, 0x71, 0xc2, 0x8f, 0x4a, 0xc5, 0x90, 0x46, 0x38, 0x8d, 0x7d, 0x91, 0x37, 0xf8, 0x34, 0x4e, 0x16,
    0x82, 0xd0, 0x88, 0xd8, 0x43, 0xb1, 0xa4, 0x52, 0x9c, 0x88, 0xda, 0xa7, 0xd0, 0x82, 0x7d, 0xfc, 0x67, 0x19, 0xd6, 0x87, 0x81,
    0x6e, 0xc4, 0x31, 0x06, 0x2c, 0x2f, 0xa4, 0xa2, 0xf6, 0x72, 0x83, 0x4e, 0x5b, 0xcb, 0x56, 0x9d, 0x5c, 0xec, 0x30, 0x24, 0x54,
    0xeb, 0x34, 0x0e, 0x74, 0x79, 0x1e, 0x7e, 0x0a, 0x71, 0x6b, 0x3f, 0x68, 0x80, 0xfa, 0xab, 0x8e, 0x4b, 0x7c, 0x2b, 0x45, 0xd3,
    0xd6, 0xb7, 0xb1, 0x43, 0xce, 0x5f, 0x93, 0x2f, 0x5b, 0xb6, 0xd5, 0x6c, 0xe2, 0x7f, 0x5c, 0x81, 0xaf, 0x7f, 0x26, 0x60, 0x7c,
    0xa0, 0x7e, 0x7a, 0x3a, 0xa8, 0x3b, 0xd5, 0x2b, 0xc5, 0x13, 0x46, 0x86, 0x3c, 0xa7, 0xd6, 0x9c, 0x84, 0x77, 0x15, 0xda, 0xbd,
    0xaa, 0x2d, 0x31, 0x7d, 0x90, 0x7c, 0x19, 0xe3, 0x3c, 0xe9, 0xb5, 0x10, 0xf4, 0xcf, 0xe9, 0x26, 0x07, 0x1d, 0x84, 0x3d, 0x4e,
    0xc3, 0x41, 0x3e, 0x0c, 0x98, 0xbe, 0x0e, 0x86, 0xff, 0xe7, 0xed, 0x74, 0xab, 0x0d, 0x88, 0xa1, 0x51, 0x32, 0x8d, 0xc0, 0x80,
    0xd7, 0x12, 0xbd, 0xf1, 0xc8, 0x1e, 0x20, 0x83, 0x33, 0x14, 0xf0, 0x14, 0x18, 0xe2, 0x50, 0x65, 0x42, 0x85, 0x9b, 0xf8, 0x18,
    0x3f, 0xd6, 0x67, 0xfd, 0xcd, 0x03, 0x7f, 0xbc, 0xd4, 0x0e, 0xbc, 0x5f, 0x89, 0x4f, 0x8a, 0x03, 0xa5, 0x92, 0xc4, 0xf3, 0xa2,
    0xda, 0x71, 0x9e, 0x52, 0x7d, 0x49, 0x6a, 0xf1, 0xbd, 0x5a, 0x75, 0x75, 0xa9, 0x9d, 0x12, 0xc6, 0xbf, 0xcf, 0x2e, 0x25, 0xad,
    0x30, 0x42, 0x6c, 0x74, 0x73, 0x54, 0x10, 0x6e, 0x80, 0xdb, 0xdc, 0x2d, 0x93, 0x17, 0x37, 0x78, 0x82, 0x66, 0xe2, 0xd8, 0x68,
    0x0e, 0x7f, 0x28, 0xe0, 0xbb, 0x06, 0x7d, 0xde, 0x8a, 0x17, 0x52, 0xf7, 0x97, 0x86, 0xd1, 0xe0, 0xed, 0x73, 0xa4, 0x98, 0x2e,
    0x17, 0x73, 0x16, 0xdf, 0x64, 0xe4, 0xa3, 0x42, 0x90, 0xa6, 0x23, 0x6e, 0xc7, 0x7e, 0xb0, 0x8e, 0xb0, 0xc9, 0xaa, 0x1c, 0xfb,
    0xae, 0x22, 0x61, 0x94, 0xbc, 0xb4, 0x33, 0xfa, 0xca, 0xe1, 0x18, 0x3d, 0x9a, 0x16, 0xd4, 0xe6, 0x6f, 0xbc, 0xba, 0x92, 0xde,
    0x95, 0x15, 0x83, 0x1e, 0x59, 0x6a, 0xc7, 0x70, 0xd6, 0x35, 0x05, 0x26, 0x01, 0x40, 0x7e, 0x05, 0x00, 0x26, 0x02, 0xa0, 0x86,
    0x01, 0x00, 0x25, 0x03, 0x2c, 0x01, 0x24, 0x04, 0x12, 0x24, 0x05, 0x0c, 0x26, 0x06, 0x00, 0x01, 0x04, 0x01, 0x24, 0x07, 0x01,
    0x18, 0x18
};

auto SeededEncodedSigma2()
{
    std::vector<uint8_t> dataVec(std::begin(FuzzSeed_EncodedSigma2_Node01_02_Chip),
                                 std::end(FuzzSeed_EncodedSigma2_Node01_02_Chip));

    return Arbitrary<vector<uint8_t>>().WithSeeds({ dataVec });
}

FUZZ_TEST(FuzzCASE, ParseSigma2Seeded).WithDomains(SeededEncodedSigma2());

/**************** */

void FuzzCASESession::EncodeParseSigma2RoundTrip(const vector<uint8_t> & fuzzResponderRandom, uint32_t fuzzResponderSessionId,
                                                 const vector<uint8_t> & fuzzRootPubKey, const vector<uint8_t> fuzzEncrypted2)
{

    CASESession::EncodeSigma2Inputs encodeParams;
    // encodeParams.responderRandom    = ByteSpan(fuzzResponderRandom.data(), fuzzResponderRandom.size());
    memcpy(&encodeParams.responderRandom[0], fuzzResponderRandom.data(), kSigmaParamRandomNumberSize);
    encodeParams.responderSessionId = fuzzResponderSessionId;

    P256PublicKey pubKey = FixedByteSpan<kP256_PublicKey_Length>(fuzzRootPubKey.data());

    // P256PublicKey pubKey(reinterpret_cast<const uint8_t(&)[kP256_PublicKey_Length]>(*fuzzRootPubKey.data()));

    encodeParams.responderEphPubKey = &pubKey;

    encodeParams.msgR2Encrypted.Alloc(fuzzEncrypted2.size());
    memcpy(encodeParams.msgR2Encrypted.Get(), fuzzEncrypted2.data(), fuzzEncrypted2.size());
    encodeParams.encrypted2Length = fuzzEncrypted2.size();

    // TODO should I add EncodeSessionParameters to EncodeSigma2Mock, to make sure we have a larger SessionParams TLV element?
    ReliableMessageProtocolConfig LocalMRPConfig(System::Clock::Milliseconds32(100), System::Clock::Milliseconds32(200),
                                                 System::Clock::Milliseconds16(4000));
    encodeParams.responderMrpConfig = &LocalMRPConfig;

    System::PacketBufferHandle msg;

    EXPECT_EQ(CHIP_NO_ERROR, CASESession::EncodeSigma2(msg, encodeParams));

    System::PacketBufferTLVReader tlvReader;

    tlvReader.Init(std::move(msg));
    CASESession::ParsedSigma2 parsedSigma2;
    CASESession::ParseSigma2(tlvReader, parsedSigma2);

    // TODO add the comparisons
    // Platform::Delete<Crypto::P256Keypair>(&pubKey);
}

void EncodeParseSigma2RoundTrip(const vector<uint8_t> & fuzzResponderRandom, uint32_t fuzzResponderSessionId,
                                const vector<uint8_t> & fuzzRootPubKey, const vector<uint8_t> fuzzEncrypted2)
{

    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    FuzzCASESession CaseSession;
    CaseSession.EncodeParseSigma2RoundTrip(fuzzResponderRandom, fuzzResponderSessionId, fuzzRootPubKey, fuzzEncrypted2);
    chip::Platform::MemoryShutdown();
}
FUZZ_TEST(FuzzCASE, EncodeParseSigma2RoundTrip)
    .WithDomains(
        // responderRandom (Original size = kSigmaParamRandomNumberSize)
        Arbitrary<vector<uint8_t>>().WithSize(kSigmaParamRandomNumberSize),
        // responderSessionId
        Arbitrary<uint32_t>(),
        // responderEphPubKey .WithSize(32), .WithSize(kSHA256_Hash_Length - 2)
        Arbitrary<vector<uint8_t>>().WithSize(kP256_PublicKey_Length),
        // msgR2Encrypted,
        Arbitrary<vector<uint8_t>>().WithMinSize(CHIP_CRYPTO_AEAD_MIC_LENGTH_BYTES + 1));

/*************************************************************************************** */

CHIP_ERROR EncodeSigma2TBEDataMock(MutableByteSpan & msgSpan, const vector<uint8_t> & responderNOC,
                                   const vector<uint8_t> & responderICAC, const vector<uint8_t> & signature,
                                   const vector<uint8_t> & resumptionID)
{

    // VerifyOrReturnError(!msg.IsNull(), CHIP_ERROR_NO_MEMORY);

    //   System::PacketBufferTLVWriter tlvWriter;
    TLVWriter tlvWriter;
    TLVType outerContainerType = kTLVType_NotSpecified;

    tlvWriter.Init(msgSpan);
    ReturnErrorOnFailure(tlvWriter.StartContainer(TLV::AnonymousTag(), TLV::kTLVType_Structure, outerContainerType));
    ReturnErrorOnFailure(tlvWriter.PutBytes(TLV::ContextTag(1), responderNOC.data(), responderNOC.size()));
    ReturnErrorOnFailure(tlvWriter.PutBytes(TLV::ContextTag(2), responderICAC.data(), responderICAC.size()));
    ReturnErrorOnFailure(tlvWriter.PutBytes(TLV::ContextTag(3), signature.data(), signature.size()));
    // ReturnErrorOnFailure(tlvWriter.PutBytes(TLV::ContextTag(4), resumptionID.data(), resumptionID.size()));

    ReturnErrorOnFailure(tlvWriter.PutBytes(TLV::ContextTag(4), resumptionID.data(), resumptionID.size()));

    // Adding an extra TLV element to test if it crashes or triggeres an unexpected error
    // ReturnErrorOnFailure(tlvWriter.PutBytes(TLV::ContextTag(5), resumptionID.data(), resumptionID.size()));

    ReturnErrorOnFailure(tlvWriter.EndContainer(outerContainerType));
    ReturnErrorOnFailure(tlvWriter.Finalize());

    msgSpan.reduce_size(tlvWriter.GetLengthWritten());

    // TRIAL TO TRUNCATE BUFFER AFTER WRITING
    // This caused an CHIP_ERROR_TLV_UNDERRUN inside VerifyElement
    //  msg->SetDataLength(msg->DataLength() - 3);

    // TRIAL TO TRUNCATE BUFFER AFTER WRITING
    // This caused an CHIP_END_OF_TLV since it deleted endContainer Marker
    // msg->SetDataLength(msg->DataLength() - 1);

    return CHIP_NO_ERROR;
}
void FuzzCASESession::ParseSigma2TBE(const vector<uint8_t> & fuzzResponderNOC, vector<uint8_t> fuzzResponderICAC,
                                     const vector<uint8_t> & fuzzSignature, const vector<uint8_t> & fuzzResumptionID,
                                     const vector<uint8_t> & garbagePayload, size_t bitflipIndex, size_t bitflipPosition)
{

    size_t dataLen = TLV::EstimateStructOverhead(fuzzResponderNOC.size(),  // responderNOC
                                                 fuzzResponderICAC.size(), // responderICAC
                                                 fuzzSignature.size(),     // signature
                                                 fuzzResumptionID.size()   // resumptionId

                                                 // resumptionID.size()

    );

    Platform::ScopedMemoryBuffer<uint8_t> encodedSigma2TBEData;
    encodedSigma2TBEData.Alloc(dataLen);

    MutableByteSpan encodedSpan(encodedSigma2TBEData.Get(), dataLen);

    EXPECT_EQ(CHIP_NO_ERROR,
              EncodeSigma2TBEDataMock(encodedSpan, fuzzResponderNOC, fuzzResponderICAC, fuzzSignature, fuzzResumptionID));

    //  1st TestCase: constructing structured fuzzedSigma2TBEData and passing to ParseSigma2TBEData
    {

        ContiguousBufferTLVReader tlvReader;
        tlvReader.Init(encodedSpan);

        CASESession::ParsedSigma2TBEData parsedSigma2TBEData;

        CHIP_ERROR err = CASESession::ParseSigma2TBEData(tlvReader, parsedSigma2TBEData);
        std::cout << "ParseSigma2TBEData: " << err.Format() << std::endl;
    }

    // 2nd TestCase, Adding a random bitflip to a structured TLV-encoded payload (which will otherwise pass all checks) to
    // ParseSigma2
    {

        //  Flip a single bit if the buffer is non-empty
        if (encodedSpan.size() > 0)
        {
            size_t actualIndex = bitflipIndex % encodedSpan.size(); // limit index to valid range
            // Flip the bit
            encodedSpan[actualIndex] ^= static_cast<uint8_t>(1 << bitflipPosition);
        }

        TLV::ContiguousBufferTLVReader tlvReader;
        // tlvReader.Init(std::move(msg));
        tlvReader.Init(encodedSpan);

        CASESession::ParsedSigma2TBEData parsedSigma2TBEData;

        CHIP_ERROR err = CASESession::ParseSigma2TBEData(tlvReader, parsedSigma2TBEData);
        std::cout << "RandomBitFlip: ParseSigma2TBEData: " << err.Format() << std::endl;
    }
    //  3rd TestCase: Passing Garbage to ParseSigma2TBEData to test if it crashes
    {
        CASESession::ParsedSigma2TBEData parsedSigma2TBEDatagarbage;
        System::PacketBufferHandle garbageMsg =
            System::PacketBufferHandle::NewWithData(garbagePayload.data(), garbagePayload.size(), 0, 38);
        System::PacketBufferTLVReader tlvReaderGarbage;
        tlvReaderGarbage.Init(std::move(garbageMsg));

        CASESession::ParseSigma2TBEData(tlvReaderGarbage, parsedSigma2TBEDatagarbage);
    }
}

void ParseSigma2TBE(const vector<uint8_t> & responderNOC, vector<uint8_t> responderICAC, const vector<uint8_t> & signature,
                    const vector<uint8_t> & resumptionID, const vector<uint8_t> & garbagePayload, size_t bitflipIndex,
                    size_t bitflipPosition)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    FuzzCASESession fuzzCaseSession;
    // CaseSession.GenerateSigma1(InitiatorRandom, fuzzInitiatorSessionId, fuzzedFabricId, IPK, rootPubKey);
    // CaseSession.HandleSigma1;
    fuzzCaseSession.ParseSigma2TBE(responderNOC, responderICAC, signature, resumptionID, garbagePayload, bitflipIndex,
                                   bitflipPosition);

    chip::Platform::MemoryShutdown();
}

// These messages are extracted from unit tests to serve as fuzzing seeds, allowing the fuzzer to start with realistic inputs.
// TODO #37654: Replace this extracted data with official test vectors when available
uint8_t FuzzSeed_EncodedSigma2TBE_Node01_02_Chip[] = {
    0x15, 0x31, 0x01, 0x0d, 0x01, 0x15, 0x30, 0x01, 0x08, 0x18, 0xe9, 0x69, 0xba, 0x0e, 0x08, 0x9e, 0x23, 0x24, 0x02, 0x01, 0x37,
    0x03, 0x27, 0x13, 0x03, 0x00, 0x00, 0x00, 0xca, 0xca, 0xca, 0xca, 0x18, 0x26, 0x04, 0xef, 0x17, 0x1b, 0x27, 0x26, 0x05, 0x6e,
    0xb5, 0xb9, 0x4c, 0x37, 0x06, 0x27, 0x11, 0x01, 0x00, 0x01, 0x00, 0xde, 0xde, 0xde, 0xde, 0x27, 0x15, 0x1d, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xb0, 0xfa, 0x18, 0x24, 0x07, 0x01, 0x24, 0x08, 0x01, 0x30, 0x09, 0x41, 0x04, 0xbc, 0xf6, 0x58, 0x0d, 0x2d, 0x71,
    0xe1, 0x44, 0x16, 0x65, 0x1f, 0x7c, 0x31, 0x1b, 0x5e, 0xfc, 0xf9, 0xae, 0xc0, 0xa8, 0xc1, 0x0a, 0xf8, 0x09, 0x27, 0x84, 0x4c,
    0x24, 0x0f, 0x51, 0xa8, 0xeb, 0x23, 0xfa, 0x07, 0x44, 0x13, 0x88, 0x87, 0xac, 0x1e, 0x73, 0xcb, 0x72, 0xa0, 0x54, 0xb6, 0xa0,
    0xdb, 0x06, 0x22, 0xaa, 0x80, 0x70, 0x71, 0x01, 0x63, 0x13, 0xb1, 0x59, 0x6c, 0x85, 0x52, 0xcf, 0x37, 0x0a, 0x35, 0x01, 0x28,
    0x01, 0x18, 0x24, 0x02, 0x01, 0x36, 0x03, 0x04, 0x02, 0x04, 0x01, 0x18, 0x30, 0x04, 0x14, 0x69, 0x67, 0xc9, 0x12, 0xf8, 0xa3,
    0xe6, 0x89, 0x55, 0x6f, 0x89, 0x9b, 0x65, 0xd7, 0x6f, 0x53, 0xfa, 0x65, 0xc7, 0xb6, 0x30, 0x05, 0x14, 0x44, 0x0c, 0xc6, 0x92,
    0x31, 0xc4, 0xcb, 0x5b, 0x37, 0x94, 0x24, 0x26, 0xf8, 0x1b, 0xbe, 0x24, 0xb7, 0xef, 0x34, 0x5c, 0x18, 0x30, 0x0b, 0x40, 0xce,
    0x6e, 0xf3, 0x93, 0xcb, 0xbc, 0x94, 0xf8, 0x0e, 0xe2, 0x90, 0xcb, 0x3c, 0x3d, 0x37, 0x33, 0x35, 0xba, 0xb9, 0x59, 0x07, 0x73,
    0x4d, 0x99, 0xd3, 0x84, 0xa6, 0x2a, 0x37, 0x3b, 0x84, 0x84, 0xe1, 0xd4, 0x1a, 0x04, 0xc3, 0x14, 0x0f, 0xaa, 0x19, 0xe8, 0xa2,
    0xb9, 0x9b, 0x0c, 0x61, 0xe3, 0x3c, 0x27, 0xea, 0x91, 0x39, 0x73, 0xe4, 0x5b, 0x5b, 0xc6, 0xe3, 0x9c, 0x27, 0x0d, 0xac, 0x53,
    0x18, 0x30, 0x02, 0xfc, 0x15, 0x30, 0x01, 0x08, 0x69, 0xd8, 0x6a, 0x8d, 0x80, 0xfc, 0x8f, 0x5d, 0x24, 0x02, 0x01, 0x37, 0x03,
    0x27, 0x14, 0x01, 0x00, 0x00, 0x00, 0xca, 0xca, 0xca, 0xca, 0x18, 0x26, 0x04, 0xef, 0x17, 0x1b, 0x27, 0x26, 0x05, 0x6e, 0xb5,
    0xb9, 0x4c, 0x37, 0x06, 0x27, 0x13, 0x03, 0x00, 0x00, 0x00, 0xca, 0xca, 0xca, 0xca, 0x18, 0x24, 0x07, 0x01, 0x24, 0x08, 0x01,
    0x30, 0x09, 0x41, 0x04, 0x5f, 0x94, 0xf5, 0x7e, 0x0b, 0x13, 0xc9, 0xcf, 0xcf, 0x96, 0xdf, 0xe1, 0xfc, 0xe7, 0x88, 0x8d, 0x56,
    0x4c, 0xc2, 0x09, 0xc5, 0x5c, 0x45, 0x08, 0xe4, 0x4d, 0xcf, 0x16, 0xba, 0x2e, 0x09, 0x66, 0x2f, 0x9e, 0xec, 0xf1, 0x9f, 0x40,
    0xb0, 0xe8, 0x8a, 0x0b, 0x28, 0x15, 0xda, 0x9e, 0xe1, 0x0a, 0x3a, 0x17, 0x7c, 0x25, 0x1f, 0x43, 0x4f, 0x5b, 0x0f, 0x26, 0x3c,
    0xe7, 0xde, 0x62, 0x78, 0xc6, 0x37, 0x0a, 0x35, 0x01, 0x29, 0x01, 0x18, 0x24, 0x02, 0x60, 0x30, 0x04, 0x14, 0x44, 0x0c, 0xc6,
    0x92, 0x31, 0xc4, 0xcb, 0x5b, 0x37, 0x94, 0x24, 0x26, 0xf8, 0x1b, 0xbe, 0x24, 0xb7, 0xef, 0x34, 0x5c, 0x30, 0x05, 0x14, 0xcc,
    0x13, 0x08, 0xaf, 0x82, 0xcf, 0xee, 0x50, 0x5e, 0xb2, 0x3b, 0x57, 0xbf, 0xe8, 0x6a, 0x31, 0x16, 0x65, 0x53, 0x5f, 0x18, 0x30,
    0x0b, 0x40, 0xad, 0xb8, 0x5b, 0x5d, 0x68, 0xcb, 0xfd, 0x36, 0x14, 0x0d, 0x8c, 0x9d, 0x12, 0x90, 0x14, 0xc4, 0x5f, 0xa7, 0xca,
    0x19, 0x1f, 0x34, 0xd9, 0xaf, 0x24, 0x1d, 0xb7, 0x17, 0x36, 0xe6, 0x0f, 0x44, 0x19, 0x9b, 0xc0, 0x7c, 0x7f, 0x79, 0x5b, 0xed,
    0x81, 0xa2, 0xe7, 0x7d, 0xc5, 0x34, 0x25, 0x76, 0xf6, 0xa0, 0xd1, 0x41, 0x98, 0xf4, 0x6b, 0x91, 0x07, 0x49, 0x42, 0x7c, 0x2e,
    0xed, 0x65, 0x9c, 0x18, 0x30, 0x03, 0x40, 0x83, 0x21, 0x57, 0x41, 0x27, 0x96, 0x60, 0x89, 0x23, 0xbd, 0x2d, 0x7b, 0x67, 0xc1,
    0xf7, 0x8d, 0x58, 0x0c, 0x07, 0x93, 0xb1, 0x4c, 0xad, 0x47, 0xb4, 0x8d, 0xae, 0xa2, 0x89, 0x37, 0xdf, 0x7b, 0x67, 0xc9, 0x88,
    0xb4, 0x0d, 0xd9, 0x5f, 0xe3, 0x7d, 0xa1, 0xe1, 0xf8, 0xd3, 0xa0, 0x40, 0xe7, 0x54, 0x62, 0x44, 0xf3, 0xe3, 0xf3, 0x84, 0x47,
    0xa1, 0xe5, 0xae, 0x14, 0xac, 0xca, 0x26, 0x11, 0x30, 0x04, 0x10, 0x88, 0xb6, 0x4a, 0xaa, 0xbd, 0x2d, 0xe3, 0x40, 0x15, 0x5c,
    0xc2, 0xd2, 0x83, 0x57, 0x3b, 0xcf, 0x18
};

auto SeededEncodedSigma2TBE()
{
    std::vector<uint8_t> EncodedSigma2TBEVector(std::begin(FuzzSeed_EncodedSigma2TBE_Node01_02_Chip),
                                                std::end(FuzzSeed_EncodedSigma2TBE_Node01_02_Chip));

    return Arbitrary<vector<uint8_t>>().WithSeeds({ EncodedSigma2TBEVector });
}

FUZZ_TEST(FuzzCASE, ParseSigma2TBE)
    .WithDomains(
        // responderNOC (Max size = Credentials::kMaxCHIPCertLength)
        Arbitrary<vector<uint8_t>>().WithSize(Credentials::kMaxCHIPCertLength),
        // responderICAC (Max size = Credentials::kMaxCHIPCertLength)
        Arbitrary<vector<uint8_t>>().WithSize(Credentials::kMaxCHIPCertLength),
        // signature (Original size = kMax_ECDSA_Signature_Length)
        Arbitrary<vector<uint8_t>>().WithSize(kMax_ECDSA_Signature_Length),
        // resumptionID, (Original size = SessionResumptionStorage::kResumptionIdSize)
        Arbitrary<vector<uint8_t>>().WithSize(SessionResumptionStorage::kResumptionIdSize),
        // Garbage payload to pass to ParseSigma2TBEData
        Arbitrary<vector<uint8_t>>(),
        // Random BitFlip index
        InRange<size_t>(0, 200),
        // Random bit position between (0..7)
        InRange<size_t>(0, 7));

/****************************************************************************** */
size_t validMsgR3SignedLen = 666;

// These messages are extracted from unit tests to serve as fuzzing seeds, allowing the fuzzer to start with realistic inputs.
// TODO #37654: Replace this extracted data with official test vectors when available
uint8_t FuzzSeed_MsgR3Signed_Node01_02_Chip[] = {
    0x15, 0x31, 0x01, 0x0d, 0x01, 0x15, 0x30, 0x01, 0x08, 0x0d, 0x90, 0x93, 0x53, 0x46, 0xb0, 0x5c, 0xbc, 0x24, 0x02, 0x01, 0x37,
    0x03, 0x27, 0x14, 0x01, 0x00, 0x00, 0x00, 0xca, 0xca, 0xca, 0xca, 0x18, 0x26, 0x04, 0xef, 0x17, 0x1b, 0x27, 0x26, 0x05, 0x6e,
    0xb5, 0xb9, 0x4c, 0x37, 0x06, 0x27, 0x11, 0x02, 0x00, 0x01, 0x00, 0xde, 0xde, 0xde, 0xde, 0x27, 0x15, 0x1d, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xb0, 0xfa, 0x18, 0x24, 0x07, 0x01, 0x24, 0x08, 0x01, 0x30, 0x09, 0x41, 0x04, 0x96, 0x5f, 0x78, 0xc5, 0x37, 0xec,
    0xe1, 0xb8, 0xc3, 0x4a, 0x7b, 0x98, 0xb9, 0xaa, 0x45, 0xf1, 0x35, 0x63, 0xa5, 0x02, 0xb1, 0x97, 0x9a, 0x60, 0x7b, 0xd0, 0xc4,
    0x19, 0x88, 0xbd, 0xd0, 0xf0, 0xbb, 0xb8, 0x98, 0x16, 0xc2, 0x07, 0xe3, 0xb5, 0x15, 0xd9, 0x26, 0x41, 0x59, 0xf7, 0x8b, 0xd0,
    0x97, 0x8e, 0x32, 0xd7, 0x4c, 0x6d, 0x05, 0x5a, 0x14, 0x9e, 0x8e, 0x9d, 0xba, 0x40, 0x19, 0xbf, 0x37, 0x0a, 0x35, 0x01, 0x28,
    0x01, 0x18, 0x24, 0x02, 0x01, 0x36, 0x03, 0x04, 0x02, 0x04, 0x01, 0x18, 0x30, 0x04, 0x14, 0x56, 0x7b, 0x4f, 0x20, 0xe4, 0xb9,
    0xc7, 0xbd, 0x27, 0xb2, 0x9b, 0x3d, 0xce, 0x6a, 0x76, 0xf7, 0xcd, 0x8e, 0xcc, 0xb6, 0x30, 0x05, 0x14, 0xcc, 0x13, 0x08, 0xaf,
    0x82, 0xcf, 0xee, 0x50, 0x5e, 0xb2, 0x3b, 0x57, 0xbf, 0xe8, 0x6a, 0x31, 0x16, 0x65, 0x53, 0x5f, 0x18, 0x30, 0x0b, 0x40, 0x60,
    0x58, 0x11, 0x4b, 0xa7, 0x21, 0x82, 0xfc, 0xf6, 0x30, 0x1f, 0x7a, 0x08, 0x1b, 0xca, 0x5a, 0x84, 0x82, 0x02, 0x43, 0x1a, 0x52,
    0xfd, 0xbf, 0xf4, 0x97, 0xd8, 0xdd, 0x6f, 0x9a, 0x59, 0x59, 0x7b, 0xad, 0xcc, 0xd6, 0xa5, 0x6d, 0x70, 0xef, 0xd8, 0xc9, 0x7c,
    0x49, 0x6e, 0xba, 0x7e, 0x28, 0x01, 0xd7, 0x33, 0x7d, 0xcf, 0xf7, 0x4d, 0x78, 0xe4, 0x6e, 0xcd, 0x3a, 0x08, 0xcc, 0xba, 0xe3,
    0x18, 0x30, 0x02, 0xfc, 0x15, 0x30, 0x01, 0x08, 0x69, 0xd8, 0x6a, 0x8d, 0x80, 0xfc, 0x8f, 0x5d, 0x24, 0x02, 0x01, 0x37, 0x03,
    0x27, 0x14, 0x01, 0x00, 0x00, 0x00, 0xca, 0xca, 0xca, 0xca, 0x18, 0x26, 0x04, 0xef, 0x17, 0x1b, 0x27, 0x26, 0x05, 0x6e, 0xb5,
    0xb9, 0x4c, 0x37, 0x06, 0x27, 0x13, 0x03, 0x00, 0x00, 0x00, 0xca, 0xca, 0xca, 0xca, 0x18, 0x24, 0x07, 0x01, 0x24, 0x08, 0x01,
    0x30, 0x09, 0x41, 0x04, 0x5f, 0x94, 0xf5, 0x7e, 0x0b, 0x13, 0xc9, 0xcf, 0xcf, 0x96, 0xdf, 0xe1, 0xfc, 0xe7, 0x88, 0x8d, 0x56,
    0x4c, 0xc2, 0x09, 0xc5, 0x5c, 0x45, 0x08, 0xe4, 0x4d, 0xcf, 0x16, 0xba, 0x2e, 0x09, 0x66, 0x2f, 0x9e, 0xec, 0xf1, 0x9f, 0x40,
    0xb0, 0xe8, 0x8a, 0x0b, 0x28, 0x15, 0xda, 0x9e, 0xe1, 0x0a, 0x3a, 0x17, 0x7c, 0x25, 0x1f, 0x43, 0x4f, 0x5b, 0x0f, 0x26, 0x3c,
    0xe7, 0xde, 0x62, 0x78, 0xc6, 0x37, 0x0a, 0x35, 0x01, 0x29, 0x01, 0x18, 0x24, 0x02, 0x60, 0x30, 0x04, 0x14, 0x44, 0x0c, 0xc6,
    0x92, 0x31, 0xc4, 0xcb, 0x5b, 0x37, 0x94, 0x24, 0x26, 0xf8, 0x1b, 0xbe, 0x24, 0xb7, 0xef, 0x34, 0x5c, 0x30, 0x05, 0x14, 0xcc,
    0x13, 0x08, 0xaf, 0x82, 0xcf, 0xee, 0x50, 0x5e, 0xb2, 0x3b, 0x57, 0xbf, 0xe8, 0x6a, 0x31, 0x16, 0x65, 0x53, 0x5f, 0x18, 0x30,
    0x0b, 0x40, 0xad, 0xb8, 0x5b, 0x5d, 0x68, 0xcb, 0xfd, 0x36, 0x14, 0x0d, 0x8c, 0x9d, 0x12, 0x90, 0x14, 0xc4, 0x5f, 0xa7, 0xca,
    0x19, 0x1f, 0x34, 0xd9, 0xaf, 0x24, 0x1d, 0xb7, 0x17, 0x36, 0xe6, 0x0f, 0x44, 0x19, 0x9b, 0xc0, 0x7c, 0x7f, 0x79, 0x5b, 0xed,
    0x81, 0xa2, 0xe7, 0x7d, 0xc5, 0x34, 0x25, 0x76, 0xf6, 0xa0, 0xd1, 0x41, 0x98, 0xf4, 0x6b, 0x91, 0x07, 0x49, 0x42, 0x7c, 0x2e,
    0xed, 0x65, 0x9c, 0x18, 0x30, 0x03, 0x41, 0x04, 0x4f, 0xfe, 0x22, 0xd7, 0xbd, 0x25, 0x4e, 0xc4, 0x35, 0xe4, 0x96, 0xbb, 0xbd,
    0xd3, 0x32, 0x8e, 0x90, 0xf8, 0x4d, 0xf6, 0x0a, 0x16, 0x58, 0xfd, 0x60, 0xd9, 0x8d, 0xd4, 0x57, 0x71, 0xb8, 0x04, 0xeb, 0x8c,
    0x27, 0xbf, 0xda, 0xb2, 0x0c, 0x05, 0x23, 0x31, 0x67, 0x1f, 0x13, 0x55, 0x10, 0x00, 0x7f, 0xe8, 0x84, 0x5d, 0xb9, 0x7d, 0x8e,
    0xa1, 0x77, 0x6a, 0x3d, 0xda, 0x19, 0x2f, 0x39, 0x9c, 0x30, 0x04, 0x41, 0x04, 0xa6, 0x70, 0x38, 0x16, 0x42, 0x4b, 0x21, 0xfb,
    0x9c, 0xdc, 0xe7, 0x46, 0x7c, 0x23, 0x6d, 0x5d, 0xcc, 0x0d, 0x2c, 0xb0, 0xce, 0x00, 0x5f, 0x72, 0x3b, 0xcf, 0xff, 0x44, 0x10,
    0x2a, 0x7e, 0xd8, 0x1f, 0xfc, 0x8c, 0x00, 0xd7, 0x45, 0x7a, 0xaf, 0x4c, 0x32, 0x72, 0xc8, 0xaa, 0xf2, 0x99, 0x54, 0x5d, 0x20,
    0x80, 0x43, 0x46, 0x27, 0x0b, 0x05, 0xff, 0x2b, 0xe8, 0x27, 0xc9, 0x94, 0xf0, 0x08, 0x18
};

uint8_t FuzzSeed_Tbs3Signature_Node01_02_Chip[] = {

    0x61, 0xBC, 0xA0, 0x09, 0x5B, 0x74, 0xB8, 0x78, 0x8F, 0x88, 0xE1, 0xF6, 0x06, 0x0A, 0xA4, 0x24,
    0x9C, 0x9F, 0x4C, 0x50, 0x60, 0x37, 0xF7, 0xFD, 0xBF, 0x05, 0x73, 0x03, 0x0A, 0xCC, 0xB5, 0x4D,
    0xA1, 0xA1, 0x5E, 0x88, 0xD8, 0x67, 0x6F, 0x82, 0xAF, 0xA1, 0xAC, 0xDD, 0x27, 0xA6, 0x95, 0x91,
    0xDE, 0x37, 0xB0, 0xB8, 0xF5, 0xC3, 0xEC, 0x39, 0xFA, 0xB4, 0x5B, 0x73, 0x25, 0x4F, 0x6F, 0x7E

};

void FuzzCASESession::HandleSigma3b(const std::string & fuzzInitiatorNOC, const std::string & fuzzInitiatorICAC,
                                    const std::string & fuzzFabricRCAC, const vector<uint8_t> & fuzzMsg3TBSData,
                                    const vector<uint8_t> & fuzzTbs3Signature, const vector<uint8_t> & garbagePayload,
                                    size_t bitflipIndex, size_t bitflipPosition, FabricId fuzzFabricId,
                                    const ValidationContext & fuzzValidContext)
{

    {
        CASESession::HandleSigma3Data data;

        data.initiatorNOC  = ByteSpan(reinterpret_cast<const uint8_t *>(fuzzInitiatorNOC.data()), fuzzInitiatorNOC.size());
        data.initiatorICAC = ByteSpan(reinterpret_cast<const uint8_t *>(fuzzInitiatorICAC.data()), fuzzInitiatorICAC.size());
        data.fabricRCAC    = ByteSpan(reinterpret_cast<const uint8_t *>(fuzzFabricRCAC.data()), fuzzFabricRCAC.size());

        FabricId initiatorFabricId;
        data.fabricId = fuzzFabricId;

        data.validContext = fuzzValidContext;
        bool unused       = false;

        // prepare the fuzzed Signed Sigma3 Message
        // data.msgR3SignedLen = fuzzMsg3TBSData.size();
        data.msgR3Signed.Alloc(fuzzMsg3TBSData.size());
        memcpy(data.msgR3Signed.Get(), fuzzMsg3TBSData.data(), fuzzMsg3TBSData.size());

        // prepare the fuzzed signature
        data.tbsData3Signature.SetLength(fuzzTbs3Signature.size());
        memcpy(data.tbsData3Signature.Bytes(), fuzzTbs3Signature.data(), fuzzTbs3Signature.size());

        CHIP_ERROR err = CASESession::HandleSigma3b(data, unused);
        std::cout << "fuzzed HandleSigma3b: " << err.Format() << std::endl;
    }

    // {
    //     CASESession::HandleSigma3Data data;
    //     data.initiatorNOC  = ByteSpan(TestCerts::sTestCert_Node01_02_Chip);
    //     data.initiatorICAC = ByteSpan(TestCerts::sTestCert_ICA01_Chip);
    //     data.fabricRCAC    = ByteSpan(TestCerts::sTestCert_Root01_Chip);

    //     FabricId initiatorFabricId;
    //     data.fabricId = 0xFAB000000000001D;

    //     ValidationContext validContext;

    //     data.validContext = validContext;
    //     bool unused       = false;

    //     // prepare the fuzzed Signed Sigma3 Message
    //     data.msgR3SignedLen = fuzzMsg3TBSData.size();
    //     data.msgR3Signed.Alloc(fuzzMsg3TBSData.size());
    //     memcpy(data.msgR3Signed.Get(), fuzzMsg3TBSData.data(), fuzzMsg3TBSData.size());

    //     // prepare the fuzzed signature
    //     data.tbsData3Signature.SetLength(fuzzTbs3Signature.size());
    //     memcpy(data.tbsData3Signature.Bytes(), fuzzTbs3Signature.data(), fuzzTbs3Signature.size());

    //     CHIP_ERROR err = CASESession::HandleSigma3b(data, unused);
    //     std::cout << "Valid HandleSigma3b: " << err.Format() << std::endl;
    // }

    /* VALID MSGr3signed and Signature
            // Allocate a buffer to hold the SignedMessage
            data.msgR3Signed.Alloc(validMsgR3SignedLen);
            memcpy(data.msgR3Signed.Get(), &FuzzSeed_MsgR3Signed_Node01_02_Chip, sizeof(FuzzSeed_MsgR3Signed_Node01_02_Chip));
            data.msgR3SignedLen = validMsgR3SignedLen;

            data.tbsData3Signature.SetLength(sizeof(FuzzSeed_Tbs3Signature_Node01_02_Chip));
            memcpy(data.tbsData3Signature.Bytes(), &FuzzSeed_Tbs3Signature_Node01_02_Chip,
       sizeof(FuzzSeed_Tbs3Signature_Node01_02_Chip));
    */
    // {
    //     CASESession::HandleSigma3Data data;
    //     //   data.initiatorNOC  = ByteSpan(TestCerts::sTestCert_Node01_02_Chip);
    //     data.initiatorICAC = ByteSpan(TestCerts::sTestCert_ICA01_Chip);
    //     data.fabricRCAC    = ByteSpan(TestCerts::sTestCert_Root01_Chip);

    //     uint8_t NearlyCorrectNOC[Credentials::kMaxCHIPCertLength];
    //     MutableByteSpan NearlyCorrectNOCSpan(NearlyCorrectNOC, sizeof(NearlyCorrectNOC));
    //     CopySpanToMutableSpan(ByteSpan(TestCerts::sTestCert_Node01_02_Chip), NearlyCorrectNOCSpan);

    //     //  Flip a single bit if the buffer is non-empty
    //     if (NearlyCorrectNOCSpan.size() > 0)
    //     {
    //         size_t actualIndex = bitflipIndex % NearlyCorrectNOCSpan.size(); // limit index to valid range
    //         // Flip the bit
    //         NearlyCorrectNOCSpan[actualIndex] ^= static_cast<uint8_t>(1 << bitflipPosition);
    //     }

    //     data.initiatorNOC = ByteSpan(NearlyCorrectNOCSpan);
    //     FabricId initiatorFabricId;
    //     data.fabricId = 0xFAB000000000001D;

    //     chip::Credentials::ValidationContext validContext;

    //     data.validContext = validContext;
    //     bool unused       = false;

    //     CHIP_ERROR err = CASESession::HandleSigma3b(data, unused);
    //     std::cout << "******2. NOC Bitflip: " << err.Format() << std::endl;
    // }

    // {
    //     CASESession::HandleSigma3Data data;
    //     data.initiatorNOC = ByteSpan(TestCerts::sTestCert_Node01_02_Chip);
    //     // data.initiatorICAC = ByteSpan(TestCerts::sTestCert_ICA01_Chip);
    //     data.fabricRCAC = ByteSpan(TestCerts::sTestCert_Root01_Chip);

    //     uint8_t NearlyCorrectICAC[Credentials::kMaxCHIPCertLength];
    //     MutableByteSpan NearlyCorrecICACSpan(NearlyCorrectICAC, sizeof(NearlyCorrectICAC));
    //     CopySpanToMutableSpan(ByteSpan(TestCerts::sTestCert_ICA01_Chip), NearlyCorrecICACSpan);

    //     //  Flip a single bit if the buffer is non-empty
    //     if (NearlyCorrecICACSpan.size() > 0)
    //     {
    //         size_t actualIndex = bitflipIndex % NearlyCorrecICACSpan.size(); // limit index to valid range
    //         // Flip the bit
    //         NearlyCorrecICACSpan[actualIndex] ^= static_cast<uint8_t>(1 << bitflipPosition);
    //     }

    //     data.initiatorICAC = ByteSpan(NearlyCorrecICACSpan);
    //     FabricId initiatorFabricId;
    //     data.fabricId = 0xFAB000000000001D;

    //     chip::Credentials::ValidationContext validContext;

    //     data.validContext = validContext;
    //     bool unused       = false;

    //     CHIP_ERROR err = CASESession::HandleSigma3b(data, unused);
    //     std::cout << "******2. ICAC Bitflip: " << err.Format() << std::endl;
    // }

    // {
    //     CASESession::HandleSigma3Data data;
    //     data.initiatorNOC  = ByteSpan(TestCerts::sTestCert_Node01_02_Chip);
    //     data.initiatorICAC = ByteSpan(TestCerts::sTestCert_ICA01_Chip);
    //     // data.fabricRCAC    = ByteSpan(TestCerts::sTestCert_Root01_Chip);

    //     uint8_t NearlyCorrectRCAC[Credentials::kMaxCHIPCertLength];
    //     MutableByteSpan NearlyCorrectRCACSpan(NearlyCorrectRCAC, sizeof(NearlyCorrectRCAC));
    //     CopySpanToMutableSpan(ByteSpan(TestCerts::sTestCert_Root01_Chip), NearlyCorrectRCACSpan);

    //     //  Flip a single bit if the buffer is non-empty
    //     if (NearlyCorrectRCACSpan.size() > 0)
    //     {
    //         size_t actualIndex = bitflipIndex % NearlyCorrectRCACSpan.size(); // limit index to valid range
    //         // Flip the bit
    //         NearlyCorrectRCACSpan[actualIndex] ^= static_cast<uint8_t>(1 << bitflipPosition);
    //     }

    //     data.fabricRCAC = ByteSpan(NearlyCorrectRCACSpan);
    //     FabricId initiatorFabricId;
    //     data.fabricId = 0xFAB000000000001D;

    //     chip::Credentials::ValidationContext validContext;

    //     data.validContext = validContext;
    //     bool unused       = false;

    //     CHIP_ERROR err = CASESession::HandleSigma3b(data, unused);
    //     std::cout << "******2. RCAC Bitflip: " << err.Format() << std::endl;
    // // }
    // }
}
void HandleSigma3b(const std::string & initiatorNOC, const std::string & initiatorICAC, const std::string & fabricRCAC,
                   const vector<uint8_t> & msg3TBSData, const vector<uint8_t> & Tbs3Signature,
                   const vector<uint8_t> & garbagePayload, size_t bitflipIndex, size_t bitflipPosition, FabricId fuzzedFabricId,
                   const ValidationContext & validContext)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    FuzzCASESession fuzzCaseSession;
    fuzzCaseSession.HandleSigma3b(initiatorNOC, initiatorICAC, fabricRCAC, msg3TBSData, Tbs3Signature, garbagePayload, bitflipIndex,
                                  bitflipPosition, fuzzedFabricId, validContext);

    chip::Platform::MemoryShutdown();
}
// // FUZZ_TEST(FuzzCASE, HandleSigma3b)
// //     .WithDomains(
// //         // initiatorNOC (Max size = Credentials::kMaxCHIPCertLength)
// //         Arbitrary<vector<uint8_t>>().WithSize(Credentials::kMaxCHIPCertLength),
// //         // initiatorICAC (Max size = Credentials::kMaxCHIPCertLength)
// //         Arbitrary<vector<uint8_t>>().WithSize(Credentials::kMaxCHIPCertLength),
// //         // signature (Original size = kMax_ECDSA_Signature_Length)
// //         Arbitrary<vector<uint8_t>>().WithSize(kMax_ECDSA_Signature_Length),
// //         // resumptionID, (Original size = SessionResumptionStorage::kResumptionIdSize)
// //         Arbitrary<vector<uint8_t>>().WithSize(SessionResumptionStorage::kResumptionIdSize),
// //         // Garbage payload to pass to ParseSigma2TBEData
// //         Arbitrary<vector<uint8_t>>(),
// //         // Random BitFlip index
// //         InRange<size_t>(0, 200),
// //         // Random bit position between (0..7)
// //         InRange<size_t>(0, 7));

std::string kDictionaryPath = "/home/aya/repos/connectedhomeipDELETEME/connectedhomeip/src/credentials/tests/dict/der.dict";

auto initiatorNOC()
{
    std::string data(TestCerts::sTestCert_Node01_02_Chip.data(),
                     TestCerts::sTestCert_Node01_02_Chip.data() + TestCerts::sTestCert_Node01_02_Chip.size());
    return Arbitrary<std::string>().WithSeeds({ data }).WithDictionary(ReadDictionaryFromFile(kDictionaryPath));
}

auto initiatorICAC()
{
    std::string data(TestCerts::sTestCert_ICA01_Chip.data(),
                     TestCerts::sTestCert_ICA01_Chip.data() + TestCerts::sTestCert_ICA01_Chip.size());
    return Arbitrary<std::string>().WithSeeds({ data }).WithDictionary(ReadDictionaryFromFile(kDictionaryPath));
}

auto fabricRCAC()
{
    std::string data(TestCerts::sTestCert_Root01_Chip.data(),
                     TestCerts::sTestCert_Root01_Chip.data() + TestCerts::sTestCert_Root01_Chip.size());
    return Arbitrary<std::string>().WithSeeds({ data }).WithDictionary(ReadDictionaryFromFile(kDictionaryPath));
}

auto AnyFabricId()
{
    return Arbitrary<FabricId>().WithSeeds({ 0xFAB000000000001D });
}

auto fuzzMsgR3Signed()
{
    std::vector<uint8_t> data(FuzzSeed_MsgR3Signed_Node01_02_Chip,
                              FuzzSeed_MsgR3Signed_Node01_02_Chip + sizeof(FuzzSeed_MsgR3Signed_Node01_02_Chip));

    return Arbitrary<vector<uint8_t>>().WithSeeds({ data });
}

auto fuzzTbs3Signature()
{
    std::vector<uint8_t> data(FuzzSeed_Tbs3Signature_Node01_02_Chip,
                              FuzzSeed_Tbs3Signature_Node01_02_Chip + sizeof(FuzzSeed_Tbs3Signature_Node01_02_Chip));

    return Arbitrary<vector<uint8_t>>().WithSize(kMax_ECDSA_Signature_Length).WithSeeds({ data });
}

auto AnyValidationContext()
{
    // Defining Domains to Pass to Map
    auto requiredKeyUsages   = ElementOf<KeyUsageFlags>({
        KeyUsageFlags::kDigitalSignature,
        KeyUsageFlags::kNonRepudiation,
        KeyUsageFlags::kKeyEncipherment,
        KeyUsageFlags::kDataEncipherment,
        KeyUsageFlags::kKeyAgreement,
        KeyUsageFlags::kKeyCertSign,
        KeyUsageFlags::kCRLSign,
        KeyUsageFlags::kEncipherOnly,
        KeyUsageFlags::kDecipherOnly,
    });
    auto requiredKeyPurposes = ElementOf<KeyPurposeFlags>({ KeyPurposeFlags::kServerAuth, KeyPurposeFlags::kClientAuth,
                                                            KeyPurposeFlags::kCodeSigning, KeyPurposeFlags::kEmailProtection,
                                                            KeyPurposeFlags::kTimeStamping, KeyPurposeFlags::kOCSPSigning });
    auto requiredCertType    = ElementOf<CertType>({ CertType::kNotSpecified, CertType::kRoot, CertType::kICA, CertType::kNode,
                                                     CertType::kFirmwareSigning, CertType::kNetworkIdentity });
    return Map(
        [](const auto & keyUsages, const auto & keyPurposes, const auto & certType) {
            ValidationContext fuzzValidationContext;

            fuzzValidationContext.Reset();
            fuzzValidationContext.mRequiredKeyUsages.Set(keyUsages);
            fuzzValidationContext.mRequiredKeyPurposes.Set(keyPurposes);
            fuzzValidationContext.mRequiredCertType = certType;

            return fuzzValidationContext;
        },
        // fuzzValidationContext);
        requiredKeyUsages, requiredKeyPurposes, requiredCertType);
}

FUZZ_TEST(FuzzCASE, HandleSigma3b)
    .WithDomains(
        // initiatorNOC (Max size = Credentials::kMaxCHIPCertLength)
        initiatorNOC(),
        // initiatorICAC (Max size = Credentials::kMaxCHIPCertLength)
        initiatorICAC(),
        // fabricRCAC
        fabricRCAC(),
        // resumptionID, (Original size = SessionResumptionStorage::kResumptionIdSize)
        fuzzMsgR3Signed(),
        // signature (Original size = kMax_ECDSA_Signature_Length)
        fuzzTbs3Signature(),

        // Garbage payload to pass to ParseSigma2TBEData
        Arbitrary<vector<uint8_t>>(),
        // Random BitFlip index
        InRange<size_t>(0, 200),
        // Random bit position between (0..7)
        InRange<size_t>(0, 7),
        // Any Fabric ID
        AnyFabricId(),
        // Any Validation Context
        AnyValidationContext());
//.WithSeeds(TestCerts::sTestCert_Node01_02_Chip, TestCerts::sTestCert_ICA01_Chip);

/******************************************************************************************** */

CHIP_ERROR EncodeSigma3(const vector<uint8_t> & fuzzEncrypted3, MutableByteSpan & encodedSpan)
{

    TLV::TLVType outerContainerType = TLV::kTLVType_NotSpecified;
    TLVWriter tlvWriter;
    tlvWriter.Init(encodedSpan);

    ReturnErrorOnFailure(tlvWriter.StartContainer(TLV::AnonymousTag(), TLV::kTLVType_Structure, outerContainerType));
    ReturnErrorOnFailure(tlvWriter.PutBytes(TLV::ContextTag(1), fuzzEncrypted3.data(), fuzzEncrypted3.size()));
    ReturnErrorOnFailure(tlvWriter.EndContainer(outerContainerType));

    encodedSpan.reduce_size(tlvWriter.GetLengthWritten());
    ReturnErrorOnFailure(tlvWriter.Finalize());

    return CHIP_NO_ERROR;
}
void ParseSigma3(const vector<uint8_t> & fuzzEncrypted3, const vector<uint8_t> & fuzzEncodedSigma3)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);

    // 1st TestCase, passing a structured payload to ParseSigma3
    {
        // Construct Sigma3
        size_t dataLen = TLV::EstimateStructOverhead(fuzzEncrypted3.size());
        chip::Platform::ScopedMemoryBuffer<uint8_t> mem;
        ASSERT_TRUE(mem.Calloc(dataLen));
        MutableByteSpan encodedSpan(mem.Get(), dataLen);
        ASSERT_EQ(CHIP_NO_ERROR, EncodeSigma3(fuzzEncrypted3, encodedSpan));

        // Prepare Sigma3 Parsing
        TLV::ContiguousBufferTLVReader tlvReader;
        tlvReader.Init(encodedSpan);
        Platform::ScopedMemoryBufferWithSize<uint8_t> outMsgR3Encrypted;
        MutableByteSpan outMsgR3EncryptedPayload;
        ByteSpan outMsgR3MIC;

        // Parse Sigma3
        CHIP_ERROR err = CHIP_NO_ERROR;
        err            = FuzzCASESession::ParseSigma3(tlvReader, outMsgR3Encrypted, outMsgR3EncryptedPayload, outMsgR3MIC);
        std::cout << err.Format() << std::endl;

        mem.Free();
    }

    // 2nd TestCase: a fuzzed fully-enoced Sigma3 to ParseSigma3 to test if it crashes
    {

        System::PacketBufferHandle EncodedSigma3 =
            System::PacketBufferHandle::NewWithData(fuzzEncodedSigma3.data(), fuzzEncodedSigma3.size(), 0, 38);
        System::PacketBufferTLVReader tlvReader2;
        tlvReader2.Init(std::move(EncodedSigma3));

        Platform::ScopedMemoryBufferWithSize<uint8_t> outMsgR3Encrypted;
        MutableByteSpan outMsgR3EncryptedPayload;
        ByteSpan outMsgR3MIC;

        CHIP_ERROR err = CHIP_NO_ERROR;
        err            = FuzzCASESession::ParseSigma3(tlvReader2, outMsgR3Encrypted, outMsgR3EncryptedPayload, outMsgR3MIC);
        std::cout << "Seeded Encoded Sigma3:" << err.Format() << std::endl;
    }

    chip::Platform::MemoryShutdown();
}

// These messages are extracted from unit tests to serve as fuzzing seeds, allowing the fuzzer to start with realistic inputs.
// TODO #37654: Replace this extracted data with official test vectors when available
uint8_t FuzzSeed_EncodedSigma3_Node01_02_Chip[] = {
    0x15, 0x31, 0x01, 0x65, 0x02, 0x82, 0x13, 0xbf, 0x62, 0x33, 0x08, 0x3c, 0x6e, 0x14, 0x21, 0xbc, 0x69, 0x97, 0x33, 0x94, 0xa8,
    0xea, 0x68, 0x34, 0x3b, 0xe2, 0x13, 0xe1, 0x72, 0x77, 0x7d, 0x0a, 0x3b, 0x61, 0x7b, 0x42, 0x6e, 0xa9, 0x6e, 0xed, 0x38, 0x1d,
    0x59, 0x35, 0x5e, 0x06, 0x82, 0x12, 0x84, 0xd3, 0xad, 0x80, 0x42, 0x6e, 0x3e, 0x03, 0x86, 0x3b, 0x38, 0x09, 0xda, 0xcc, 0xd0,
    0xe9, 0x8c, 0xd0, 0xe1, 0x9a, 0x6e, 0xdd, 0x4f, 0xd1, 0xfe, 0xf5, 0x91, 0xe0, 0xc1, 0xb1, 0xda, 0xf2, 0x85, 0xb5, 0x9d, 0x03,
    0x25, 0xe3, 0x21, 0xec, 0xe3, 0x7f, 0x71, 0xab, 0xe8, 0xf0, 0xaa, 0x33, 0xac, 0x21, 0x87, 0x67, 0x89, 0xe9, 0x70, 0xab, 0x93,
    0x62, 0xa2, 0x95, 0xe2, 0x1d, 0xaf, 0xf0, 0x97, 0x81, 0x93, 0x2c, 0x0d, 0x06, 0x73, 0x25, 0x60, 0x4d, 0x66, 0x2e, 0x60, 0xc5,
    0xa5, 0x8d, 0x8b, 0xe0, 0xb6, 0xa7, 0x61, 0x73, 0x80, 0x8b, 0xbc, 0x7c, 0xf3, 0xdb, 0x7f, 0x9e, 0x65, 0x8f, 0x58, 0xcd, 0xba,
    0x04, 0x60, 0x8c, 0x4c, 0x69, 0xca, 0x54, 0x33, 0x29, 0xce, 0x09, 0x75, 0x7f, 0x01, 0x5c, 0xc7, 0x0c, 0x60, 0xa3, 0x96, 0x36,
    0x62, 0x71, 0xf7, 0x30, 0xfd, 0x8f, 0x4f, 0x08, 0x6f, 0xe6, 0x0b, 0xda, 0x16, 0x3f, 0x84, 0x06, 0xed, 0xd3, 0xf5, 0x99, 0xed,
    0x04, 0x72, 0x00, 0x55, 0x80, 0x5d, 0x54, 0x4a, 0x41, 0xcb, 0x44, 0x37, 0x00, 0x9c, 0x89, 0x0b, 0xa4, 0xba, 0xe7, 0x87, 0xd6,
    0xa7, 0x32, 0x07, 0x92, 0x4e, 0xd8, 0x3d, 0x5e, 0xb2, 0xe0, 0x49, 0xc6, 0xda, 0xc1, 0x74, 0x5f, 0x3e, 0x4d, 0x02, 0x72, 0x86,
    0x2c, 0x0d, 0x0a, 0xf7, 0xce, 0x0e, 0xb7, 0x89, 0xc2, 0x92, 0xa3, 0x30, 0x1e, 0x65, 0x76, 0x05, 0x34, 0xb4, 0x29, 0x4e, 0x0a,
    0xe7, 0x4c, 0xf0, 0x51, 0xd8, 0xfd, 0x12, 0x82, 0x9e, 0xbf, 0xbd, 0x1b, 0xbd, 0x79, 0x76, 0x5d, 0xb9, 0x81, 0x64, 0xaf, 0x9b,
    0xaa, 0x24, 0x5d, 0xa5, 0x43, 0xe5, 0xa1, 0x9f, 0x3e, 0x80, 0xcc, 0x00, 0xed, 0x23, 0xb6, 0x82, 0xd0, 0xfa, 0x66, 0x47, 0x71,
    0x5d, 0x60, 0x98, 0xc6, 0x44, 0xfa, 0xf4, 0xfe, 0xc1, 0x85, 0x38, 0xfc, 0xf8, 0xff, 0xb4, 0x30, 0x08, 0x86, 0xae, 0xf6, 0xca,
    0x3f, 0xda, 0x65, 0xf3, 0x1b, 0x81, 0xcd, 0xf0, 0x78, 0xfc, 0x97, 0x92, 0x56, 0xa2, 0xa8, 0xd6, 0x50, 0x72, 0xb4, 0x53, 0xfd,
    0x41, 0xea, 0xd8, 0xef, 0x29, 0x65, 0x73, 0xf3, 0xe1, 0xe1, 0x0f, 0x57, 0x25, 0x82, 0xfc, 0x0f, 0x3e, 0x30, 0x81, 0xec, 0xa8,
    0xa0, 0x34, 0x26, 0xef, 0x07, 0x32, 0xb9, 0x5a, 0x1a, 0xdb, 0xc9, 0x4e, 0x28, 0x5f, 0xb9, 0xe8, 0x5e, 0xca, 0x11, 0xc6, 0x4b,
    0x4e, 0x73, 0x5b, 0x84, 0xb8, 0x6c, 0x8a, 0x9f, 0xe3, 0xd7, 0x8c, 0xbc, 0xbb, 0x7d, 0xaa, 0xbd, 0xd9, 0xdb, 0x28, 0x06, 0x30,
    0x2f, 0x93, 0x20, 0x68, 0x21, 0x58, 0x5d, 0x64, 0xf4, 0xd7, 0xce, 0xca, 0x7c, 0x40, 0x06, 0x3b, 0x87, 0xdc, 0xbe, 0x3e, 0x1d,
    0xc2, 0xed, 0x46, 0xcd, 0x0a, 0x44, 0x28, 0x2f, 0x78, 0x85, 0x55, 0x86, 0xb3, 0xc0, 0x96, 0xc6, 0xb6, 0x5e, 0x8f, 0xaa, 0x78,
    0x75, 0xe6, 0xbc, 0x8f, 0x90, 0x8d, 0x14, 0xad, 0xca, 0xc7, 0x16, 0xe3, 0x4b, 0xea, 0xac, 0xfd, 0x23, 0xd6, 0xc9, 0xca, 0x40,
    0x0a, 0xfd, 0x72, 0xad, 0xb2, 0x03, 0x21, 0xdb, 0x42, 0x3f, 0x2e, 0x65, 0xca, 0x07, 0xac, 0x81, 0xdf, 0xc4, 0x2b, 0xa8, 0x3c,
    0x70, 0x99, 0xf0, 0x73, 0x5f, 0x99, 0xcf, 0x53, 0x34, 0xf0, 0xcd, 0x50, 0x9c, 0xbe, 0xf0, 0x2f, 0x33, 0x3a, 0x7e, 0x5f, 0x86,
    0xca, 0xe5, 0xe5, 0x10, 0xc4, 0x35, 0xc8, 0xb9, 0x38, 0x8c, 0xa4, 0x95, 0x51, 0xcc, 0xb8, 0x77, 0xf1, 0x39, 0xcc, 0xb3, 0x31,
    0x29, 0xb9, 0x7a, 0x5c, 0x4d, 0x36, 0x04, 0xa7, 0x5c, 0x56, 0x00, 0xae, 0x2b, 0xe2, 0x57, 0x9f, 0xe0, 0x35, 0x57, 0x80, 0x15,
    0x02, 0x17, 0xfd, 0xde, 0xe7, 0x1c, 0x49, 0xe6, 0xda, 0x9f, 0xa9, 0xa9, 0x1d, 0x20, 0x4e, 0xf5, 0x82, 0xf1, 0x1f, 0xaa, 0xd2,
    0x6b, 0x35, 0x4d, 0xda, 0xe2, 0xea, 0xd5, 0xc0, 0xa7, 0x1b, 0x1a, 0xcd, 0x8d, 0x8f, 0xde, 0x25, 0x6a, 0x18, 0x7c, 0xa5, 0xc3,
    0xcc, 0x46, 0x16, 0x9a, 0x7e, 0x48, 0x84, 0x8e, 0xa6, 0xdc, 0x84, 0x51, 0x36, 0x01, 0x8c, 0xaf, 0x04, 0xd7, 0x80, 0xbd, 0x88,
    0x36, 0xe3, 0x2c, 0x32, 0xce, 0xb7, 0xc0, 0x14, 0xd2, 0x18
};

auto SeededEncodedSigma3()
{
    std::vector<uint8_t> EncodedSigma3Vector(std::begin(FuzzSeed_EncodedSigma3_Node01_02_Chip),
                                             std::end(FuzzSeed_EncodedSigma3_Node01_02_Chip));

    return Arbitrary<vector<uint8_t>>().WithSeeds({ EncodedSigma3Vector });
}

FUZZ_TEST(FuzzCASE, ParseSigma3)
    .WithDomains(
        // Encrypted3 .WithSize(kSigmaParamRandomNumberSize)
        Arbitrary<vector<uint8_t>>(),
        // Fuzzing a fully encoded Sigma3, to pass to ParseSigma3
        SeededEncodedSigma3());
/******************************************************************************************** */

CHIP_ERROR EncodeSigma3TBEData(const vector<uint8_t> & fuzzInitiatorNOC, const vector<uint8_t> & fuzzInitiatorICAC,
                               const vector<uint8_t> & fuzzSignature, MutableByteSpan & outEncodedSpan)
{
    TLV::TLVType outerContainerType = TLV::kTLVType_NotSpecified;
    TLVWriter tlvWriter;
    tlvWriter.Init(outEncodedSpan);

    ReturnErrorOnFailure(tlvWriter.StartContainer(TLV::AnonymousTag(), TLV::kTLVType_Structure, outerContainerType));
    ReturnErrorOnFailure(tlvWriter.PutBytes(TLV::ContextTag(1), fuzzInitiatorNOC.data(), fuzzInitiatorNOC.size()));
    ReturnErrorOnFailure(tlvWriter.PutBytes(TLV::ContextTag(2), fuzzInitiatorICAC.data(), fuzzInitiatorICAC.size()));
    ReturnErrorOnFailure(tlvWriter.PutBytes(TLV::ContextTag(3), fuzzSignature.data(), fuzzSignature.size()));
    ReturnErrorOnFailure(tlvWriter.EndContainer(outerContainerType));

    outEncodedSpan.reduce_size(tlvWriter.GetLengthWritten());
    ReturnErrorOnFailure(tlvWriter.Finalize());

    return CHIP_NO_ERROR;
}

void ParseSigma3TBEData(const vector<uint8_t> & fuzzInitiatorNOC, const vector<uint8_t> & fuzzInitiatorICAC,
                        const vector<uint8_t> & fuzzSignature, const vector<uint8_t> & fuzzEncodedSigma3TBEData)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);

    // 1st TestCase, passing a structured payload to ParseSigma3
    {
        // Construct Sigma3TBEData
        size_t dataLen = TLV::EstimateStructOverhead(fuzzInitiatorNOC.size(),  // responderNOC
                                                     fuzzInitiatorICAC.size(), // responderICAC
                                                     fuzzSignature.size()      // signature
        );

        chip::Platform::ScopedMemoryBuffer<uint8_t> mem;
        ASSERT_TRUE(mem.Calloc(dataLen));
        MutableByteSpan encodedSpan(mem.Get(), dataLen);
        ASSERT_EQ(CHIP_NO_ERROR, EncodeSigma3TBEData(fuzzInitiatorNOC, fuzzInitiatorICAC, fuzzSignature, encodedSpan));

        // Prepare Sigma3 Parsing
        FuzzCASESession::HandleSigma3Data unused;
        TLV::ContiguousBufferTLVReader tlvReader;
        tlvReader.Init(encodedSpan);

        // Parse Sigma3
        CHIP_ERROR err = CHIP_NO_ERROR;
        err            = FuzzCASESession::ParseSigma3TBEData(tlvReader, unused);
        std::cout << err.Format() << std::endl;

        mem.Free();
    }

    // 2nd TestCase : fuzzing an already fully - encoded Sigma3TBEData to ParseSigma3TBEData to test if it crashes
    {

        System::PacketBufferHandle EncodedSigma3 =
            System::PacketBufferHandle::NewWithData(fuzzEncodedSigma3TBEData.data(), fuzzEncodedSigma3TBEData.size(), 0, 38);
        System::PacketBufferTLVReader tlvReader2;
        tlvReader2.Init(std::move(EncodedSigma3));

        FuzzCASESession::HandleSigma3Data unused;

        CHIP_ERROR err = CHIP_NO_ERROR;
        err            = FuzzCASESession::ParseSigma3TBEData(tlvReader2, unused);
        std::cout << "Seeded Encoded Sigma3TBEData:" << err.Format() << std::endl;
    }

    chip::Platform::MemoryShutdown();
}

// These messages are extracted from unit tests to serve as fuzzing seeds, allowing the fuzzer to start with realistic inputs.
// TODO #37654: Replace this extracted data with official test vectors when available
uint8_t FuzzSeed_EncodedSigma3TBE_Node01_02_Chip[] = {
    0x15, 0x31, 0x01, 0x0d, 0x01, 0x15, 0x30, 0x01, 0x08, 0x0d, 0x90, 0x93, 0x53, 0x46, 0xb0, 0x5c, 0xbc, 0x24, 0x02, 0x01, 0x37,
    0x03, 0x27, 0x14, 0x01, 0x00, 0x00, 0x00, 0xca, 0xca, 0xca, 0xca, 0x18, 0x26, 0x04, 0xef, 0x17, 0x1b, 0x27, 0x26, 0x05, 0x6e,
    0xb5, 0xb9, 0x4c, 0x37, 0x06, 0x27, 0x11, 0x02, 0x00, 0x01, 0x00, 0xde, 0xde, 0xde, 0xde, 0x27, 0x15, 0x1d, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xb0, 0xfa, 0x18, 0x24, 0x07, 0x01, 0x24, 0x08, 0x01, 0x30, 0x09, 0x41, 0x04, 0x96, 0x5f, 0x78, 0xc5, 0x37, 0xec,
    0xe1, 0xb8, 0xc3, 0x4a, 0x7b, 0x98, 0xb9, 0xaa, 0x45, 0xf1, 0x35, 0x63, 0xa5, 0x02, 0xb1, 0x97, 0x9a, 0x60, 0x7b, 0xd0, 0xc4,
    0x19, 0x88, 0xbd, 0xd0, 0xf0, 0xbb, 0xb8, 0x98, 0x16, 0xc2, 0x07, 0xe3, 0xb5, 0x15, 0xd9, 0x26, 0x41, 0x59, 0xf7, 0x8b, 0xd0,
    0x97, 0x8e, 0x32, 0xd7, 0x4c, 0x6d, 0x05, 0x5a, 0x14, 0x9e, 0x8e, 0x9d, 0xba, 0x40, 0x19, 0xbf, 0x37, 0x0a, 0x35, 0x01, 0x28,
    0x01, 0x18, 0x24, 0x02, 0x01, 0x36, 0x03, 0x04, 0x02, 0x04, 0x01, 0x18, 0x30, 0x04, 0x14, 0x56, 0x7b, 0x4f, 0x20, 0xe4, 0xb9,
    0xc7, 0xbd, 0x27, 0xb2, 0x9b, 0x3d, 0xce, 0x6a, 0x76, 0xf7, 0xcd, 0x8e, 0xcc, 0xb6, 0x30, 0x05, 0x14, 0xcc, 0x13, 0x08, 0xaf,
    0x82, 0xcf, 0xee, 0x50, 0x5e, 0xb2, 0x3b, 0x57, 0xbf, 0xe8, 0x6a, 0x31, 0x16, 0x65, 0x53, 0x5f, 0x18, 0x30, 0x0b, 0x40, 0x60,
    0x58, 0x11, 0x4b, 0xa7, 0x21, 0x82, 0xfc, 0xf6, 0x30, 0x1f, 0x7a, 0x08, 0x1b, 0xca, 0x5a, 0x84, 0x82, 0x02, 0x43, 0x1a, 0x52,
    0xfd, 0xbf, 0xf4, 0x97, 0xd8, 0xdd, 0x6f, 0x9a, 0x59, 0x59, 0x7b, 0xad, 0xcc, 0xd6, 0xa5, 0x6d, 0x70, 0xef, 0xd8, 0xc9, 0x7c,
    0x49, 0x6e, 0xba, 0x7e, 0x28, 0x01, 0xd7, 0x33, 0x7d, 0xcf, 0xf7, 0x4d, 0x78, 0xe4, 0x6e, 0xcd, 0x3a, 0x08, 0xcc, 0xba, 0xe3,
    0x18, 0x30, 0x02, 0xfc, 0x15, 0x30, 0x01, 0x08, 0x69, 0xd8, 0x6a, 0x8d, 0x80, 0xfc, 0x8f, 0x5d, 0x24, 0x02, 0x01, 0x37, 0x03,
    0x27, 0x14, 0x01, 0x00, 0x00, 0x00, 0xca, 0xca, 0xca, 0xca, 0x18, 0x26, 0x04, 0xef, 0x17, 0x1b, 0x27, 0x26, 0x05, 0x6e, 0xb5,
    0xb9, 0x4c, 0x37, 0x06, 0x27, 0x13, 0x03, 0x00, 0x00, 0x00, 0xca, 0xca, 0xca, 0xca, 0x18, 0x24, 0x07, 0x01, 0x24, 0x08, 0x01,
    0x30, 0x09, 0x41, 0x04, 0x5f, 0x94, 0xf5, 0x7e, 0x0b, 0x13, 0xc9, 0xcf, 0xcf, 0x96, 0xdf, 0xe1, 0xfc, 0xe7, 0x88, 0x8d, 0x56,
    0x4c, 0xc2, 0x09, 0xc5, 0x5c, 0x45, 0x08, 0xe4, 0x4d, 0xcf, 0x16, 0xba, 0x2e, 0x09, 0x66, 0x2f, 0x9e, 0xec, 0xf1, 0x9f, 0x40,
    0xb0, 0xe8, 0x8a, 0x0b, 0x28, 0x15, 0xda, 0x9e, 0xe1, 0x0a, 0x3a, 0x17, 0x7c, 0x25, 0x1f, 0x43, 0x4f, 0x5b, 0x0f, 0x26, 0x3c,
    0xe7, 0xde, 0x62, 0x78, 0xc6, 0x37, 0x0a, 0x35, 0x01, 0x29, 0x01, 0x18, 0x24, 0x02, 0x60, 0x30, 0x04, 0x14, 0x44, 0x0c, 0xc6,
    0x92, 0x31, 0xc4, 0xcb, 0x5b, 0x37, 0x94, 0x24, 0x26, 0xf8, 0x1b, 0xbe, 0x24, 0xb7, 0xef, 0x34, 0x5c, 0x30, 0x05, 0x14, 0xcc,
    0x13, 0x08, 0xaf, 0x82, 0xcf, 0xee, 0x50, 0x5e, 0xb2, 0x3b, 0x57, 0xbf, 0xe8, 0x6a, 0x31, 0x16, 0x65, 0x53, 0x5f, 0x18, 0x30,
    0x0b, 0x40, 0xad, 0xb8, 0x5b, 0x5d, 0x68, 0xcb, 0xfd, 0x36, 0x14, 0x0d, 0x8c, 0x9d, 0x12, 0x90, 0x14, 0xc4, 0x5f, 0xa7, 0xca,
    0x19, 0x1f, 0x34, 0xd9, 0xaf, 0x24, 0x1d, 0xb7, 0x17, 0x36, 0xe6, 0x0f, 0x44, 0x19, 0x9b, 0xc0, 0x7c, 0x7f, 0x79, 0x5b, 0xed,
    0x81, 0xa2, 0xe7, 0x7d, 0xc5, 0x34, 0x25, 0x76, 0xf6, 0xa0, 0xd1, 0x41, 0x98, 0xf4, 0x6b, 0x91, 0x07, 0x49, 0x42, 0x7c, 0x2e,
    0xed, 0x65, 0x9c, 0x18, 0x30, 0x03, 0x40, 0x63, 0xb9, 0x2a, 0x76, 0xa1, 0x0b, 0x3e, 0x1c, 0x9a, 0xb5, 0xcf, 0xc3, 0x72, 0x9b,
    0x59, 0xce, 0xca, 0x6d, 0xec, 0xfb, 0x4d, 0x0a, 0xc8, 0xca, 0x09, 0x60, 0x67, 0xc9, 0xd4, 0xe0, 0xad, 0xc9, 0x6a, 0x1c, 0x52,
    0x72, 0x54, 0xc0, 0xaf, 0xa1, 0xd1, 0xf2, 0x79, 0x82, 0x2b, 0xec, 0x51, 0xd4, 0xa2, 0x3e, 0x9c, 0xbf, 0x8f, 0x2c, 0xc9, 0x84,
    0x82, 0x63, 0x73, 0x3e, 0xcf, 0xe1, 0xc1, 0xc1, 0x18
};

auto SeededEncodedSigma3TBE()
{
    std::vector<uint8_t> EncodedSigma3TBEVector(std::begin(FuzzSeed_EncodedSigma3TBE_Node01_02_Chip),
                                                std::end(FuzzSeed_EncodedSigma3TBE_Node01_02_Chip));

    return Arbitrary<vector<uint8_t>>().WithSeeds({ EncodedSigma3TBEVector });
}

FUZZ_TEST(FuzzCASE, ParseSigma3TBEData)
    .WithDomains(
        // initiatorNOC (Max size = Credentials::kMaxCHIPCertLength)
        Arbitrary<vector<uint8_t>>(),
        // initiatorICAC (Max size = Credentials::kMaxCHIPCertLength)
        Arbitrary<vector<uint8_t>>(),
        // ss
        Arbitrary<vector<uint8_t>>(),
        // ss
        SeededEncodedSigma3TBE());

} // namespace Testing
} // namespace chip
