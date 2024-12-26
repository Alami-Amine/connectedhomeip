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

namespace chip {
namespace Testing {

using namespace std;

using namespace Crypto;
using namespace fuzztest;
using namespace Transport;
using namespace Messaging;
using namespace System::Clock::Literals;

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

class FuzzCASESession
{
public:
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

    CHIP_ERROR EncodeSigma1Mock(System::PacketBufferHandle & msg, CASESession::EncodeSigma1Inputs & inputParams,
                                ByteSpan & initiatorEphPubKey);

    void HandleSigma2(const vector<uint8_t> & InitiatorRandom, uint32_t fuzzInitiatorSessionId, FabricId fuzzedFabricId,
                      const vector<uint8_t> & IPK, const vector<uint8_t> & rootPubKey);

    void EncodeParseSigma1RoundTrip(const vector<uint8_t> & InitiatorRandom, uint32_t fuzzInitiatorSessionId,
                                    const vector<uint8_t> & destinationIdentifier, FabricId fuzzedFabricId,
                                    const vector<uint8_t> & IPK, const vector<uint8_t> & rootPubKey,
                                    const vector<uint8_t> & fuzzResumptionID, const vector<uint8_t> & fuzzInitiatorResumeMIC,
                                    bool fuzzSessionResumptionRequested);
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

CHIP_ERROR FuzzCASESession::EncodeSigma1Mock(System::PacketBufferHandle & msg, CASESession::EncodeSigma1Inputs & inputParams,
                                             ByteSpan & initiatorEphPubKey)
{

    size_t dataLen = TLV::EstimateStructOverhead(inputParams.initiatorRandom.size(),   // initiatorRandom
                                                 sizeof(uint16_t),                     // initiatorSessionId,
                                                 inputParams.destinationId.size(),     // destinationId
                                                 initiatorEphPubKey.size(),            // InitiatorEphPubKey,
                                                 SessionParameters::kEstimatedTLVSize, // initiatorSessionParams
                                                 inputParams.resumptionId.size(),      // resumptionId
                                                 inputParams.initiatorResumeMIC.size() // initiatorResumeMIC
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

    CASESession::ParsedSigma1 parsedMessage;
    pairingAccessory.ParseSigma1(tlvReader, parsedMessage);

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
FUZZ_TEST(FuzzCASE_PW, ParseSigma1)
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
                                                 const vector<uint8_t> & IPK, const vector<uint8_t> & rootPubKey,
                                                 const vector<uint8_t> & resumptionID, const vector<uint8_t> & initiatorResumeMIC,
                                                 bool fuzzSessionResumptionRequested)
{

    /*CONSTRUCT SIGMA1*/

    ByteSpan fuzzedIPK(IPK.data(), IPK.size());
    ByteSpan fuzzedRootPubKey(rootPubKey.data(), rootPubKey.size());

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

    P256PublicKey key(reinterpret_cast<const uint8_t(&)[kP256_PublicKey_Length]>(*rootPubKey.data()));

    encodeParams.initiatorEphPubKey = &key;
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
FUZZ_TEST(FuzzCASE_PW, EncodeParseSigma1RoundTrip)
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

} // namespace Testing
} // namespace chip
