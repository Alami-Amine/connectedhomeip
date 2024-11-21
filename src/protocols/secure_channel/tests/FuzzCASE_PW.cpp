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

    void ParseSigma1(const vector<uint8_t> & InitiatorRandom, uint32_t fuzzInitiatorSessionId, FabricId fuzzedFabricId,
                     const vector<uint8_t> & IPK, const vector<uint8_t> & rootPubKey);
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
    pairingAccessory.ParseSigma1(tlvReader, initiatorRandom, initiatorSessionId, destinationIdentifier, initiatorPubKey,
                                 sessionResumptionRequested, resumptionId, resume1MIC);
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
