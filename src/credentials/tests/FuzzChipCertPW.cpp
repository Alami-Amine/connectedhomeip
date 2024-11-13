#include <cstddef>
#include <cstdint>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

#include "credentials/CHIPCert.h"

#include <crypto/CHIPCryptoPAL.h>

#include <lib/core/StringBuilderAdapters.h>

#include <credentials/DeviceAttestationConstructor.h>
#include <credentials/DeviceAttestationVendorReserved.h>

#include <credentials/examples/DeviceAttestationCredsExample.h>

#include <credentials/examples/ExampleDACs.h>
#include <credentials/examples/ExamplePAI.h>

#include <credentials/attestation_verifier/DeviceAttestationVerifier.h>

// this is needed for GetTestAttestationTrustStore
#include <credentials/attestation_verifier/DefaultDeviceAttestationVerifier.h>

#include <lib/core/CHIPError.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/Span.h>

#include "CHIPAttCert_test_vectors.h"

#include <fstream>

namespace {

using namespace chip;
using namespace chip::Crypto;
using namespace chip::Credentials;

using namespace fuzztest;

void ChipCertFuzzer(const std::vector<std::uint8_t> & bytes)
{
    ByteSpan span(bytes.data(), bytes.size());

    {
        NodeId nodeId;
        FabricId fabricId;
        (void) ExtractFabricIdFromCert(span, &fabricId);
        (void) ExtractNodeIdFabricIdFromOpCert(span, &nodeId, &fabricId);
    }

    {
        CATValues cats;
        (void) ExtractCATsFromOpCert(span, cats);
    }

    {
        Credentials::P256PublicKeySpan key;
        (void) ExtractPublicKeyFromChipCert(span, key);
    }

    {
        chip::System::Clock::Seconds32 rcacNotBefore;
        (void) ExtractNotBeforeFromChipCert(span, rcacNotBefore);
    }

    {
        Credentials::CertificateKeyId skid;
        (void) ExtractSKIDFromChipCert(span, skid);
    }

    {
        ChipDN subjectDN;
        (void) ExtractSubjectDNFromChipCert(span, subjectDN);
    }

    {
        uint8_t outCertBuf[kMaxDERCertLength];
        MutableByteSpan outCert(outCertBuf);
        (void) ConvertChipCertToX509Cert(span, outCert);
    }

    {
        // TODO: #35369 Move this to a Fixture once Errors related to FuzzTest Fixtures are resolved
        ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
        ValidateChipRCAC(span);
        chip::Platform::MemoryShutdown();
    }
    {
        CMS_ExtractCDContent()
    }
}

FUZZ_TEST(FuzzChipCert, ChipCertFuzzer).WithDomains(Arbitrary<std::vector<std::uint8_t>>());

// The Property function for DecodeChipCertFuzzer, The FUZZ_TEST Macro will call this function.
void DecodeChipCertFuzzer(const std::vector<std::uint8_t> & bytes, BitFlags<CertDecodeFlags> aDecodeFlag)
{
    ByteSpan span(bytes.data(), bytes.size());

    // TODO: #34352 To Move this to a Fixture once Errors related to FuzzTest Fixtures are resolved
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);

    ChipCertificateData certData;
    (void) DecodeChipCert(span, certData, aDecodeFlag);

    chip::Platform::MemoryShutdown();
}

// This function allows us to fuzz using one of three CertDecodeFlags flags; by using FuzzTests's `ElementOf` API, we define an
// input domain by explicitly enumerating the set of values in it More Info:
// https://github.com/google/fuzztest/blob/main/doc/domains-reference.md#elementof-domains-element-of
auto AnyCertDecodeFlag()
{
    constexpr BitFlags<CertDecodeFlags> NullDecodeFlag;
    constexpr BitFlags<CertDecodeFlags> GenTBSHashFlag(CertDecodeFlags::kGenerateTBSHash);
    constexpr BitFlags<CertDecodeFlags> TrustAnchorFlag(CertDecodeFlags::kIsTrustAnchor);

    return ElementOf<CertDecodeFlags>({ NullDecodeFlag, GenTBSHashFlag, TrustAnchorFlag });
}

FUZZ_TEST(FuzzChipCert, DecodeChipCertFuzzer).WithDomains(Arbitrary<std::vector<std::uint8_t>>(), AnyCertDecodeFlag());

// Example Credentials impl uses development certs.
static const ByteSpan kExpectedDacPublicKey = DevelopmentCerts::kDacPublicKey;
static const ByteSpan kExpectedPaiPublicKey = DevelopmentCerts::kPaiPublicKey;

// The Aim for this fuzz test is to fuzz the message to be signed, and make sure no errors occur
void DAC(const std::vector<std::uint8_t> & message_to_sign)
{

    ByteSpan message_to_sign_span(message_to_sign.data(), message_to_sign.size());

    DeviceAttestationCredentialsProvider * example_dac_provider = Examples::GetExampleDACProvider();
    EXPECT_NE(example_dac_provider, nullptr);

    // Sign using the example attestation private key
    P256ECDSASignature da_signature;
    MutableByteSpan out_sig_span(da_signature.Bytes(), da_signature.Capacity());

    EXPECT_EQ(CHIP_NO_ERROR, example_dac_provider->SignWithDeviceAttestationKey(message_to_sign_span, out_sig_span));

    //  EXPECT_EQ(out_sig_span.size(), kP256_ECDSA_Signature_Length_Raw);
    da_signature.SetLength(out_sig_span.size());

    // Get DAC from the provider
    uint8_t dac_cert_buf[kMaxDERCertLength];
    MutableByteSpan dac_cert_span(dac_cert_buf);

    memset(dac_cert_span.data(), 0, dac_cert_span.size());
    EXPECT_EQ(CHIP_NO_ERROR, example_dac_provider->GetDeviceAttestationCert(dac_cert_span));

    // Extract public key from DAC, prior to signature verification
    P256PublicKey dac_public_key;
    EXPECT_EQ(CHIP_NO_ERROR, ExtractPubkeyFromX509Cert(dac_cert_span, dac_public_key));
    EXPECT_EQ(dac_public_key.Length(), kExpectedDacPublicKey.size());
    EXPECT_EQ(memcmp(dac_public_key.ConstBytes(), kExpectedDacPublicKey.data(), kExpectedDacPublicKey.size()), 0);

    // Verify round trip signature
    EXPECT_EQ(CHIP_NO_ERROR,
              dac_public_key.ECDSA_validate_msg_signature(message_to_sign.data(), message_to_sign.size(), da_signature));
}
FUZZ_TEST(FuzzChipCert, DAC)
    .WithDomains(
        // message_to_sign can not be empty
        Arbitrary<std::vector<std::uint8_t>>().WithMinSize(1));

// Attestation TEST_F(TestDeviceAttestationConstruction, TestAttestationElements_Roundtrip)
void AttestationElements_Roundtrip(const std::vector<std::uint8_t> & certificationDeclaration,
                                   const std::vector<std::uint8_t> & attestationNonce,
                                   const std::vector<std::uint8_t> & vendorReserved1,
                                   const std::vector<std::uint8_t> & vendorReserved3,
                                   const std::vector<std::uint8_t> & firmwareInfo, const std::uint32_t fuzzTimestamp)
{
    // TODO: #35369 Move this to a Fixture once Errors related to FuzzTest Fixtures are resolved
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);

    chip::Platform::ScopedMemoryBuffer<uint8_t> attestationElements;
    size_t attestationElementsLen;

    static constexpr uint16_t vendorId   = 0xbeef;
    static constexpr uint16_t profileNum = 0xdead;
    VendorReservedElement vendorReservedArray[2];
    DeviceAttestationVendorReservedConstructor vendorReservedConstructor(vendorReservedArray, 2);

    ByteSpan fuzzCertificationDeclaration(certificationDeclaration.data(), certificationDeclaration.size());
    ByteSpan fuzzAttestationNonce(attestationNonce.data(), attestationNonce.size());
    ByteSpan fuzzfirmwareInfo(firmwareInfo.data(), firmwareInfo.size());

    attestationElementsLen = certificationDeclaration.size() + attestationNonce.size() + sizeof(fuzzTimestamp) +
        vendorReserved1.size() + vendorReserved3.size() + sizeof(uint64_t) * 5 + fuzzfirmwareInfo.size();

    // attestation_elements_message shall not be more than RESP_MAX
    if (attestationElementsLen > Credentials::kMaxRspLen)
    {
        GTEST_SKIP();
    }
    attestationElements.Alloc(attestationElementsLen);
    vendorReservedConstructor.addVendorReservedElement(vendorId, profileNum, 1,
                                                       ByteSpan(vendorReserved1.data(), vendorReserved1.size()));
    vendorReservedConstructor.addVendorReservedElement(vendorId, profileNum, 3,
                                                       ByteSpan(vendorReserved3.data(), vendorReserved3.size()));
    EXPECT_TRUE(attestationElements);

    {
        MutableByteSpan attestationElementsSpan(attestationElements.Get(), attestationElementsLen);
        EXPECT_EQ(CHIP_NO_ERROR,
                  ConstructAttestationElements(fuzzCertificationDeclaration, fuzzAttestationNonce, fuzzTimestamp, fuzzfirmwareInfo,
                                               vendorReservedConstructor, attestationElementsSpan));

        attestationElementsLen = attestationElementsSpan.size();
    }

    ByteSpan certificationDeclarationDeconstructed;
    ByteSpan attestationNonceDeconstructed;
    uint32_t timestampDeconstructed;
    ByteSpan firmwareInfoDeconstructed;
    DeviceAttestationVendorReservedDeconstructor vendorReservedDeconstructor;

    EXPECT_EQ(CHIP_NO_ERROR,
              DeconstructAttestationElements(ByteSpan(attestationElements.Get(), attestationElementsLen),
                                             certificationDeclarationDeconstructed, attestationNonceDeconstructed,
                                             timestampDeconstructed, firmwareInfoDeconstructed, vendorReservedDeconstructor));

    EXPECT_TRUE(certificationDeclarationDeconstructed.data_equal(fuzzCertificationDeclaration));
    EXPECT_TRUE(attestationNonceDeconstructed.data_equal(fuzzAttestationNonce));
    EXPECT_TRUE(firmwareInfoDeconstructed.data_equal(fuzzfirmwareInfo));
    EXPECT_EQ(timestampDeconstructed, fuzzTimestamp);
    EXPECT_EQ(vendorReservedConstructor.GetNumberOfElements(), vendorReservedDeconstructor.GetNumberOfElements());

    // Checking Vendor Reserved elements
    const VendorReservedElement * constructionElement = vendorReservedConstructor.cbegin();
    VendorReservedElement deconstructionElement;
    while ((constructionElement = vendorReservedConstructor.Next()) != nullptr &&
           vendorReservedDeconstructor.GetNextVendorReservedElement(deconstructionElement) == CHIP_NO_ERROR)
    {
        EXPECT_EQ(constructionElement->vendorId, deconstructionElement.vendorId);
        EXPECT_EQ(constructionElement->profileNum, deconstructionElement.profileNum);
        EXPECT_TRUE(constructionElement->vendorReservedData.data_equal(deconstructionElement.vendorReservedData));
    }
}

// CertificationDeclaration and Certification Nonce have to be BOTH emtpy or BOTH FULL
FUZZ_TEST(FuzzChipCert, AttestationElements_Roundtrip)
    .WithDomains(
        // certificationDeclaration
        Arbitrary<std::vector<std::uint8_t>>().WithMinSize(1),
        // attestationNonce
        Arbitrary<std::vector<std::uint8_t>>().WithSize(32),
        // vendorReserved1
        Arbitrary<std::vector<std::uint8_t>>(),
        // vendorReserved3
        Arbitrary<std::vector<std::uint8_t>>(),
        // firmwareInfo
        Arbitrary<std::vector<std::uint8_t>>(),
        // timestamp
        Arbitrary<std::uint32_t>());

static void OnAttestationInformationVerificationCallback(void * context, const DeviceAttestationVerifier::AttestationInfo & info,
                                                         AttestationVerificationResult result)
{
    AttestationVerificationResult * pResult = reinterpret_cast<AttestationVerificationResult *>(context);
    *pResult                                = result;
}

// TODO: THE PROBLEM WITH THIS TEST IS THAT FOR AttestationInfo, we need a DAC and PAI Der, which are generated and we use specific
// generated ones
void AttestationVerify(const std::vector<std::uint8_t> & certificationDeclaration,
                       const std::vector<std::uint8_t> & attestationNonce, const std::vector<std::uint8_t> & vendorReserved1,
                       const std::vector<std::uint8_t> & vendorReserved3, const std::vector<std::uint8_t> & firmwareInfo,
                       const std::uint32_t fuzzTimestamp)
{
    uint8_t attestationElementsTestVector[] = {
        0x15, 0x30, 0x01, 0xeb, 0x30, 0x81, 0xe8, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02, 0xa0, 0x81,
        0xda, 0x30, 0x81, 0xd7, 0x02, 0x01, 0x03, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
        0x02, 0x01, 0x30, 0x45, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x38, 0x04, 0x36, 0x15,
        0x24, 0x00, 0x01, 0x25, 0x01, 0xf1, 0xff, 0x36, 0x02, 0x05, 0x00, 0x80, 0x18, 0x25, 0x03, 0x34, 0x12, 0x2c, 0x04, 0x13,
        0x5a, 0x49, 0x47, 0x32, 0x30, 0x31, 0x34, 0x31, 0x5a, 0x42, 0x33, 0x33, 0x30, 0x30, 0x30, 0x31, 0x2d, 0x32, 0x34, 0x24,
        0x05, 0x00, 0x24, 0x06, 0x00, 0x25, 0x07, 0x94, 0x26, 0x24, 0x08, 0x00, 0x18, 0x31, 0x7c, 0x30, 0x7a, 0x02, 0x01, 0x03,
        0x80, 0x14, 0x62, 0xfa, 0x82, 0x33, 0x59, 0xac, 0xfa, 0xa9, 0x96, 0x3e, 0x1c, 0xfa, 0x14, 0x0a, 0xdd, 0xf5, 0x04, 0xf3,
        0x71, 0x60, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x30, 0x0a, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x04, 0x46, 0x30, 0x44, 0x02, 0x20, 0x43, 0xa6, 0x3f, 0x2b, 0x94, 0x3d, 0xf3,
        0x3c, 0x38, 0xb3, 0xe0, 0x2f, 0xca, 0xa7, 0x5f, 0xe3, 0x53, 0x2a, 0xeb, 0xbf, 0x5e, 0x63, 0xf5, 0xbb, 0xdb, 0xc0, 0xb1,
        0xf0, 0x1d, 0x3c, 0x4f, 0x60, 0x02, 0x20, 0x4c, 0x1a, 0xbf, 0x5f, 0x18, 0x07, 0xb8, 0x18, 0x94, 0xb1, 0x57, 0x6c, 0x47,
        0xe4, 0x72, 0x4e, 0x4d, 0x96, 0x6c, 0x61, 0x2e, 0xd3, 0xfa, 0x25, 0xc1, 0x18, 0xc3, 0xf2, 0xb3, 0xf9, 0x03, 0x69, 0x30,
        0x02, 0x20, 0xe0, 0x42, 0x1b, 0x91, 0xc6, 0xfd, 0xcd, 0xb4, 0x0e, 0x2a, 0x4d, 0x2c, 0xf3, 0x1d, 0xb2, 0xb4, 0xe1, 0x8b,
        0x41, 0x1b, 0x1d, 0x3a, 0xd4, 0xd1, 0x2a, 0x9d, 0x90, 0xaa, 0x8e, 0x52, 0xfa, 0xe2, 0x26, 0x03, 0xfd, 0xc6, 0x5b, 0x28,
        0xd0, 0xf1, 0xff, 0x3e, 0x00, 0x01, 0x00, 0x17, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x5f, 0x76, 0x65, 0x6e, 0x64, 0x6f,
        0x72, 0x5f, 0x72, 0x65, 0x73, 0x65, 0x72, 0x76, 0x65, 0x64, 0x31, 0xd0, 0xf1, 0xff, 0x3e, 0x00, 0x03, 0x00, 0x18, 0x76,
        0x65, 0x6e, 0x64, 0x6f, 0x72, 0x5f, 0x72, 0x65, 0x73, 0x65, 0x72, 0x76, 0x65, 0x64, 0x33, 0x5f, 0x65, 0x78, 0x61, 0x6d,
        0x70, 0x6c, 0x65, 0x18
    };
    uint8_t attestationChallengeTestVector[] = { 0x7b, 0x49, 0x53, 0x05, 0xd0, 0x77, 0x79, 0xa4,
                                                 0x94, 0xdd, 0x39, 0xa0, 0x85, 0x1b, 0x66, 0x0d };
    uint8_t attestationSignatureTestVector[] = { 0x79, 0x82, 0x53, 0x5d, 0x24, 0xcf, 0xe1, 0x4a, 0x71, 0xab, 0x04, 0x24, 0xcf,
                                                 0x0b, 0xac, 0xf1, 0xe3, 0x45, 0x48, 0x7e, 0xd5, 0x0f, 0x1a, 0xc0, 0xbc, 0x25,
                                                 0x9e, 0xcc, 0xfb, 0x39, 0x08, 0x1e, 0x61, 0xa9, 0x26, 0x7e, 0x74, 0xf8, 0x55,
                                                 0xda, 0x53, 0x63, 0x83, 0x74, 0xa0, 0x16, 0x71, 0xcf, 0x3d, 0x7d, 0xb8, 0xcc,
                                                 0x17, 0x0b, 0x38, 0x03, 0x45, 0xe6, 0x0b, 0xc8, 0x6f, 0xdf, 0x45, 0x9e };
    uint8_t attestationNonceTestVector[]     = { 0xe0, 0x42, 0x1b, 0x91, 0xc6, 0xfd, 0xcd, 0xb4, 0x0e, 0x2a, 0x4d,
                                                 0x2c, 0xf3, 0x1d, 0xb2, 0xb4, 0xe1, 0x8b, 0x41, 0x1b, 0x1d, 0x3a,
                                                 0xd4, 0xd1, 0x2a, 0x9d, 0x90, 0xaa, 0x8e, 0x52, 0xfa, 0xe2 };

    // TODO: #35369 Move this to a Fixture once Errors related to FuzzTest Fixtures are resolved
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);

    // Make sure default verifier exists and is not implemented on at least one method
    DeviceAttestationVerifier * default_verifier = GetDeviceAttestationVerifier();
    ASSERT_NE(default_verifier, nullptr);

    AttestationVerificationResult attestationResult = AttestationVerificationResult::kSuccess;
    ByteSpan emptyByteSpan;
    attestationResult = default_verifier->ValidateCertificationDeclarationSignature(ByteSpan(), emptyByteSpan);

    // After one Iteration, kNotImplemented will never be as a result, because SetDeviceAttestationVerifier changes a global
    // variable, that holds the DAC Verifier, and this variable is not reset in between iterations
    // EXPECT_EQ(attestationResult, AttestationVerificationResult::kNotImplemented);

    DeviceAttestationVerifier * example_dac_verifier = GetDefaultDACVerifier(GetTestAttestationTrustStore());
    ASSERT_NE(example_dac_verifier, nullptr);

    // Same Comment as above, example_dac_verifier default_verifier will hold example_dac_verifier, which was set in a previos
    // iteration
    //    EXPECT_NE(default_verifier, example_dac_verifier);

    SetDeviceAttestationVerifier(example_dac_verifier);
    default_verifier = GetDeviceAttestationVerifier();
    EXPECT_EQ(default_verifier, example_dac_verifier);

    attestationResult = AttestationVerificationResult::kNotImplemented;
    Callback::Callback<DeviceAttestationVerifier::OnAttestationInformationVerification> attestationInformationVerificationCallback(
        OnAttestationInformationVerificationCallback, &attestationResult);

    Credentials::DeviceAttestationVerifier::AttestationInfo info(
        ByteSpan(attestationElementsTestVector), ByteSpan(attestationChallengeTestVector), ByteSpan(attestationSignatureTestVector),
        TestCerts::sTestCert_PAI_FFF1_8000_Cert, TestCerts::sTestCert_DAC_FFF1_8000_0004_Cert, ByteSpan(attestationNonceTestVector),
        static_cast<VendorId>(0xFFF1), 0x8000);
    default_verifier->VerifyAttestationInformation(info, &attestationInformationVerificationCallback);

    EXPECT_EQ(attestationResult, AttestationVerificationResult::kSuccess);

    chip::Platform::MemoryShutdown();
}
FUZZ_TEST(FuzzChipCert, AttestationVerify)
    .WithDomains(
        // certificationDeclaration
        Arbitrary<std::vector<std::uint8_t>>().WithMinSize(1),
        // attestationNonce
        Arbitrary<std::vector<std::uint8_t>>().WithSize(32),
        // vendorReserved1
        Arbitrary<std::vector<std::uint8_t>>(),
        // vendorReserved3
        Arbitrary<std::vector<std::uint8_t>>(),
        // firmwareInfo
        Arbitrary<std::vector<std::uint8_t>>(),
        // timestamp
        Arbitrary<std::uint32_t>());

} // namespace
