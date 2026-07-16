#include <cstddef>
#include <cstdint>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

#include "credentials/CHIPCert.h"
#include <crypto/CHIPCryptoPAL.h>

#include <credentials/attestation_verifier/TestPAAStore.h>
#include <credentials/tests/CHIPAttCert_test_vectors.h>
#include <credentials/tests/CHIPCert_test_vectors.h>

namespace {

using namespace chip;
using namespace chip::Credentials;
using namespace chip::Crypto;
using namespace fuzztest;
using namespace TestCerts;

//
//
//
//

const std::string relativeAttestationCertsDir = "credentials/test/attestation/";

// TODO reconsider a better approach than using an ENV Varaible to find ROOT PATH
std::filesystem::path GetAttestationCertsDir()
{
    const char * chipRoot = std::getenv("PW_PROJECT_ROOT");
    assert(chipRoot && "PW_PROJECT_ROOT not set. Did you forget to source activate.sh?");

    return std::filesystem::path(chipRoot) / relativeAttestationCertsDir;
}
const std::string attestationCertsDir = GetAttestationCertsDir();

// Example location: credentials/test/attestation/Chip-Test-DAC-FFF1-8000-0002-Cert.der
auto isPaiCert = [](std::string_view name) { return absl::StrContains(name, "PAI") && absl::EndsWith(name, ".der"); };
auto isPaaCert = [](std::string_view name) { return absl::StrContains(name, "PAA") && absl::EndsWith(name, ".der"); };
auto isDacCert = [](std::string_view name) { return absl::StrContains(name, "DAC") && absl::EndsWith(name, ".der"); };

// Lambda that reads certificates from a directory and returns them as a vector of strings, to be used as seeds
auto seedProvider = [](auto filterFunction) -> std::vector<std::string> {
    // fuzztest::ReadFilesFromDirectory returns a vector of tuples, each tuple contains a file
    // We need to unpack the tuples and then extract file content into a vector of strings.
    std::vector<std::tuple<std::string>> tupleVector = ReadFilesFromDirectory(attestationCertsDir, filterFunction);
    std::vector<std::string> seeds;

    if (tupleVector.size() == 0)
    {
        std::cout << "No Matching Seed files found in the chosen directory" << std::endl;
    }
    // DEBUG TIP: print tupleVector.size() here to check that we have the correct number of files as seeds.
    for (auto & [fileContents] : tupleVector)
    {
        seeds.push_back(fileContents);
    }
    return seeds;
};
//
//
//
//
// void X509_VerifyAttestationCertificateFormat(const std::vector<uint8_t> & fuzzDerCerts, AttestationCertType type)
void X509_VerifyAttestationCertificateFormat(const std::string fuzzDerCerts, AttestationCertType type)
{
    ByteSpan cert(reinterpret_cast<const uint8_t *>(fuzzDerCerts.data()), fuzzDerCerts.size());

    // ByteSpan cert = ByteSpan(fuzzDerCerts.data(), fuzzDerCerts.size());

    VerifyAttestationCertificateFormat(cert, type);
}

auto DAC()
{
    // std::vector<uint8_t> data(sTestCert_DAC_FFF2_8004_0021_ValInFuture_Cert.begin(),
    // sTestCert_DAC_FFF2_8004_0021_ValInFuture_Cert.end());

    //     std::vector<uint8_t> data(sTestCert_DAC_FFF2_8002_0017_Cert.begin(),
    //                               sTestCert_DAC_FFF2_8002_0017_Cert.end());

    // std::vector<uint8_t> data(sTestCert_DAC_FFF2_8004_001C_FB_Cert.begin(), sTestCert_DAC_FFF2_8004_001C_FB_Cert.end());

    std::vector<uint8_t> data(sTestCert_DAC_FFF2_8006_0034_ValInFuture_Cert.begin(),
                              sTestCert_DAC_FFF2_8006_0034_ValInFuture_Cert.end());

    return Arbitrary<std::vector<uint8_t>>().WithSeeds({ data });
}

std::vector<uint8_t> ToVector(const ByteSpan & span)
{
    return std::vector<uint8_t>(span.begin(), span.end());
}

auto PAI()
{
    std::vector<uint8_t> data(sTestCert_PAI_FFF1_8000_Cert.begin(), sTestCert_PAI_FFF1_8000_Cert.end());

    // std::vector<uint8_t> data(sTestCert_PAI_FFF2_8004_FB_Cert.begin(), sTestCert_PAI_FFF2_8004_FB_Cert.end());

    // std::vector<uint8_t> data(sTestCert_PAI_FFF2_8006_ValInPast_Cert.begin(), sTestCert_PAI_FFF2_8006_ValInPast_Cert.end());

    return Arbitrary<std::vector<uint8_t>>().WithSeeds({ data });
}

auto PAA()
{
    // std::vector<uint8_t> data(sTestCert_PAA_FFF1_Cert.begin(), sTestCert_PAA_FFF1_Cert.end());

    // std::vector<uint8_t> data(sTestCert_PAA_NoVID_Cert.begin(), sTestCert_PAA_NoVID_Cert.end());

    std::vector<uint8_t> data(sTestCert_PAA_FFF2_ValInPast_Cert.begin(), sTestCert_PAA_FFF2_ValInPast_Cert.end());

    return Arbitrary<std::vector<uint8_t>>().WithSeeds({ data });
}

auto AnyAttestationCertType()
{
    return ElementOf({ AttestationCertType::kPAA, AttestationCertType::kPAI, AttestationCertType::kDAC });
}
FUZZ_TEST(FuzzChipCryptoPal, X509_VerifyAttestationCertificateFormat)
    .WithDomains(
        // Filtering for DAC Certs in folder
        Arbitrary<std::string>().WithSeeds(seedProvider(isDacCert)),
        // Allowing any Attestation Cert Type
        AnyAttestationCertType());

/*************************************************************************************************************************** */
/**/
/**/
/**/
/*************************************************************************************************************************** */
//  TODO: seems no failures happening in OpenSSL or mbedTLS

void X509_ValidateCertificateChain(const std::vector<uint8_t> & DAC, const std::vector<uint8_t> & PAI,
                                   const std::vector<uint8_t> & PAA, AttestationCertType type)
{
    // ByteSpan span(reinterpret_cast<const uint8_t *>(fuzzDerCerts.data()), fuzzDerCerts.size());

    CertificateChainValidationResult chainValidationResult;

    //  ByteSpan cert = ByteSpan(fuzzDerCerts.data(), fuzzDerCerts.size());

    //  std::cout << "Size of Cert " << fuzzDerCerts.size();
    ValidateCertificateChain(PAA.data(), PAA.size(), PAI.data(), PAI.size(), DAC.data(), DAC.size(), chainValidationResult);
    //  std::cout << err << endl;
}
// FUZZ_TEST(FuzzChipCryptoPal, X509_ValidateCertificateChain)
//     .WithDomains(DAC(), PAI(), Arbitrary<std::vector<uint8_t>>().WithSeeds({ ToVector(sTestCert_PAA_NoVID_Cert) }),
//                  AnyAttestationCertType());

FUZZ_TEST(FuzzChipCryptoPal, X509_ValidateCertificateChain).WithDomains(DAC(), PAI(), PAA(), AnyAttestationCertType());

/*************************************************************************************************************************** */
/**/
/**/
/**/
/*************************************************************************************************************************** */
// TODO: tested using openssl, not tested using mbedtls
// TODO: should we fuzz IsCertificateValidAtCurrentTime ?
void X509_IssuingTimestampValidation(const std::vector<uint8_t> & candidateCertificate,
                                     const std::vector<uint8_t> & issuerCertificate)
{
    // ByteSpan span(reinterpret_cast<const uint8_t *>(fuzzDerCerts.data()), fuzzDerCerts.size());

    CertificateChainValidationResult chainValidationResult;

    //  ByteSpan cert = ByteSpan(fuzzDerCerts.data(), fuzzDerCerts.size());

    //  std::cout << "Size of Cert " << fuzzDerCerts.size();
    IsCertificateValidAtIssuance(ByteSpan(candidateCertificate.data(), candidateCertificate.size()),
                                 ByteSpan(issuerCertificate.data(), issuerCertificate.size()));
    //  std::cout << err << endl;
}
FUZZ_TEST(FuzzChipCryptoPal, X509_IssuingTimestampValidation).WithDomains(DAC(), PAI());

/*************************************************************************************************************************** */
/**/
/**/
/**/
/*************************************************************************************************************************** */

void KID_x509Extraction(bool isSKID, const std::vector<uint8_t> & cert)
{
    // ByteSpan span(reinterpret_cast<const uint8_t *>(fuzzDerCerts.data()), fuzzDerCerts.size());

    //  ByteSpan cert = ByteSpan(fuzzDerCerts.data(), fuzzDerCerts.size());

    //  std::cout << "Size of Cert " << fuzzDerCerts.size();
    uint8_t skidBuf[kSubjectKeyIdentifierLength];
    MutableByteSpan unused(skidBuf);

    ExtractSKIDFromX509Cert(ByteSpan(cert.data(), cert.size()), unused);

    ExtractAKIDFromX509Cert(ByteSpan(cert.data(), cert.size()), unused);

    //  std::cout << err << endl;
}
FUZZ_TEST(FuzzChipCryptoPal, KID_x509Extraction).WithDomains(Arbitrary<bool>(), DAC());

/*************************************************************************************************************************** */
/**/
/**/
/**/
/*************************************************************************************************************************** */

auto CdpCerts()
{
    // std::vector<uint8_t> data(sTestCert_DAC_FFF2_8004_0021_ValInFuture_Cert.begin(),
    // sTestCert_DAC_FFF2_8004_0021_ValInFuture_Cert.end());

    // std::vector<uint8_t> data(sTestCert_DAC_FFF2_8004_001C_FB_Cert.begin(), sTestCert_DAC_FFF2_8004_001C_FB_Cert.end());

    // std::vector<uint8_t> data(sTestCert_DAC_FFF1_8000_0000_CDP_2CRLIssuers_PAA_FFF1_Cert.begin(),
    //                           sTestCert_DAC_FFF1_8000_0000_CDP_2CRLIssuers_PAA_FFF1_Cert.end());

    std::vector<uint8_t> data(sTestCert_DAC_FFF1_8000_0000_CDP_Issuer_PAA_FFF1_Cert.begin(),
                              sTestCert_DAC_FFF1_8000_0000_CDP_Issuer_PAA_FFF1_Cert.end());

    return Arbitrary<std::vector<uint8_t>>().WithSeeds({ data });
}

void CDPExtension_x509Extraction(const std::vector<uint8_t> & cert)
{
    char cdpBuf[kMaxCRLDistributionPointURLLength] = { '\0' };
    MutableCharSpan unused(cdpBuf);

    ExtractCRLDistributionPointURIFromX509Cert(ByteSpan(cert.data(), cert.size()), unused);

    //  std::cout << err << endl;
}
FUZZ_TEST(FuzzChipCryptoPal, CDPExtension_x509Extraction).WithDomains(CdpCerts());

/*************************************************************************************************************************** */
/**/
/**/
/**/
/*************************************************************************************************************************** */

void ExtractCDPExtensionCRLIssuer(const std::vector<uint8_t> & cert)
{
    uint8_t crlIssuerBuf[kMaxCertificateDistinguishedNameLength] = { 0 };
    MutableByteSpan unused(crlIssuerBuf);

    ExtractCDPExtensionCRLIssuerFromX509Cert(ByteSpan(cert.data(), cert.size()), unused);

    //  std::cout << err << endl;
}
FUZZ_TEST(FuzzChipCryptoPal, ExtractCDPExtensionCRLIssuer).WithDomains(CdpCerts());

/*************************************************************************************************************************** */
/**/
/**/
/**/
/*************************************************************************************************************************** */

void VIDPID_x509Extraction(const std::vector<uint8_t> & cert)
{
    {

        AttestationCertVidPid unused;

        ExtractVIDPIDFromX509Cert(ByteSpan(cert.data(), cert.size()), unused);
    }
    //  std::cout << err << endl;
}
FUZZ_TEST(FuzzChipCryptoPal, VIDPID_x509Extraction).WithDomains(DAC());

/*************************************************************************************************************************** */
/**/
/**/
/**/
/*************************************************************************************************************************** */

void VIDPID_StringExtraction(DNAttrType attrType, std::string attrString)
{

    AttestationCertVidPid unused_vidpid;
    AttestationCertVidPid unused_vidpidFromCN;

    ByteSpan attrStringSpan(reinterpret_cast<const uint8_t *>(attrString.data()), attrString.size());

    ExtractVIDPIDFromAttributeString(attrType, attrStringSpan, unused_vidpid, unused_vidpidFromCN);

    //  std::cout << err << endl;
}
auto AnyDNAttrType()
{
    return ElementOf({ DNAttrType::kMatterVID, DNAttrType::kMatterPID, DNAttrType::kUnspecified, DNAttrType::kCommonName });
}
FUZZ_TEST(FuzzChipCryptoPal, VIDPID_StringExtraction).WithDomains(AnyDNAttrType(), Arbitrary<std::string>());

/*************************************************************************************************************************** */
/**/
/**/
/**/
/*************************************************************************************************************************** */

void ExtractSubjectOrIssuerFromX509Cert(const std::vector<uint8_t> & cert)
{

    ByteSpan certSpan(cert.data(), cert.size());

    uint8_t Buf[kMaxCertificateDistinguishedNameLength] = { 0 };
    MutableByteSpan unusedBuf(Buf);

    ExtractIssuerFromX509Cert(certSpan, unusedBuf);
    ExtractSubjectFromX509Cert(certSpan, unusedBuf);
}

FUZZ_TEST(FuzzChipCryptoPal, ExtractSubjectOrIssuerFromX509Cert).WithDomains(DAC());

/*************************************************************************************************************************** */
/**/
/**/
/**/
/*************************************************************************************************************************** */

ByteSpan TestCandidateCertsList1[] = { sTestCert_DAC_FFF1_8000_0004_Cert, sTestCert_PAI_FFF2_8004_FB_Cert,
                                       sTestCert_PAA_FFF1_Cert };

// TODO: this is not used in matter, should I fuzz it?
void X509_ReplaceCertIfResignedCertFound(const std::vector<uint8_t> & cert, size_t candidateCertificatesCount)
{
    {

        ByteSpan unused;
        ReplaceCertIfResignedCertFound(ByteSpan(cert.data(), cert.size()), &TestCandidateCertsList1[0], 3, unused);
    }
    //  std::cout << err << endl;
}
FUZZ_TEST(FuzzChipCryptoPal, X509_ReplaceCertIfResignedCertFound).WithDomains(DAC(), Arbitrary<uint8_t>());

/*************************************************************************************************************************** */
/**/
/**/
/**/
/**/
/**/
/**/
/**/
/**/
/**/
/*************************************************************************************************************************** */

// TODO: is this really for X509??

const uint8_t kGoodCsrSubjectPublicKey[] = {
    0x04, 0xa3, 0xbe, 0xa1, 0xf5, 0x42, 0x01, 0x07, 0x3c, 0x4b, 0x75, 0x85, 0xd8, 0xe2, 0x98, 0xac, 0x2f,
    0xf6, 0x98, 0xdb, 0xd9, 0x5b, 0xe0, 0x7e, 0xc1, 0x04, 0xd5, 0x73, 0xc5, 0xb0, 0x90, 0x77, 0x27, 0x00,
    0x1e, 0x22, 0xc7, 0x89, 0x5e, 0x4d, 0x75, 0x07, 0x89, 0x82, 0x0f, 0x49, 0xb6, 0x59, 0xd5, 0xc5, 0x15,
    0x7d, 0x93, 0xe6, 0x80, 0x5c, 0x70, 0x89, 0x0a, 0x43, 0x10, 0x3d, 0xeb, 0x3d, 0x4a,
};

const uint8_t kGoodCsr[] = {
    0x30, 0x81, 0xca, 0x30, 0x70, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x03,
    0x43, 0x53, 0x52, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xa3, 0xbe, 0xa1, 0xf5, 0x42, 0x01, 0x07, 0x3c, 0x4b, 0x75, 0x85, 0xd8,
    0xe2, 0x98, 0xac, 0x2f, 0xf6, 0x98, 0xdb, 0xd9, 0x5b, 0xe0, 0x7e, 0xc1, 0x04, 0xd5, 0x73, 0xc5, 0xb0, 0x90, 0x77, 0x27, 0x00,
    0x1e, 0x22, 0xc7, 0x89, 0x5e, 0x4d, 0x75, 0x07, 0x89, 0x82, 0x0f, 0x49, 0xb6, 0x59, 0xd5, 0xc5, 0x15, 0x7d, 0x93, 0xe6, 0x80,
    0x5c, 0x70, 0x89, 0x0a, 0x43, 0x10, 0x3d, 0xeb, 0x3d, 0x4a, 0xa0, 0x00, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x04, 0x03, 0x02, 0x05, 0x00, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x1d, 0x86, 0x21, 0xb4, 0xc2, 0xe1, 0xa9, 0xf3, 0xbc,
    0xc8, 0x7c, 0xda, 0xb4, 0xb9, 0xc6, 0x8c, 0xd0, 0xe4, 0x9a, 0x9c, 0xef, 0x02, 0x93, 0x98, 0x27, 0x7e, 0x81, 0x21, 0x5d, 0x20,
    0x9d, 0x32, 0x02, 0x21, 0x00, 0x8b, 0x6b, 0x49, 0xb6, 0x7d, 0x3e, 0x67, 0x9e, 0xb1, 0x22, 0xd3, 0x63, 0x82, 0x40, 0x4f, 0x49,
    0xa4, 0xdc, 0x17, 0x35, 0xac, 0x4b, 0x7a, 0xbf, 0x52, 0x05, 0x58, 0x68, 0xe0, 0xaa, 0xd2, 0x8e,
};

auto CSR()
{
    std::vector<uint8_t> data(&kGoodCsr[0], &kGoodCsr[0] + sizeof(kGoodCsr));

    return Arbitrary<std::vector<uint8_t>>().WithSeeds({ data });
}
void X509_VerifyCertificateSigningRequest(const std::vector<uint8_t> & fuzzedCSR)
{
    {
        Crypto::P256PublicKey expected(kGoodCsrSubjectPublicKey);

        VerifyCertificateSigningRequest(fuzzedCSR.data(), fuzzedCSR.size(), expected);
    }
    //  std::cout << err << endl;
}
FUZZ_TEST(FuzzChipCryptoPal, X509_VerifyCertificateSigningRequest).WithDomains(CSR());

} // namespace
