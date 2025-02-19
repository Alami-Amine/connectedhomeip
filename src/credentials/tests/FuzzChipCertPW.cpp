#include <cstddef>
#include <cstdint>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

#include "credentials/CHIPCert.h"

namespace {

using namespace chip;
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
        // TODO: #35369 Move this to a Fixture once Errors related to FuzzTest Fixtures are resolved
        ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
        ValidateChipRCAC(span);
        chip::Platform::MemoryShutdown();
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

/******************************************************************************************************************* */
/********************************************************************** */
std::string certsDir =
    "/home/aya/repos/connectedhomeipDELETEME/connectedhomeip/credentials/test/operational-certificates-error-cases/";

// Lambda that reads certificates in "Matter Format "from a directory and returns them as a vector of strings, to be used as seeds
// TODO, consider factoring this out into a utility function that can be called ? libavif have an example
auto seedProviderChipCerts = []() -> std::vector<std::string> {
    // fuzztest::ReadFilesFromDirectory returns a vector of tuples, each tuple contains one of the DER encoded certificates
    // We need to unpack the tuples and then extract file content into a vector of strings.
    std::vector<std::tuple<std::string>> tupleVector = ReadFilesFromDirectory(certsDir);
    std::vector<std::string> seeds;

    if (tupleVector.size() == 0)
    {
        std::cout << "No Matching Seed files found in the directory" << std::endl;
    }

    for (auto & [fileContents] : tupleVector)
    {
        seeds.push_back(fileContents);
    }
    return seeds;
};

void ConvertChipCertToX509CertFuzz(const std::string & fuzzChipCerts)
{
    ByteSpan span(reinterpret_cast<const uint8_t *>(fuzzChipCerts.data()), fuzzChipCerts.size());

    uint8_t outCertBuf[kMaxDERCertLength];
    MutableByteSpan outCert(outCertBuf);
    (void) ConvertChipCertToX509Cert(span, outCert);
}
FUZZ_TEST(FuzzChipCert, ConvertChipCertToX509CertFuzz).WithDomains(Arbitrary<std::string>().WithSeeds(seedProviderChipCerts));

/******************************************************************************** */

// Lambda that reads DER encoded certificates from a directory and returns them as a vector of strings, to be used as seeds
auto seedProviderDerCerts = []() -> std::vector<std::string> {
    // fuzztest::ReadFilesFromDirectory returns a vector of tuples, each tuple contains one of the DER encoded certificates
    // We need to unpack the tuples and then extract file content into a vector of strings.
    std::vector<std::tuple<std::string>> tupleVector = ReadFilesFromDirectory(certsDir);
    std::vector<std::string> seeds;

    if (tupleVector.size() == 0)
    {
        std::cout << "No Matching Seed files found in the directory" << std::endl;
    }

    for (auto & [fileContents] : tupleVector)
    {
        seeds.push_back(fileContents);
    }
    return seeds;
};

std::string kDictionaryPath = "/home/aya/repos/connectedhomeipDELETEME/connectedhomeip/src/credentials/tests/dict/der.dict";

void ConvertX509CertToChipCertFuzz(const std::string & fuzzDerCerts)
{
    ByteSpan span(reinterpret_cast<const uint8_t *>(fuzzDerCerts.data()), fuzzDerCerts.size());

    uint8_t outCertBuf[kMaxDERCertLength];
    MutableByteSpan outCert(outCertBuf);

    CHIP_ERROR err = CHIP_NO_ERROR;

    err = ConvertX509CertToChipCert(span, outCert);
    std::cout << err.Format() << std::endl;
}
FUZZ_TEST(FuzzChipCert, ConvertX509CertToChipCertFuzz)
    .WithDomains(Arbitrary<std::string>().WithSeeds(seedProviderDerCerts).WithDictionary(ReadDictionaryFromFile(kDictionaryPath)));

void ExtractSubjectDNFromX509CertFuzz(const std::string & fuzzDerCerts)
{
    ByteSpan span(reinterpret_cast<const uint8_t *>(fuzzDerCerts.data()), fuzzDerCerts.size());
    ChipDN subjectDN;
    CHIP_ERROR err = ExtractSubjectDNFromX509Cert(span, subjectDN);
    std::cout << err.Format() << std::endl;
}
FUZZ_TEST(FuzzChipCert, ExtractSubjectDNFromX509CertFuzz)
    .WithDomains(Arbitrary<std::string>().WithSeeds(seedProviderDerCerts).WithDictionary(ReadDictionaryFromFile(kDictionaryPath)));

//.WithDomains(Arbitrary<std::vector<std::uint8_t>>().WithSeeds(fuzztest::ReadFilesFromDirectory(kMyCorpusPath)));

// credentials/test/operational-certificates-error-cases/Chip-Test-ICAC-Cert-Version-V2-Cert.der

} // namespace
