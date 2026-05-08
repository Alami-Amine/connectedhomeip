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
 *      Seeded FuzzTest harness for Base64Encode/Base64Decode. The
 *      libFuzzer variant must discover the alphabet from random bytes;
 *      here we seed with valid base64 strings (PEM-style cert blocks,
 *      typical attestation payloads, padding-edge-case forms) so the
 *      mutator stays close to the legal alphabet and exercises the
 *      length / padding / 4-char block boundary logic.
 *
 *      Property under test: encode(input) → decode → equals input.
 */

#include <string>
#include <vector>

#include <pw_fuzzer/fuzztest.h>
#include <pw_unit_test/framework.h>

#include <lib/support/Base64.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>

namespace {

using namespace chip;
using namespace fuzztest;

void EnsureInitialized()
{
    static const bool sInitialized = [] {
        VerifyOrDie(Platform::MemoryInit() == CHIP_NO_ERROR);
        return true;
    }();
    (void) sInitialized;
}

// Real base64 strings hitting all four padding shapes (none, '=', '==')
// plus typical PEM-style content.
std::vector<std::string> Base64StringSeeds()
{
    return {
        // ==== Length / padding boundaries ====
        "",
        "A",                              // 1-char (incomplete)
        "AA",                             // 2-char (no padding) — malformed
        "AAA",                            // 3-char (no padding) — malformed
        "AAAA",                           // 4-char clean
        "AAAAAAAA",                       // 8-char (two clean blocks)
        "AA==",                           // 1-byte + 2 padding
        "AAA=",                           // 2-byte + 1 padding
        "AAAA====",                       // doubled padding (malformed)
        // ==== Strings that decode to known content ====
        "Zg==",                           // "f"
        "Zm8=",                           // "fo"
        "Zm9v",                           // "foo"
        "Zm9vYg==",                       // "foob"
        "Zm9vYmE=",                       // "fooba"
        "Zm9vYmFy",                       // "foobar"
        "AAECAwQFBgcICQoLDA0ODw==",       // 0..15
        "/+8=",                           // contains '+' '/' '='
        "+/A=",                           // '+' first
        "//8=",                           // wraparound bytes
        // ==== Typical PEM/DER content prefixes ====
        "MIIB",                           // typical DER cert SEQUENCE prefix
        "MIIBADANBgkqhkiG9w0BAQE",        // longer DER prefix
        "BAEAAQ==",                       // typical key blob fragment
        "AAAA////",                       // alternating null/all-1
        // ==== Invalid characters / mis-formed ====
        "AAAA AAAA",                      // embedded whitespace
        "AAAA\nAAAA",                     // PEM-style newline
        "AAAA\r\nAAAA",                   // CRLF newline
        "AAAA\tAAAA",                     // embedded tab
        "AAA*",                           // '*' (invalid)
        "AAA-",                           // '-' (URL-safe variant char, not standard)
        "AAA_",                           // '_' (URL-safe variant char, not standard)
        "==AAAA",                         // padding at start
        "A=AA",                           // padding mid-block
        "AAAA=",                          // 5-char trailing padding
        "ABCD!",                          // non-alphabet char at end
        // ==== Big strings ====
        std::string(255, 'A'),            // long valid alphabet prefix
        std::string(64, 'A') + "===",     // overlong padding tail
    };
}

// Bytes seeds for the encode->decode round-trip test.
std::vector<std::vector<uint8_t>> ByteSeeds()
{
    return {
        {},
        { 0x00 },                                                       // 1 byte
        { 0xFF },
        { 0x00, 0x01 },                                                 // 2 bytes
        { 0xFF, 0xFF },
        { 0x00, 0x01, 0x02 },                                           // 3 bytes (no padding)
        { 0xFF, 0xFF, 0xFF },
        { 0xDE, 0xAD, 0xBE, 0xEF },                                     // 4 bytes (1 padding)
        { 'f', 'o' },                                                   // 2 ASCII
        { 'f', 'o', 'o' },                                              // 3 ASCII
        { 'f', 'o', 'o', 'b' },                                         // 4 ASCII
        { 'f', 'o', 'o', 'b', 'a' },                                    // 5 ASCII
        { 'f', 'o', 'o', 'b', 'a', 'r' },                               // 6 ASCII
        { 0x30, 0x82, 0x01, 0x00, 0x06, 0x09 },                         // typical DER cert prefix
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },             // all zeros (8)
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },             // all ones (8)
        // Walk-through patterns to drive distinct alphabet bytes.
        { 0x0F, 0x1F, 0x2F, 0x3F, 0x4F, 0x5F, 0x6F, 0x7F, 0x8F, 0x9F, 0xAF, 0xBF, 0xCF, 0xDF, 0xEF, 0xFF },
        { 0xFB, 0xFF, 0xBF, 0x00 },                                     // produces '+' '/'
    };
}

void Base64DecodeFuzz(const std::string & s)
{
    EnsureInitialized();

    if (s.size() > UINT16_MAX)
        return;

    std::vector<uint8_t> out(s.size() + 4);
    (void) Base64Decode(s.c_str(), static_cast<uint16_t>(s.size()), out.data());
    (void) Base64Decode32(s.c_str(), static_cast<uint32_t>(s.size()), out.data());
}

FUZZ_TEST(Base64PW, Base64DecodeFuzz)
    .WithDomains(Arbitrary<std::string>().WithSeeds(Base64StringSeeds()).WithMaxSize(8192));

// Property: encode(input) -> decode -> equals input (when input is byte-clean).
void Base64RoundtripFuzz(const std::vector<uint8_t> & input)
{
    EnsureInitialized();

    if (input.size() > 4096)
        return;

    std::vector<char> encoded(input.size() * 4 / 3 + 8);
    const uint16_t encLen = Base64Encode(input.data(), static_cast<uint16_t>(input.size()), encoded.data());

    std::vector<uint8_t> decoded(static_cast<size_t>(encLen));
    const uint16_t decLen = Base64Decode(encoded.data(), encLen, decoded.data());

    ASSERT_EQ(decLen, input.size());
    for (size_t i = 0; i < input.size(); ++i)
    {
        ASSERT_EQ(decoded[i], input[i]);
    }
}

FUZZ_TEST(Base64PW, Base64RoundtripFuzz)
    .WithDomains(Arbitrary<std::vector<uint8_t>>().WithSeeds(ByteSeeds()).WithMaxSize(4096));

} // namespace
