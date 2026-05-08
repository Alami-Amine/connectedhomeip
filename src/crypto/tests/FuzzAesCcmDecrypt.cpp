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
 *      Fuzzes Crypto::AES_CCM_decrypt with attacker-controlled
 *      ciphertext+aad+nonce+tag. Every encrypted Matter message goes
 *      through this primitive; bounds bugs in the backend (mbedTLS or
 *      OpenSSL) here would be exploitable from any peer that has a
 *      session.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include <crypto/CHIPCryptoPAL.h>
#include <crypto/RawKeySessionKeystore.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>

namespace {
bool EnsureInitialized()
{
    static const bool sInitialized = [] {
        VerifyOrDie(chip::Platform::MemoryInit() == CHIP_NO_ERROR);
        return true;
    }();
    return sInitialized;
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t len)
{
    using namespace chip;
    using namespace chip::Crypto;

    (void) EnsureInitialized();

    // Layout: [16-byte key][13-byte nonce][1-byte tag-len-selector]
    //         [1-byte aad-len][aad...][16-byte tag][ciphertext...]
    constexpr size_t kKeyLen   = 16;
    constexpr size_t kNonceLen = 13;
    constexpr size_t kHeader   = kKeyLen + kNonceLen + 2;
    constexpr size_t kTagFixed = 16;

    if (len < kHeader + kTagFixed)
    {
        return 0;
    }

    Symmetric128BitsKeyByteArray keyMaterial;
    memcpy(keyMaterial, data, kKeyLen);

    const uint8_t * nonce         = data + kKeyLen;
    const uint8_t tagLenSelector  = data[kKeyLen + kNonceLen];
    const uint8_t aadLenSelector  = data[kKeyLen + kNonceLen + 1];

    // Tag length: AES-CCM allows {4,6,8,10,12,14,16}; pick deterministically.
    static constexpr size_t tagLengths[] = { 4, 6, 8, 10, 12, 14, 16 };
    const size_t tagLen = tagLengths[tagLenSelector % (sizeof(tagLengths) / sizeof(tagLengths[0]))];

    // AAD length: 0 to (len - kHeader - kTagFixed).
    const size_t maxAad = len - kHeader - kTagFixed;
    const size_t aadLen = (maxAad == 0) ? 0 : (aadLenSelector % (maxAad + 1));

    const uint8_t * aad         = data + kHeader;
    const uint8_t * tag         = aad + aadLen;
    const uint8_t * ciphertext  = tag + tagLen;
    const size_t ctLen          = len - kHeader - aadLen - tagLen;

    if (ctLen > 65536)
    {
        return 0;
    }

    // Wrap key bytes in a SessionKeystore-derived Aes128KeyHandle.
    Aes128KeyHandle keyHandle;
    RawKeySessionKeystore keystore;
    if (keystore.CreateKey(keyMaterial, keyHandle) != CHIP_NO_ERROR)
    {
        return 0;
    }

    std::vector<uint8_t> plaintext(ctLen);
    (void) AES_CCM_decrypt(ciphertext, ctLen, aad, aadLen, tag, tagLen, keyHandle, nonce, kNonceLen, plaintext.data());

    keystore.DestroyKey(keyHandle);
    return 0;
}
