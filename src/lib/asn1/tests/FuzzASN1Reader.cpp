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
 *      Fuzzes ASN1Reader: the DER parser used by the X.509 attestation cert
 *      pipeline. ChipCert is fuzzed at a higher level; this harness exercises
 *      the underlying parser directly with adversarial DER input including
 *      indefinite-length, deep constructed nesting, and weird tags.
 */

#include <cstddef>
#include <cstdint>

#include <lib/asn1/ASN1.h>
#include <lib/asn1/ASN1Macros.h>
#include <lib/core/CHIPError.h>

namespace {

using namespace chip;
using namespace chip::ASN1;

// Walk every element, recursing into constructed types and following
// encapsulated bit/octet strings. Also exercises every Get* call path.
void Walk(ASN1Reader & reader, int depth)
{
    if (depth > 8) // bounded so a malicious input cannot OOM us; actual recursion
                   // limit in ASN1Reader is enforced by kMaxConstructedAndEncapsulatedTypesDepth
    {
        return;
    }

    while (reader.Next() == CHIP_NO_ERROR)
    {
        // Touch all field-getters regardless of type.
        (void) reader.GetClass();
        (void) reader.GetTag();
        (void) reader.GetValue();
        (void) reader.GetValueLen();
        (void) reader.IsConstructed();
        (void) reader.IsIndefiniteLen();
        (void) reader.IsEndOfContents();
        (void) reader.IsContained();

        int64_t intVal;
        (void) reader.GetInteger(intVal);

        bool boolVal;
        (void) reader.GetBoolean(boolVal);

        OID oid;
        (void) reader.GetObjectId(oid);

        uint32_t bitStr;
        (void) reader.GetBitString(bitStr);

        ASN1UniversalTime t;
        (void) reader.GetUTCTime(t);
        (void) reader.GetGeneralizedTime(t);

        if (reader.IsConstructed())
        {
            if (reader.EnterConstructedType() == CHIP_NO_ERROR)
            {
                Walk(reader, depth + 1);
                (void) reader.ExitConstructedType();
            }
        }
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t len)
{
    ASN1Reader reader;
    reader.Init(data, len);
    Walk(reader, 0);
    return 0;
}
