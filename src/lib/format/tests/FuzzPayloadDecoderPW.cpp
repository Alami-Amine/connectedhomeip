/*
 *
 *    Copyright (c) 2020-2021 Project CHIP Authors
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
#include <cstddef>
#include <cstdint>
#include <lib/format/protocol_decoder.h>
#include <lib/support/StringBuilder.h>

#include <tlv/meta/clusters_meta.h>
#include <tlv/meta/protocols_meta.h>

namespace {

using namespace chip::Decoders;
using namespace chip::FlatTree;
using namespace chip::TLV;
using namespace chip::TLVMeta;

void RunDecodePW( const uint8_t * data, size_t len)
{

    chip::ByteSpan payload(data, len);

    PayloadDecoderInitParams params;
    params.SetProtocolDecodeTree(chip::TLVMeta::protocols_meta).SetClusterDecodeTree(chip::TLVMeta::clusters_meta);


    // Try some SC variants
    params.SetProtocol(chip::Protocols::SecureChannel::Id);
    params.SetMessageType(0);

    chip::Decoders::PayloadDecoder<64, 128> decoder(params);

    decoder.StartDecoding(payload);

    PayloadEntry entry;
    while (decoder.Next(entry))
    {
        // Nothing to do ...
    }
}

} // namespace


FUZZ_TEST(PayloadDecoder, RunDecodePW).WithDomains(fuzztest::Arbitrary<uint8_t>(), fuzztest::Arbitrary<size_t>());
