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
 *      Fuzzes the TLV circular-buffer reader. Drives the wraparound logic by
 *      moving the queue head/tail to a fuzz-chosen offset and walking the
 *      content with CircularTLVReader. The wraparound math has historically
 *      been a source of off-by-one bugs.
 */

#include <cstddef>
#include <cstdint>
#include <vector>

#include <lib/core/CHIPError.h>
#include <lib/core/TLVCircularBuffer.h>
#include <lib/core/TLVReader.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t len)
{
    using namespace chip::TLV;

    if (len < 2)
    {
        return 0;
    }

    // First byte selects an offset into the backing buffer to use as the
    // initial queue-head position; this drives wraparound permutations.
    const size_t headOffset = data[0];
    const size_t bufferLen  = len - 1;

    if (bufferLen < 2 || bufferLen > 65536)
    {
        return 0;
    }

    std::vector<uint8_t> backing(data + 1, data + len);

    const size_t safeOffset = headOffset % bufferLen;
    TLVCircularBuffer cb(backing.data(), static_cast<uint32_t>(bufferLen),
                         backing.data() + safeOffset);

    CircularTLVReader reader;
    reader.Init(cb);

    int safety = 0;
    while (reader.Next() == CHIP_NO_ERROR)
    {
        if (++safety > 256)
        {
            break;
        }
    }

    return 0;
}
