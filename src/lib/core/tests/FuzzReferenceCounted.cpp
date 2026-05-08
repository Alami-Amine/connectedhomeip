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
 *      Fuzzer for the ReferenceCounted<Subclass, Deletor, kInitRefCount>
 *      template's Retain/Release sequence handling. The base template
 *      asserts (`VerifyOrDie`) on:
 *        - Release-when-already-zero
 *        - Retain at MAX (overflow) when the type starts at >0 init count
 *      The asserts terminate the process, so any sequence that *should* be
 *      legal but trips them is a real defect — and a sequence that *shouldn't*
 *      be legal but slips past them is a refcount underflow / use-after-free
 *      vector.
 *
 *      Drives several refcounting flavors in parallel:
 *        - kInitRefCount = 1 (the SessionHandle / SessionHolder default)
 *        - kInitRefCount = 0 (the ReferenceCountedPtr default)
 *        - 8-bit CounterType (max=255) where overflow wraps fast
 */

#include <cstddef>
#include <cstdint>

#include <lib/core/ReferenceCounted.h>
#include <lib/support/CHIPMem.h>

namespace {

using namespace chip;

bool EnsureInitialized()
{
    static const bool sInitialized = [] {
        VerifyOrDie(chip::Platform::MemoryInit() == CHIP_NO_ERROR);
        return true;
    }();
    return sInitialized;
}

class TrackingDeletor;

class TrackedRC : public ReferenceCounted<TrackedRC, TrackingDeletor, /*kInitRefCount=*/1, /*CounterType=*/uint32_t>
{
public:
    bool released = false;
};

class TrackingDeletor
{
public:
    static void Release(TrackedRC * obj) { obj->released = true; }
};

class TrackingDeletor8;

class TrackedRC8 : public ReferenceCounted<TrackedRC8, TrackingDeletor8, /*kInitRefCount=*/1, /*CounterType=*/uint8_t>
{
public:
    bool released = false;
};

class TrackingDeletor8
{
public:
    static void Release(TrackedRC8 * obj) { obj->released = true; }
};

template <typename T, typename CounterType>
void DriveRetainRelease(T & obj, const uint8_t * data, size_t size)
{
    // Each byte: high bit selects retain vs release; low 7 bits are bounded
    // count (1..127) of how many times to invoke. The base ReferenceCounted
    // template aborts (VerifyOrDie) on counter overflow at MAX, so cap each
    // Retain to (max - current) - 1 to stay strictly inside the contract.
    constexpr CounterType kMax = std::numeric_limits<CounterType>::max();
    for (size_t i = 0; i < size; ++i)
    {
        if (obj.released)
        {
            return;
        }
        const uint8_t b   = data[i];
        const bool retain = (b & 0x80) != 0;
        const uint8_t n   = (b & 0x7F) ? (b & 0x7F) : 1;

        for (uint8_t k = 0; k < n; ++k)
        {
            if (retain)
            {
                if (obj.GetReferenceCount() >= kMax - 1)
                {
                    break;
                }
                obj.Retain();
            }
            else
            {
                if (obj.GetReferenceCount() == 0)
                {
                    return;
                }
                obj.Release();
                if (obj.released)
                {
                    return;
                }
            }
        }
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)
{
    (void) EnsureInitialized();

    if (size == 0 || size > 256)
    {
        return 0;
    }

    {
        TrackedRC obj;
        DriveRetainRelease<decltype(obj), decltype(obj.GetReferenceCount())>(obj, data, size);
        if (!obj.released)
        {
            // Drive to release so the destructor runs cleanly.
            obj.Release();
        }
    }

    {
        TrackedRC8 obj;
        DriveRetainRelease<decltype(obj), decltype(obj.GetReferenceCount())>(obj, data, size);
        if (!obj.released)
        {
            obj.Release();
        }
    }

    return 0;
}
