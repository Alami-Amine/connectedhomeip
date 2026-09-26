// Copyright 2024 The Pigweed Authors
// Copyright (c) 2026 Project CHIP Authors
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

// From Pigweed's pw_fuzzer/asan_default_options.c.

#include <sanitizer/asan_interface.h>

const char * __asan_default_options(void)
{
    // FuzzTest is not coverage-instrumented, and it passes STL containers across
    // the boundary with instrumented code, which produces false positives such as
    // github.com/google/sanitizers/wiki/AddressSanitizerContainerOverflow
    return "detect_container_overflow=0";
}
