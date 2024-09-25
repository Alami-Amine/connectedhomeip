/*
 *    Copyright (c) 2021 Project CHIP Authors
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

#pragma once

#include <string.h>
#include <type_traits>

#include <lib/core/CHIPConfig.h>

namespace chip {

class LambdaBridge
{
public:
    // Use initialize instead of constructor because this class has to be trivial
    template <typename Lambda>
    void Initialize(const Lambda & lambda)
    {
        // memcpy is used to move the lambda into the event queue, so it must be trivially copyable
        static_assert(std::is_trivially_copyable<Lambda>::value, "lambda must be trivially copyable");
        static_assert(sizeof(Lambda) <= CHIP_CONFIG_LAMBDA_EVENT_SIZE, "lambda too large");
        static_assert(CHIP_CONFIG_LAMBDA_EVENT_ALIGN % alignof(Lambda) == 0, "lambda align too large");

       if constexpr (std::is_same_v<decltype(lambda()), CHIP_ERROR>)
        {
            mLambdaProxy = [](const LambdaStorage & body) { 
                return (*reinterpret_cast<const Lambda *>(&body))(); 
            };
        }
        else if constexpr (std::is_same_v<decltype(lambda()), void>)
        {
            mLambdaVoidProxy = [](const LambdaStorage & body) { 
                (*reinterpret_cast<const Lambda *>(&body))(); 
            };
        }


        ::memcpy(&mLambdaBody, &lambda, sizeof(Lambda));
    }

        // For lambdas returning CHIP_ERROR
    CHIP_ERROR CallLambdaWithErrorReturn() const
    {
        if (mLambdaProxy != nullptr)
        {
            return mLambdaProxy(mLambdaBody);
        }
        return CHIP_ERROR_INTERNAL;  // Return an error if the proxy is not for CHIP_ERROR
    }

    // For lambdas returning void
    void operator()() const
    {
        if (mLambdaVoidProxy != nullptr)
        {
            mLambdaVoidProxy(mLambdaBody);
        }
    }

private:
    using LambdaStorage = std::aligned_storage_t<CHIP_CONFIG_LAMBDA_EVENT_SIZE, CHIP_CONFIG_LAMBDA_EVENT_ALIGN>;
 // Proxies for different lambda return types
    CHIP_ERROR (*mLambdaProxy)(const LambdaStorage & body);  // For CHIP_ERROR-returning lambdas
    void (*mLambdaVoidProxy)(const LambdaStorage & body);    // For void-returning lambdas
    
    LambdaStorage mLambdaBody;
};

// template <typename T>
// class LambdaBridgev2
// {
// public:

//     // Use initialize instead of constructor because this class has to be trivial
//     template <typename Lambda>
//     void Initialize(const Lambda & lambda, T* Data)
//     {
//         // memcpy is used to move the lambda into the event queue, so it must be trivially copyable
//         static_assert(std::is_trivially_copyable<Lambda>::value, "lambda must be trivially copyable");
//         static_assert(sizeof(Lambda) <= CHIP_CONFIG_LAMBDA_EVENT_SIZE, "lambda too large");
//         static_assert(CHIP_CONFIG_LAMBDA_EVENT_ALIGN % alignof(Lambda) == 0, "lambda align too large");

//         // Implicit cast a capture-less lambda into a raw function pointer.
//         mLambdaProxy = [](const LambdaStorage & body, T* Data) { (*reinterpret_cast<const Lambda *>(&body))(Data); };
//         ::memcpy(&mLambdaBody, &lambda, sizeof(Lambda));
//     }

//     void operator()() const { mLambdaProxy(mLambdaBody); }

// private:
//     using LambdaStorage = std::aligned_storage_t<CHIP_CONFIG_LAMBDA_EVENT_SIZE, CHIP_CONFIG_LAMBDA_EVENT_ALIGN>;
//     void (*mLambdaProxy)(const LambdaStorage & body, T * Data);
//     LambdaStorage mLambdaBody;
// };

static_assert(std::is_trivial<LambdaBridge>::value, "LambdaBridge is not trivial");

} // namespace chip
