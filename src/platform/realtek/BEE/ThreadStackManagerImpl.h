/*
 *
 *    Copyright (c) 2020 Project CHIP Authors
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
 *          Provides an implementation of the ThreadStackManager object
 *          for Realtek platforms and the OpenThread
 *          stack.
 */

#pragma once

#include <openthread/tasklet.h>
#include <openthread/thread.h>
#include <platform/FreeRTOS/GenericThreadStackManagerImpl_FreeRTOS.h>
#if CHIP_SYSTEM_CONFIG_USE_LWIP
#include <platform/OpenThread/GenericThreadStackManagerImpl_OpenThread_LwIP.h>
#else
#include <platform/OpenThread/GenericThreadStackManagerImpl_OpenThread.h>
#endif

#define USE_FREERTOS_NATIVE_API 0

extern "C" void otSysEventSignalPending(void);

namespace chip {
namespace DeviceLayer {

class ThreadStackManager;
class ThreadStackManagerImpl;
namespace Internal {
extern int GetEntropy(uint8_t * buf, size_t bufSize);
}

/**
 * Concrete implementation of the ThreadStackManager singleton object for Qorvo platforms
 * using the OpenThread stack.
 */
class ThreadStackManagerImpl final : public ThreadStackManager,
#if CHIP_SYSTEM_CONFIG_USE_LWIP
                                     public Internal::GenericThreadStackManagerImpl_OpenThread_LwIP<ThreadStackManagerImpl>,
#else
                                     public Internal::GenericThreadStackManagerImpl_OpenThread<ThreadStackManagerImpl>,
#endif
                                     public Internal::GenericThreadStackManagerImpl_FreeRTOS<ThreadStackManagerImpl>
{
    // Allow the ThreadStackManager interface class to delegate method calls to
    // the implementation methods provided by this class.
    friend class ThreadStackManager;

    // Allow the generic implementation base classes to call helper methods on
    // this class.
#ifndef DOXYGEN_SHOULD_SKIP_THIS
    friend Internal::GenericThreadStackManagerImpl_OpenThread<ThreadStackManagerImpl>;
    friend Internal::GenericThreadStackManagerImpl_OpenThread_LwIP<ThreadStackManagerImpl>;
    friend Internal::GenericThreadStackManagerImpl_FreeRTOS<ThreadStackManagerImpl>;
#endif

    // Allow glue functions called by OpenThread to call helper methods on this
    // class.
    friend void ::otTaskletsSignalPending(otInstance * otInst);
    friend void ::otSysEventSignalPending(void);

public:
    // ===== Platform-specific members that may be accessed directly by the application.

    using ThreadStackManager::InitThreadStack;
    CHIP_ERROR InitThreadStack(otInstance * otInst);
    void GetExtAddress(otExtAddress & aExtAddr);
    void SignalThreadActivityPending();

#if USE_FREERTOS_NATIVE_API
    BaseType_t SignalThreadActivityPendingFromISR();
#else
    void SignalThreadActivityPendingFromISR();
#endif

protected:
    // ===== Methods that implement the ThreadStackManager abstract interface.
    CHIP_ERROR _StartThreadTask();

private:
    // ===== Methods that implement the ThreadStackManager abstract interface.

    CHIP_ERROR _InitThreadStack(void);

    // ===== Members for internal use by the following friends.

    friend ThreadStackManager & ::chip::DeviceLayer::ThreadStackMgr(void);
    friend ThreadStackManagerImpl & ::chip::DeviceLayer::ThreadStackMgrImpl(void);
    friend int Internal::GetEntropy(uint8_t * buf, size_t bufSize);
    static ThreadStackManagerImpl sInstance;
    static bool IsInitialized();

    // ===== Private members for use by this class only.

    ThreadStackManagerImpl() = default;
#if USE_FREERTOS_NATIVE_API
    TaskHandle_t mThreadTask;
#else
    void * mThreadTask;
#endif
    void ExecuteThreadTask(void);
    static void ThreadTaskMain(void * arg);
};

/**
 * Returns the public interface of the ThreadStackManager singleton object.
 *
 * chip applications should use this to access features of the ThreadStackManager object
 * that are common to all platforms.
 */
inline ThreadStackManager & ThreadStackMgr(void)
{
    return ThreadStackManagerImpl::sInstance;
}

/**
 * Returns the platform-specific implementation of the ThreadStackManager singleton object.
 *
 * chip applications can use this to gain access to features of the ThreadStackManager
 * that are specific to the platform.
 */
inline ThreadStackManagerImpl & ThreadStackMgrImpl(void)
{
    return ThreadStackManagerImpl::sInstance;
}

} // namespace DeviceLayer
} // namespace chip
